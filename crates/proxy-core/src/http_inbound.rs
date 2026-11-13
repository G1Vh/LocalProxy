//! HTTP proxy inbound: CONNECT tunnels and plain HTTP forwarding (keep-alive,
//! chunked bodies, upgrades such as WebSocket over `ws://`).

use std::convert::Infallible;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::pac;
use crate::router::{HttpHop, Inbound, RouteError};
use crate::server::ConnCtx;
use crate::stream::TargetAddr;

type Body = BoxBody<Bytes, hyper::Error>;

/// Serves one client connection until it closes.
pub(crate) async fn serve(stream: TcpStream, ctx: ConnCtx) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| handle(req, ctx.clone()));
    let conn = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades();
    if let Err(e) = conn.await {
        tracing::debug!("http inbound connection ended: {e}");
    }
}

async fn handle(req: Request<Incoming>, ctx: ConnCtx) -> Result<Response<Body>, Infallible> {
    let response = if req.method() == Method::CONNECT {
        connect(req, ctx).await
    } else if req.uri().scheme().is_some() && req.uri().authority().is_some() {
        forward(req, ctx).await
    } else {
        local(&req, &ctx)
    };
    Ok(response)
}

/// Requests addressed to the proxy itself (origin-form): the PAC file.
fn local(req: &Request<Incoming>, ctx: &ConnCtx) -> Response<Body> {
    let is_read = req.method() == Method::GET || req.method() == Method::HEAD;
    if is_read && req.uri().path() == pac::PAC_PATH {
        let pac = ctx.router.snapshot().pac.clone();
        let mut response =
            Response::new(Full::new(Bytes::from(pac)).map_err(|n| match n {}).boxed());
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(pac::PAC_CONTENT_TYPE),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    text(
        StatusCode::NOT_FOUND,
        "LocalProxy: это прокси-сервер, а не веб-сайт",
    )
}

async fn connect(req: Request<Incoming>, ctx: ConnCtx) -> Response<Body> {
    let Some(target) = req
        .uri()
        .authority()
        .and_then(|a| TargetAddr::parse_authority(a.as_str(), 443))
    else {
        return text(StatusCode::BAD_REQUEST, "LocalProxy: CONNECT без адреса");
    };

    let mut upstream = match ctx
        .router
        .connect(&target, Inbound::Connect, ctx.process.as_deref())
        .await
    {
        Ok(io) => io,
        Err(e) => return route_error(&e),
    };

    ctx.spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                if let Err(e) = copy_bidirectional(&mut client, &mut upstream).await {
                    tracing::trace!(%target, "tunnel closed: {e}");
                }
            }
            Err(e) => tracing::debug!(%target, "CONNECT upgrade failed: {e}"),
        }
    });
    Response::new(empty())
}

async fn forward(mut req: Request<Incoming>, ctx: ConnCtx) -> Response<Body> {
    let uri = req.uri().clone();
    if uri.scheme_str() != Some("http") {
        return text(
            StatusCode::BAD_REQUEST,
            "LocalProxy: для HTTPS используйте CONNECT",
        );
    }
    let Some(authority) = uri.authority() else {
        return text(StatusCode::BAD_REQUEST, "LocalProxy: нет адреса в запросе");
    };
    let target = TargetAddr::new(
        authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']'),
        uri.port_u16().unwrap_or(80),
    );

    let wants_upgrade = is_upgrade(req.headers());
    let client_upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut req));

    let (io, hop) = match ctx
        .router
        .connect_http(&target, ctx.process.as_deref())
        .await
    {
        Ok(v) => v,
        Err(e) => return route_error(&e),
    };

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers, wants_upgrade);
    // We answer `Expect: 100-continue` ourselves when the body is first read.
    parts.headers.remove(header::EXPECT);
    if !parts.headers.contains_key(header::HOST)
        && let Ok(host) = HeaderValue::from_str(authority.as_str())
    {
        parts.headers.insert(header::HOST, host);
    }
    parts.version = Version::HTTP_11;
    match &hop {
        HttpHop::Origin => {
            let path = uri.path_and_query().map_or("/", |p| p.as_str());
            parts.uri = Uri::try_from(path).unwrap_or_else(|_| Uri::from_static("/"));
        }
        HttpHop::Proxy { authorization } => {
            if let Some(value) = authorization
                .as_deref()
                .and_then(|a| HeaderValue::from_str(a).ok())
            {
                parts.headers.insert(header::PROXY_AUTHORIZATION, value);
            }
        }
    }

    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(TokioIo::new(io))
        .await
    {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_GATEWAY, &format!("LocalProxy: {e}")),
    };
    ctx.spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!("upstream http connection ended: {e}");
        }
    });

    let mut response = match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => {
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("LocalProxy: {target} не ответил: {e}"),
            );
        }
    };

    if response.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let server_upgrade = hyper::upgrade::on(&mut response);
        ctx.spawn(async move {
            match tokio::try_join!(client_upgrade, server_upgrade) {
                Ok((client, server)) => {
                    let (mut client, mut server) = (TokioIo::new(client), TokioIo::new(server));
                    let _ = copy_bidirectional(&mut client, &mut server).await;
                }
                Err(e) => tracing::debug!("upgrade failed: {e}"),
            }
        });
        return response.map(|b| b.boxed());
    }

    strip_hop_by_hop(response.headers_mut(), false);
    response.map(|b| b.boxed())
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

/// Removes headers that only make sense for one hop, including any the
/// `Connection` header names. With `keep_upgrade` the upgrade handshake survives.
fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in named {
        if !(keep_upgrade && name == header::UPGRADE) {
            headers.remove(name);
        }
    }
    let upgrade = headers.get(header::UPGRADE).cloned();
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    if keep_upgrade && let Some(upgrade) = upgrade {
        headers.insert(header::UPGRADE, upgrade);
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

fn route_error(e: &RouteError) -> Response<Body> {
    let status = match e {
        RouteError::Blocked(_) => StatusCode::FORBIDDEN,
        RouteError::Failed(_) => StatusCode::BAD_GATEWAY,
    };
    text(status, &format!("LocalProxy: {e}"))
}

fn text(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from(message.to_owned()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn empty() -> Body {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests;
