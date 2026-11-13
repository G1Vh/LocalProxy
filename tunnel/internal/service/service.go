// Package service runs the TUN mode as a Windows service, so LocalProxy
// asks for administrator rights once (to install it) instead of on every
// start. The service runs LocalProxy's own localproxy-tunnel.exe from the
// install folder, so updates take effect without asking again. The user who
// installed it may start, stop and query it, nothing else.
//
// LocalProxy starts it with StartService, passing the same arguments as the
// "tun" command; the service serves one session and stops when it ends.
package service

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/G1Vh/LocalProxy/tunnel/internal/tun"
)

const (
	Name        = "LocalProxyTun"
	displayName = "LocalProxy TUN"
)

func logPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "LocalProxy", "tun.log")
}

// Install (re)creates the service for this exe (wintun.dll next to it).
// Needs administrator rights.
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	sid, err := userSID()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		stopAndWait(s)
		s.Close()
	}
	cfg := mgr.Config{
		DisplayName: displayName,
		Description: "Весь трафик системы через LocalProxy (виртуальный адаптер). Запускается из LocalProxy.",
		StartType:   mgr.StartManual,
	}
	s, err := m.OpenService(Name)
	if err == nil {
		cfg.BinaryPathName = fmt.Sprintf(`"%s" service run`, exe)
		err = s.UpdateConfig(cfg)
	} else {
		s, err = m.CreateService(Name, exe, cfg, "service", "run")
	}
	if err != nil {
		return fmt.Errorf("служба: %w", err)
	}
	defer s.Close()
	// SYSTEM and administrators as usual; the installing user may read its
	// config, query, start and stop it (CC LC RP WP LO RC).
	sddl := "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCRPWPLORC;;;" + sid + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(windows.Handle(s.Handle), windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("права на службу: %w", err)
	}
	return nil
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(Name); err == nil {
		stopAndWait(s)
		err := s.Delete()
		s.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func stopAndWait(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	s.Control(svc.Stop)
	for range 50 {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// userSID is the SID of the user running us (elevated through UAC, it is
// still the user who asked).
func userSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// Run is the service entry point ("service run").
func Run() error {
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		return errors.New("запускается только диспетчером служб")
	}
	if f, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		defer f.Close()
		log.SetOutput(f)
	} else if os.MkdirAll(filepath.Dir(logPath()), 0o755) == nil {
		if f, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}
	return svc.Run(Name, handler{})
}

type handler struct{}

// Execute serves one TUN session with the start arguments LocalProxy gave.
func (handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	control := fs.String("control", "", "")
	token := fs.String("token", "", "")
	socks := fs.String("socks", "127.0.0.1:3128", "")
	parent := fs.Int("parent", 0, "")
	fs.String("log", "", "") // the service logs to ProgramData only
	if len(args) < 2 || fs.Parse(args[1:]) != nil || *control == "" {
		log.Printf("service: нет параметров сеанса (служба запускается из LocalProxy)")
		return true, 1
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- tun.Run(*control, *token, *socks, *parent, stop) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Printf("tun: %v", err)
			}
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		}
	}
}
