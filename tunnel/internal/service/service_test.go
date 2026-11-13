package service

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestServiceSDDLParses(t *testing.T) {
	sid, err := userSID()
	if err != nil || !strings.HasPrefix(sid, "S-1-") {
		t.Fatalf("sid %q %v", sid, err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCRPWPLORC;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.DACL(); err != nil {
		t.Fatal(err)
	}
}

func TestRunOutsideServiceManagerRefuses(t *testing.T) {
	if err := Run(); err == nil {
		t.Fatal("must refuse outside the service manager")
	}
}

func TestInstallNeedsAdmin(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated: would really install")
	}
	if err := Install(); err == nil {
		t.Fatal("installed without rights?")
	} else {
		t.Logf("as expected: %v", err)
	}
}
