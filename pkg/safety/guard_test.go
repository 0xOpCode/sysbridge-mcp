package safety

import "testing"

func TestGuardPathAndCommandIsolation(t *testing.T) {
	g := NewGuard([]string{"/dev/sda", "/dev/sda1"}, []string{"/boot/efi"}, true)

	if err := g.CheckPath("/dev/sda"); err == nil {
		t.Fatal("expected /dev/sda to be blocked")
	}
	if err := g.CheckPath("/dev/sda1"); err == nil {
		t.Fatal("expected /dev/sda1 to be blocked")
	}
	if err := g.CheckPath("/boot/efi/EFI/arch"); err == nil {
		t.Fatal("expected /boot/efi subpath to be blocked")
	}
	if err := g.CheckPath("/dev/sdb4"); err != nil {
		t.Fatalf("expected /dev/sdb4 to be allowed, got: %v", err)
	}

	if err := g.CheckCommand("dd if=/dev/zero of=/dev/sda bs=1M"); err == nil {
		t.Fatal("expected dd to /dev/sda to be blocked")
	}
	if err := g.CheckCommand("mkfs.ext4 sda1"); err == nil {
		t.Fatal("expected mkfs on sda1 to be blocked")
	}
	if err := g.CheckCommand("lsblk -f /dev/sdb"); err != nil {
		t.Fatalf("expected lsblk on /dev/sdb to be allowed, got: %v", err)
	}

	if err := g.RequireDeleteConfirmation(false, "/tmp/test.txt"); err == nil {
		t.Fatal("expected unconfirmed delete to fail")
	}
	if err := g.RequireDeleteConfirmation(true, "/tmp/test.txt"); err != nil {
		t.Fatalf("expected confirmed delete to pass, got: %v", err)
	}
}
