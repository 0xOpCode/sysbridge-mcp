//go:build linux

package discovery

import (
	"context"
	"syscall"
	"time"
)

func StartNetlinkWatcher(ctx context.Context, onChange func()) {
	if onChange == nil {
		return
	}

	go func() {
		fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
		if err != nil {
			return
		}

		const (
			rtmgrpLink       = 0x1
			rtmgrpIPv4IfAddr = 0x10
		)

		sa := &syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Groups: rtmgrpLink | rtmgrpIPv4IfAddr,
		}

		if err := syscall.Bind(fd, sa); err != nil {
			_ = syscall.Close(fd)
			return
		}

		tv := syscall.Timeval{Sec: 1, Usec: 0}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = syscall.Close(fd)
			case <-done:
			}
		}()
		defer func() {
			close(done)
			_ = syscall.Close(fd)
		}()

		buf := make([]byte, 4096)
		var lastTrigger time.Time

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			nr, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					time.Sleep(500 * time.Millisecond)
					continue
				}
			}

			if nr < syscall.NLMSG_HDRLEN {
				continue
			}

			if time.Since(lastTrigger) > 500*time.Millisecond {
				lastTrigger = time.Now()
				go onChange()
			}
		}
	}()
}
