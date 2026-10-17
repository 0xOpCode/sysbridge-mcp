//go:build !linux

package discovery

import "context"

func StartNetlinkWatcher(ctx context.Context, onChange func()) {
	_ = ctx
	_ = onChange
}
