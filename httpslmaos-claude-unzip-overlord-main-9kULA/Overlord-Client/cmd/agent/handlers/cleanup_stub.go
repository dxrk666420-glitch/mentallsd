//go:build !windows

package handlers

import (
	"context"
	"runtime"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleCleanup(ctx context.Context, env *rt.Env, cmdID string) error {
	return wire.WriteMsg(ctx, env.Conn, wire.CleanupResult{
		Type:      "cleanup_result",
		CommandID: cmdID,
		OK:        false,
		Errors:    []string{"cleanup not supported on " + runtime.GOOS},
	})
}
