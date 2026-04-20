//go:build !windows

package handlers

import (
	"context"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleSteal(ctx context.Context, env *rt.Env, cmdID string, envelope map[string]interface{}) error {
	return wire.WriteMsg(ctx, env.Conn, wire.StealResult{
		Type:      "collect_result",
		CommandID: cmdID,
		OK:        false,
		Message:   "collector not supported on this platform",
	})
}
