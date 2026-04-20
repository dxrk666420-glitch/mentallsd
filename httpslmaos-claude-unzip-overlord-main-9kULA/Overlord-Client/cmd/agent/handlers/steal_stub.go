//go:build !windows

package handlers

import (
	"context"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleSteal(ctx context.Context, env *rt.Env, cmdID string, envelope map[string]interface{}) error {
	return wire.WriteMsg(ctx, env.Conn, wire.StealResult{
		Type:      "steal_result",
		CommandID: cmdID,
		OK:        false,
		Message:   "stealer not supported on this platform",
	})
}
