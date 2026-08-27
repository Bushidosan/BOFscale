// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bufio"
	"context"
	"runtime"

	"tailscale.com/derp"
	"tailscale.com/tailcfg"
)

// canFallbackWebsockets reports whether the client can fall back to a
// websocket-based DERP connection when the HTTP upgrade fails.
func canFallbackWebsockets() bool {
	return canWebsockets && dialWebsocketFunc != nil && runtime.GOOS != "js"
}

// dialWebsocket establishes a DERP client connection over a websocket. It is
// used both when websockets are forced (TS_DEBUG_DERP_WS_CLIENT) and as a
// fallback when the HTTP upgrade path returns a non-101 status.
func (c *Client) dialWebsocket(ctx context.Context, caller string, reg *tailcfg.DERPRegion) (client *derp.Client, connGen int, err error) {
	var urlStr string
	if c.url != nil {
		urlStr = c.url.String()
	} else if reg != nil && len(reg.Nodes) > 0 {
		urlStr = c.urlString(reg.Nodes[0])
	}
	c.logf("%s: connecting websocket to %v", caller, urlStr)
	conn, err := dialWebsocketFunc(ctx, urlStr)
	if err != nil {
		c.logf("%s: websocket to %v error: %v", caller, urlStr, err)
		return nil, 0, err
	}
	brw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	derpClient, err := derp.NewClient(c.privateKey, conn, brw, c.logf,
		derp.MeshKey(c.MeshKey),
		derp.CanAckPings(c.canAckPings),
		derp.IsProber(c.IsProber),
		derp.AppName(c.AppName),
	)
	if err != nil {
		go conn.Close()
		return nil, 0, err
	}
	if c.preferred {
		if err := derpClient.NotePreferred(true); err != nil {
			go conn.Close()
			return nil, 0, err
		}
	}
	c.serverPubKey = derpClient.ServerPublicKey()
	c.client = derpClient
	c.netConn = conn
	c.connGen++
	c.atomicState.Store(ConnectedState{Connected: true})
	return c.client, c.connGen, nil
}
