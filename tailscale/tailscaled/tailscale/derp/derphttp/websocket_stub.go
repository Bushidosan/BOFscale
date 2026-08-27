// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(js || windows || linux || darwin)

package derphttp

const canWebsockets = false
