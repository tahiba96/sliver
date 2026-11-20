# Critic report: WireGuard over HTTPS

**Plan:** `PLAN-wg-over-https.md`
**Verdict:** 8 Blockers · 4 Risks

A worker who follows the plan will not ship a `wg+https` implant, will not attach the new bind to the live device, and will not give an operator a command that selects this mode. A normal WireGuard client can already peer with the C2 device. The plan does not put that client's packets on the HTTPS path, and it does not test the reply.

## Blockers

### B1. The named `IsC2Enabled` edits do not turn on WireGuard for a `wg+https` implant

- Where: "pass `[]string{"wg", "wg+https"}` so `IncludeWG` compiles in the WG template" at `server/generate/external.go` and `server/generate/binaries.go`.
- Evidence: The generate RPC sets the flag at `server/rpc/rpc-generate.go:88` with `[]string{"wg"}` only. Save does the same at `server/db/models/implant.go:474`. `server/generate/binaries.go:1202` only decides whether to embed WG keys. `server/generate/external.go:30` runs only for external builds. The client sets `IncludeWG` from `--include-wg`, not from the URL (`client/command/generate/generate.go:499-507`). The WG sources are stripped unless that flag is true (`implant/sliver/transports/wireguard/wireguard.go:23`).
- Consequence: A worker who edits only the two named files builds a `wg+https` implant with `IncludeWG` false. The manual "build a `wg+https` implant" gate fails because the binary has no WG connect path and no WG keys.

### B2. `bind_http.go` cannot call `httpclient` on a `wg+https`-only implant

- Where: "HTTP mechanics reuse `implant/sliver/transports/httpclient`" and "No new `Include*` flag is needed."
- Evidence: `implant/sliver/transports/httpclient/httpclient.go:21` through `:716` is inside `{{if .Config.IncludeHTTP}}`. `GoHTTPDriver` is in that package (`implant/sliver/transports/httpclient/gohttp.go:41`). Scheme `wg+https` does not match `http` or `https` in `IsC2Enabled` (`server/db/models/implant.go:558-566`). No step sets `IncludeHTTP`.
- Consequence: The implant build renders `httpclient` as an empty package. The new bind's import of `GoHTTPDriver` or `ParseHTTPOptions` does not compile. That is the implant the plan says to ship.

### B3. No step installs the new bind on the device that actually sends packets

- Where: "`WGConnect` becomes a thin wrapper passing `newWGUDPBind()`" and "`StartWGListenerJob` registers the receiver". The server file "`wgHTTPBind` wraps `conn.NewDefaultBind()`".
- Evidence: The implant device is created only in `bringUpWGInterface` with `newWGUDPBind()` (`implant/sliver/transports/wireguard/wireguard.go:377`). Key exchange calls that function first (`getSessKeys`, same file, line 274), then `WGConnect` calls it again (line 321). The server device is created only in `StartWGListener` (`server/c2/wireguard.go:113`). `device.Up` receives only the `ReceiveFunc`s returned by that bind's `Open` (`vendor/golang.zx2c4.com/wireguard/device/device.go:488-525`).
- Consequence: A wrapper around `WGConnect`, and a handler registered beside the job, never replace those `NewDevice` calls. Key exchange still opens a UDP socket. HTTPS-encapsulated packets are never read by the live device. The HTTPS-only goal fails before the session exists.

### B4. The frame cannot be parsed when `c2IP` is 4 or 16 bytes

- Where: "`version(1B)=1 | flags(1B)=0 | sessionID(16B) | c2IP(4|16B) | count(2B) | ...`" with `flags` fixed at 0.
- Evidence: After the 18-byte prefix there is no family bit and no length. `wgConnect` uses `net.LookupHost` and takes `addrs[0]` (`implant/sliver/transports/session.go:512-520`). That address is often IPv6. The codec test requires a round trip of this frame.
- Consequence: A parser cannot tell a 4-byte address from the first four bytes of a 16-byte address. IPv4-only tests can pass. A dual-stack implant fails at decode, or the worker has to break the written frame to make the gate pass.

### B5. The mac2 gate cannot fail a handshake the way the plan requires

- Where: "the server must report the same bytes on the synthetic endpoint, or every handshake is dropped at `CheckMAC2`" and "flip one byte and the handshake must fail." Also: "Plain UDP binds get this from `IP_RECVORIGDSTADDR`."
- Evidence: `CheckMAC2` runs only inside `if device.IsUnderLoad()` (`vendor/golang.zx2c4.com/wireguard/device/receive.go:318-331`). `IsUnderLoad` is a handshake-queue threshold (`vendor/golang.zx2c4.com/wireguard/device/device.go:217-226`). On failure the code sends a cookie and skips that packet. It does not reject the peer. `AddMacs` does not take `DstToBytes` (`vendor/golang.zx2c4.com/wireguard/device/cookie.go:214-246`). `StdNetEndpoint.DstToBytes` is `AddrPort.MarshalBinary()`, and the receive comment says that address is the datagram source (`vendor/golang.zx2c4.com/wireguard/conn/bind_std.go:113-116`). The vendor conn tree has `IP_PKTINFO` for sticky source (`vendor/golang.zx2c4.com/wireguard/conn/sticky_linux.go:48-67`). It has no `IP_RECVORIGDSTADDR`.
- Consequence: A loopback handshake with one flipped `c2IP` byte still completes. The required test fails. The worker cannot make it pass without changing wireguard-go, which the plan forbids, or without inventing a reject the stack does not do.

### B6. Phase 2 has no path from `dig @127.0.0.1` into the tunnel, and the return packets are dropped

- Where: "relays each datagram to a server-side helper that calls `tNet.DialUDP` ... mirroring how the TCP path dials the tun listener." End-to-end gate: `dig @127.0.0.1 <localPort>`.
- Evidence: `StartWGListener` keeps `tNet` as a local variable and does not return it (`server/c2/wireguard.go:65-68`, return at line 166). Package vars are only the logger, tun IP, and yamux preface (`server/c2/wireguard.go:48-62`). `WGPortFwdAddCmd` only sends `WGStartPortForward` and returns (`client/command/wireguard/wg-portfwd-add.go:53-66`). It does not dial the tun. The server stack installs a filter whose Input chain drops every packet (`server/netstack/tun.go:79-85` and `CreateNetTUN` at line 181). `AllowTCPPort` matches TCP only (`server/netstack/tun.go:128-149`). There is no UDP allow function. No step stores `tNet`, adds an RPC, or adds a UDP accept rule.
- Consequence: The worker cannot call `tNet.DialUDP` from the client command. Even if they stash the stack, the DNS reply is an Input UDP packet and the filter drops it. The `dig` gate fails.

### B7. `wg+https` is not in the command interface, and the plan forbids the edits that would put it there

- Where: "No changes to `WGListenerReq`, listener RPCs, or the client console." The only client parser step is "`ParseWGc2` ... accept the `wg+https://` prefix."
- Evidence: The generate flag is still `--wg` / `-g`, help text "wg connection strings" (`client/command/generate/commands.go:337`). Forms offer one WireGuard choice, value `"wg"` (`client/forms/generate.go:97`, and the same option in `client/forms/generate_beacon.go:100`, `client/forms/generate_profiles_new.go:112`, `client/forms/generate_profiles_new_beacon.go:117`). `applyGenerateForm` maps that choice to the `--wg` flag (`client/command/generate/generate.go:189-192`). The example string is `1.2.3.4:8888` or `https://c2.example.com` (`client/forms/generate.go:113`). `ParseWGc2` prepends `wg://` unless the string already starts with `wg://` (`client/command/generate/generate.go:1235-1253`). `ParseHTTPc2` accepts only `http` and `https` (`client/command/generate/generate.go:1366-1367`). `jobs wg` is documented as a UDP listen port (`client/command/jobs/commands.go:84`). `WGListenerCmd` prints `udp:%d` and does not read `--lhost` (`client/command/jobs/wg.go:35-40`). After connect, `handleWGSliverConnection` always calls `NewImplantConnection("wg", ...)` (`server/c2/wireguard.go:261`). `ActiveC2` is `connection.URL()` (`implant/sliver/runner/runner.go:643`). Reopening a beacon switches on the URL scheme and only has `case "wg"` (`client/command/sessions/interactive.go:114`). The default branch prints `Unsupported C2 scheme: %s` (`client/command/sessions/interactive.go:152`). `url.Parse` of `wg+https://host:443` yields scheme `wg+https`.
- Consequence: An operator who uses the form, or who types a host and port into `--wg`, still gets UDP `wg://`. An operator who types `wg+https://...` into the HTTP(S) field is rejected. An operator who starts only `https`, or only `wg`, has no command text that says both jobs are required, or that the URL port is the HTTPS port. A live beacon whose `ActiveC2` is `wg+https://...` cannot be reopened. The session list still shows transport `wg`.

### B8. A normal WireGuard client cannot complete wrap, implant HTTPS, unwrap, and reply

- Where: "UDP keeps working exactly as today." "If both UDP and HTTPS variants of the same peer run, one WG device serves both." Out of scope: "multiplayer WireGuard (operator client to server, `client/transport/wireguard.go`, `100.65.0.0/16`)." Latency claim: "interactive traffic is fine because responses usually ride back in the POST that carried the request."
- Evidence: `wg-config` calls `GenerateWGClientConfig` (`client/command/wireguard/wg-config.go:53-56`). The printed config is stock `wg-quick` with `Endpoint = <configure yourself>` and `AllowedIPs` of the client `/16` (`client/command/wireguard/wg-config.go:30-42`). The RPC uses `GenerateUniqueWGPeerKeys` and `certs.GetWGServerKeys` (`server/rpc/rpc-wg.go:15-31`). Those addresses are in `100.64.0.0/16` (`server/db/wgips.go:14-24`). `saveWGKeys` publishes `allowed_ip=%s/32` onto the C2 device (`server/certs/wireguard.go:242-246`). The multiplayer listener is a different device: `server/transport/multiplayer_wireguard.go:105-131` uses `conn.NewDefaultBind()` and `100.65.0.1/16`. The plan's out-of-scope file, `client/transport/wireguard.go`, is that operator mTLS tunnel, not `wg-config`. The C2 device is created only in `StartWGListener` (`server/c2/wireguard.go:113`). No step replaces that bind, and no test starts `jobs wg`, starts `jobs https`, runs `wg-config`, and checks a packet to the implant tun IP.
- Consequence: A worker who treats "multiplayer" as "any stock client" never tests this path. If they do test it, `Send` still uses the UDP bind, so packets for an HTTPS-only implant never enter the POST body. The first packet from the stock client is downlink. Nothing is waiting in a POST. The plan's "reply rides back in the POST that carried the request" applies when the implant spoke first. Here the packet sits until the implant's next poll, default 10 seconds. There is no command and no gate for the reply.

## Risks

### R1. The server bind constructor breaks the Windows ARM64 UDP path the plan says to keep

- Where: "`wgHTTPBind` wraps `conn.NewDefaultBind()`. UDP keeps working exactly as today."
- Evidence: On `windows && arm64`, `newWGUDPBind` returns `conn.NewStdNetBind()` because WinRing stops handshakes (`server/c2/wireguard_bind_windows_arm64.go:6-11`). `conn.NewDefaultBind` on Windows returns `NewWinRingBind()` (`vendor/golang.zx2c4.com/wireguard/conn/bind_windows.go:80`). `TestWindowsARM64WGUDPBindUsesStandardSockets` only checks `newWGUDPBind` (`server/c2/wireguard_bind_windows_arm64_test.go:11-15`).
- Consequence: A composite built as written uses WinRing for the UDP half on that target. Existing UDP implants stop completing handshakes, and the current test still passes.

### R2. Session expiry cannot see the poll override

- Where: idle expiry is "3 × poll interval", and the interval is "overridable via C2 URL query `wg-poll-interval`".
- Evidence: That query is parsed on the implant. The frame has no poll field (`flags` is 0). The server table therefore has only the 10 second default.
- Consequence: An implant with `wg-poll-interval` of several minutes is expired after 30 seconds. The next poll is a new `sessionID` and a new `100.70.0.0/16` address. Queued downlink packets are dropped in the gap.

### R3. `net-timeout` can be shorter than the server hold, and the plan treats them as independent

- Where: long-poll `maxHold` default 12 seconds. Implant HTTP options come from the C2 URL.
- Evidence: `GoHTTPDriver` sets `http.Client.Timeout` to `opts.NetTimeout` (`implant/sliver/transports/httpclient/gohttp.go:74-76`). `ParseHTTPOptions` defaults that to 30 seconds, but a URL can set `net-timeout` (`implant/sliver/transports/httpclient/httpclient.go:88-91`). Server `WriteTimeout` is one minute (`server/c2/http.go:74`, `:198`), so the server side of a 12 second hold is fine.
- Consequence: A `net-timeout` below 12 seconds aborts every long poll while the server is still holding the request. The worker has no rule that ties the two knobs together.

### R4. The HTTPS job's long-poll flag does not tune the WireGuard hold

- Where: "Poll interval and long-poll hold: fixed defaults (10 s / 12 s) with a C2 URL query override. Server config knobs can come later."
- Evidence: `jobs https` and `jobs http` both default `--long-poll-timeout` / `-T` to `1s`, help text "server-side long poll timeout" (`client/command/jobs/commands.go:122` and `:146`). That flag sets the Sliver HTTP C2 poll. The plan's 12 second hold is a separate constant, with no flag and no step that reads this one.
- Consequence: An operator who lengthens `--long-poll-timeout` will think they tuned the implant hold. They did not. The plan leaves that collision undocumented.

## Checked, and not a blocker on its own

- `RekeyTimeout` is 5 seconds and `RejectAfterTime` is 180 seconds, as the plan says.
- `mainHandler` is the only HTTP route (`server/c2/http.go:375`, `:539`). A header check before session handling can be added there.
- `StartWGListenerJob` does not swap the bind (`server/c2/jobs.go:74`). That is why B3 stands.
- `WGPortForwardStartReq` uses field 1, field 2, and field 9. `Protocol = 3` is free. The protobuf field number is not the phase-2 failure. B6 is.
- The implant netstack does not install the server Input drop. Implant `ListenUDP` can work. The drop is on the server stack.
- `wg ports` still matches a session because `session.Transport` stays `wg` (`client/command/wireguard/wg-portfwd-add.go:36`). That guard is not why the command interface misses the scheme. B7 is.
