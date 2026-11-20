# Plan

## Goal

A `wg+https://host:port` implant carries its WireGuard tunnel inside HTTPS POSTs to an existing HTTPS C2 listener, so an implant with only HTTP(S) egress still gets the WG tunnel, and (phase 2) an operator can forward UDP through that tunnel. UDP `wg://` implants and listeners keep working exactly as today.

## Context

### How the WG transport works today (verified)

- Implant device creation happens in exactly one function: `bringUpWGInterface` in `implant/sliver/transports/wireguard/wireguard.go:355`, which calls `device.NewDevice(tun, newWGUDPBind(), ...)` at line 377. Both `getSessKeys` (line 273, key exchange) and `WGConnect` (line 312, comms) go through it. The whole file is wrapped in `// {{if .Config.IncludeWG}}` (line 23) and `// {{end}}` (line 466).
- The bind is chosen in exactly one place per side: `newWGUDPBind()` in `implant/sliver/transports/wireguard/bind_default.go` (returns `conn.NewDefaultBind()`) with a `windows && arm64` override in `bind_windows_arm64.go` (returns `conn.NewStdNetBind()`, because WinRing stops handshakes). The server mirror is `server/c2/wireguard_bind_default.go` (`//go:build !windows || !arm64`) and `server/c2/wireguard_bind_windows_arm64.go`. `conn.NewDefaultBind` on Windows returns `NewWinRingBind()` (`vendor/golang.zx2c4.com/wireguard/conn/bind_windows.go:80`), so the override exists for a reason.
- Server device creation happens in exactly one function: `StartWGListener` in `server/c2/wireguard.go:65`, `device.NewDevice` at line 110, `dev.Up()` at line 142. It returns `(net.Listener, *device.Device, *bytes.Buffer, error)`; the netstack `tNet` is a local variable and is NOT returned (return at line 166). Package vars are only `wgLog`, `tunIP`, and the yamux preface (lines 48-59).
- `device.Up` receives packets only from the `ReceiveFunc`s returned by the bind's own `Open` (`vendor/golang.zx2c4.com/wireguard/device/device.go:488-525`). A handler registered beside the job cannot feed the device.
- `handleWGSliverConnection` always calls `core.NewImplantConnection("wg", ...)` (`server/c2/wireguard.go:261`). The session transport label stays `wg` for both socket types, so `wg ports` guards (`client/command/wireguard/wg-portfwd-add.go:36`) keep matching.
- `conn.Bind` (`vendor/golang.zx2c4.com/wireguard/conn/conn.go:36`) is `Open`, `Close`, `SetMark`, `Send`, `ParseEndpoint`, `BatchSize`. Every WG byte on the wire passes through `Send` and the receive functions. Roaming stores the endpoint object the receive function supplied (`SetEndpointFromPacket`, `vendor/golang.zx2c4.com/wireguard/device/peer.go:279`).

### Where the compile flags actually come from (verified)

- `IncludeWG` is set in three places, each hardcoding `[]string{"wg"}`: `server/rpc/rpc-generate.go:88`, `server/db/models/implant.go:474` (the `Save` path), and `server/generate/external.go:30`. `server/generate/binaries.go:1202` only decides whether to embed WG keys, and it checks `models.IsC2Enabled([]string{"wg"}, ...)` again. The client sets `IncludeWG` from the `--include-wg` flag (`client/command/generate/generate.go:499-507`), not from the URL.
- `IsC2Enabled` (`server/db/models/implant.go:558`) compares schemes with exact string equality. `wg+https` matches neither `wg` nor `http`/`https`.
- `implant/sliver/transports/httpclient/httpclient.go` is entirely inside `// {{if .Config.IncludeHTTP}}` (line 21). `GoHTTPDriver` (`gohttp.go:38`) and `ParseHTTPOptions` (`httpclient.go:88`) live in that package. A `wg+https`-only implant has `IncludeHTTP` false, so that package renders empty.

### Why mac2 is not the correctness gate (verified, this replaces the original plan's claim)

- `CheckMAC2` runs only inside `if device.IsUnderLoad()` (`vendor/golang.zx2c4.com/wireguard/device/receive.go:325-331`). `IsUnderLoad` is true only when the handshake queue holds at least `QueueHandshakeSize/8` elements, i.e. 128 of 1024 (`vendor/golang.zx2c4.com/wireguard/device/device.go:217` and `queueconstants_default.go:16`). On failure the code sends a cookie and skips that one packet; it does not reject the peer.
- `AddMacs` computes mac2 from a cookie the peer received earlier, not from `DstToBytes()` (`vendor/golang.zx2c4.com/wireguard/device/cookie.go:214-246`). `StdNetEndpoint.DstToBytes()` is `AddrPort.MarshalBinary()` of the datagram's source address (`vendor/golang.zx2c4.com/wireguard/conn/bind_std.go:113-116`); the vendor tree has no `IP_RECVORIGDSTADDR`.
- So a flipped `c2IP` byte does not fail a handshake, and the original plan's test cannot pass without modifying wireguard-go. The frame does not carry `c2IP`. The synthetic endpoint's `DstToBytes()` returns the session's own scratch address, which is stable for the life of the session, and that is all mac2 needs.

### Why phase 2 cannot dial from the client command (verified)

- `WGStartPortForward` (`server/rpc/rpc-wg.go:38`) is a pure `GenericHandler` relay to the implant. `WGPortFwdAddCmd` (`client/command/wireguard/wg-portfwd-add.go:53`) sends that RPC and returns; it never dials the tunnel.
- The server netstack installs an Input chain that drops every packet (`server/netstack/tun.go:77-85`, installed by `CreateNetTUN` at line 181). `AllowTCPPort` (`server/netstack/tun.go:330`) allows TCP only. There is no UDP allow function. The implant netstack installs no filter (`implant/sliver/netstack/tun.go:55-60`), so implant-side `ListenUDP` works.
- `WGPortForwardStartReq` (`protobuf/sliverpb/sliver.proto:1026`) uses fields 1, 2, and 9. Field 3 is free.

### Operator surface today (verified)

- `generate` has one WG flag, `--wg`/`-g`, help "wg connection strings" (`client/command/generate/commands.go:337`). `ParseWGc2` (`client/command/generate/generate.go:1229`) prepends `wg://` unless the string already starts with `wg://`, then rejects any scheme other than `wg`, and defaults the port to `DefaultWGLPort` (53). `ParseHTTPc2` accepts only `http` and `https` (line 1366).
- The four generate forms offer one WireGuard choice, value `"wg"` (`client/forms/generate.go:97`, `client/forms/generate_beacon.go:100`, `client/forms/generate_profiles_new.go:112`, `client/forms/generate_profiles_new_beacon.go:117`). `applyGenerateForm` maps that choice to the `--wg` flag (`client/command/generate/generate.go:189`).
- `jobs wg` prints `udp:%d` and does not read `--lhost` (`client/command/jobs/wg.go:35`). Reopening a beacon switches on the URL scheme and has only `case "wg"` (`client/command/sessions/interactive.go:114`); the default prints `Unsupported C2 scheme: %s` (line 152). `url.Parse("wg+https://host:443").Scheme` is `wg+https`.
- `jobs https`/`jobs http` `--long-poll-timeout` (`-T`, default `1s`, `client/command/jobs/commands.go:122` and `:146`) sets the Sliver HTTP C2 poll, not anything in this plan. `GoHTTPDriver` sets `http.Client.Timeout` to `opts.NetTimeout` (`implant/sliver/transports/httpclient/gohttp.go:70`), which `ParseHTTPOptions` defaults to 30 s but a URL can override (`httpclient.go:88`). Server `WriteTimeout` is `DefaultHTTPTimeout` = 1 minute (`server/c2/http.go:74`, `:198`).

### Binding repo rules

- `gofmt` on all Go; no `CGO`; no empty interfaces; `client` never imports `server` packages (repo `AGENTS.md`).
- Tests verify behavior through public interfaces and extreme values, not implementation details (user `AGENTS.md`). Run tests only through `./go-tests.sh`.
- Protobuf changes require `make pb`.
- Do not modify anything under `vendor/`.

### Design decisions

- Bind-layer encapsulation, because `bringUpWGInterface` and `StartWGListener` are the only seams that both key exchange and comms pass through. Carrying WG packets as envelope messages was rejected: key exchange happens before any C2 session exists.
- The implant bind is selected per device, not globally. `bringUpWGInterface` gains a `conn.Bind` parameter, and both of its callers (`getSessKeys`, `WGConnect`) pass it. `WGConnect` stays the UDP entry point and passes `newWGUDPBind()`; a new `WGConnectWithBind` is the HTTP entry point. A package-level swap would break UDP implants in the same binary.
- The server bind is a composite created inside `StartWGListener` and stored in a new package-level variable, because the HTTP handler runs in a different goroutine and must reach the same object whose `Open` fed `device.Up`. The composite's UDP half is `newWGUDPBind()`, never `conn.NewDefaultBind()`, so the Windows ARM64 override survives.
- HTTP mechanics are copied into the wireguard package instead of imported from `httpclient`, because that package is compiled out of a `wg+https`-only implant. The copy is the smallest set: a `POST` with `InsecureSkipVerify: true` TLS (matching `gohttp.go`) and proxy support from the URL query.
- The frame carries no `c2IP`. A family bit would be guesswork about a field the stack does not need. `DstToBytes()` returns the session scratch address; `DstIP()` returns the real HTTP peer address so the handshake rate limiter (`vendor/golang.zx2c4.com/wireguard/ratelimiter/ratelimiter.go:99`) still keys on the actual source.
- Session identity is the 16 random bytes, and the session record stores the poll interval the implant declares. Idle expiry is `3 × declared interval`, so an implant that polls slowly is not evicted between polls.
- The implant derives its poll interval, its HTTP client timeout, and the server's hold from one number, so the client timeout can never be shorter than the hold it is waiting on.
- Operator surface: a new `--wg-https` generate flag rather than overloading `--wg`, because `ParseWGc2` prepends `wg://` to bare input and operators already type bare `host:port` there. A second flag makes the choice explicit and auditable. Forms get a second WireGuard choice for the same reason.
- Out of scope: operator multiplayer WireGuard (`server/transport/multiplayer_wireguard.go`, `100.65.0.0/16`) and the stock `wg-config` client (`client/command/wireguard/wg-config.go`). A stock `wg-quick` client speaks UDP only; it cannot enter the HTTPS path, and nothing in this plan claims it can. SOCKS5 UDP ASSOCIATE is also out.

## Gotchas

- Every `.go` file in the implant tree is rendered as a Go template, not just the ones with guards. `renderSliverGoCode` (`server/generate/binaries.go:842`) walks the implant filesystem and calls `template.Parse` on every file whose extension is `.go`, `.c`, or `.h` (the extension check is at line 929, the parse at line 954). So `bind_http.go` and `udpforward.go` are templates too. The delimiters `{{` and `}}` start an action anywhere in them, including inside strings and comments. The comment at `implant/sliver/transports/wireguard/wireguard.go:99` documents this. Keep that character sequence out of every new implant file.
- `httpclient` is not importable from a `wg+https`-only implant. Do not import it from `implant/sliver/transports/wireguard`. The HTTP POST helper goes in the wireguard package, inside the existing `IncludeWG` guard.
- `newWGUDPBind()` is defined twice with mutually exclusive build tags. The composite bind must call `newWGUDPBind()`, not `conn.NewDefaultBind()`. A test that only type-asserts `newWGUDPBind()` (`server/c2/wireguard_bind_windows_arm64_test.go`) will stay green even if the composite is wrong, so the new test must assert on the composite's UDP half.
- `StartWGListener` does not return `tNet`, and the Input filter drops UDP. Phase 2 needs both a stored `*netstack.Net` and a new allow function. `DialUDP` alone changes nothing.
- `hasValidC2AdvancedOptions` (`client/command/generate/generate.go:1267`) rejects query keys it does not list. A new query key on a WG URL is not validated today because `ParseWGc2` never calls it, but the new parser must, or operators can ship typos.
- Server `WriteTimeout` is 1 minute. The hold must stay under 60 seconds or the server closes the response while the handler is still waiting.
- `make pb` regenerates every stub. After editing `protobuf/sliverpb/sliver.proto`, the worker runs `make pb` and commits the generated files with the proto change.

## Assumptions

- One `jobs wg` listener serves both UDP and HTTPS implants. The plan does not add a `WGListenerReq` field or a second listener type, because the HTTPS listener already exists and the WG device is shared. The operator runs both jobs. Recommendation accepted over a dedicated listener because a dedicated listener would duplicate the device, the peer table, and the tun IP.
- The session scratch range is `100.70.0.0/16`, one address per HTTP session. It does not overlap the implant tun range `100.64.0.0/16` or the multiplayer range `100.65.0.0/16`. Chosen because the bind cannot know the peer's tun IP before decryption, and a stable per-session address lets roaming route replies to the HTTP queue instead of to a NAT address that changes per request.
- Caps: 512 sessions, 64 packets per frame, 2048 bytes per packet, 128 KiB per request body, downlink queue 128 packets with drop-oldest. Chosen to bound memory at roughly 200 MiB worst case.
- Poll defaults: implant polls every 10 s when idle, server holds a poll for 12 s, implant HTTP client timeout is 30 s. The server hold is always `min(declaredInterval + 2 s, 50 s)`. 50 s keeps it under the server's 60 s `WriteTimeout` with margin.

## Risks

- R1 (resolved in WP2): a composite built on `conn.NewDefaultBind()` would put WinRing back on Windows ARM64 and silently break UDP handshakes. WP2 builds the UDP half with `newWGUDPBind()` and tests the composite.
- R2 (resolved in WP1 and WP2): the server cannot see a poll-interval override that lives only in the implant URL. The frame carries the interval, and expiry uses it.
- R3 (resolved in WP3): a `net-timeout` shorter than the hold aborts every poll. The implant computes its client timeout as `max(net-timeout, hold + 5 s)`, so the URL override can lengthen the timeout but not undercut the hold.
- R4 (accepted): `jobs https --long-poll-timeout` does not tune this hold, and an operator may think it does. WP7 documents the distinction on the WG C2 page and in the `jobs wg` output. No code reads that flag, on purpose, because it belongs to the HTTP C2 poll.
- A slow poll means server-initiated traffic waits up to one poll interval. Accepted: that is what the operator configured, and it matches beacon behavior. The plan states it in the docs instead of hiding it.

## Work Packages

### WP1. Frame codec in `util/wghttp`

**Steps:**
WP1.S1. Create `util/wghttp/frame.go` with the frame format, big-endian:

```
version(1)=1 | flags(1) | sessionID(16) | pollIntervalSeconds(2) | count(2) | { len(2) | packet }*count
```

`flags` bit 0 is `ip6` and is reserved for a future address field; encoders set it to 0 and decoders ignore it. No address field is present in version 1. `pollIntervalSeconds` is the implant's idle poll interval; 0 means "server default" (10). Decoders reject `version != 1`, `count > 64`, any `len > 2048`, a body over 128 KiB, and a body that ends before the last packet. `count = 0` is valid and means a poll with nothing to send.
WP1.S2. Create `util/wghttp/frame_test.go` covering: round trip of 0, 1, and 64 packets; `count` 65; a packet of 2049 bytes; a body truncated mid-packet; `version` 2; a `pollIntervalSeconds` of 0 and of 600 surviving a round trip; a body of 128 KiB plus one byte.

**Done when:**
- `go test ./util/wghttp/` exits 0.
- `grep -c "c2IP" util/wghttp/frame.go` prints `0`.

### WP2. Server composite bind and HTTP handler

**Steps:**
WP2.S1. Create `server/c2/wireguard_http_bind.go`. `newWGHTTPBind()` returns a `conn.Bind` whose UDP half is `newWGUDPBind()` — not `conn.NewDefaultBind()`. `Open` calls the UDP half's `Open` and appends one more `ReceiveFunc` that reads from an internal packet channel. `Send` type-asserts the endpoint: a `*wgHTTPSessionEndpoint` (defined in this file) enqueues into that session's downlink queue; any other endpoint goes to the UDP half. `BatchSize` returns the UDP half's batch size. `ParseEndpoint` delegates to the UDP half.
WP2.S2. Define `wgHTTPSessionEndpoint` implementing `conn.Endpoint`. `DstToBytes()` returns the session scratch address bytes. `DstIP()` returns the most recent HTTP peer address, updated on each request. `DstToString()` returns the scratch address as `ip:port`. `SrcIP()` returns an empty `netip.Addr`. `ClearSrc()` is a no-op.
WP2.S3. In `server/c2/wireguard.go` `StartWGListener`, replace `newWGUDPBind()` at line 110 with `newWGHTTPBind()`, and store the returned bind in a new package-level `wgHTTPBindCurrent`. Add `WGHTTPBind() conn.Bind` returning it, and set it back to nil when the job stops. Do not change the function's return values.
WP2.S4. Create `server/c2/http_wireguard.go` with `wgOverHTTPSHandler(resp http.ResponseWriter, req *http.Request)`. It reads at most 128 KiB, decodes with `util/wghttp`, looks up or creates a session by `sessionID`, assigns a scratch address from `100.70.0.0/16`, caps live sessions at 512 (reject newest with HTTP 429), and expires a session after `3 × max(declaredInterval, 10 s)` without a request. Each decoded packet is handed to the bind's receive path with that session's endpoint. The handler then waits up to `min(declaredInterval + 2 s, 50 s)` for downlink packets and writes them back with the same framing. If `WGHTTPBind()` returns nil, the handler returns false and the caller falls through.
WP2.S5. In `server/c2/http.go` `mainHandler` (line 539), before `getHTTPSession`, add: if the request has header `Sliver-WG: 1`, method POST, and `Content-Type: application/octet-stream`, and `wgOverHTTPSHandler` returns true, return. Everything else is unchanged.
WP2.S6. In `server/c2/jobs.go` `StartWGListenerJob`, the stop goroutine already calls `dev.Down()`; add a call that clears `wgHTTPBindCurrent` next to it.
WP2.S7. Add `server/c2/wireguard_http_bind_test.go`. One test builds the composite and asserts its UDP half equals what `newWGUDPBind()` returns, so the Windows ARM64 override is covered by construction. One test runs two wireguard-go devices with netstack TUNs over an `httptest` TLS server using this handler and asserts a handshake completes and a tun-to-tun TCP dial succeeds. One test sends a frame with no bind registered and asserts the response is 404. One test fills 512 sessions and asserts session 513 gets HTTP 429. One test sets a session's declared interval to 600 and asserts it is not expired at 30 seconds.

**Done when:**
- `go test ./server/c2/ -run 'WGHTTP|WindowsARM64WGUDP'` exits 0.
- `grep -n "NewDefaultBind" server/c2/wireguard_http_bind.go` prints nothing.
- `grep -n "newWGHTTPBind" server/c2/wireguard.go` prints exactly one line.

### WP3. Implant HTTP bind

**Steps:**
WP3.S1. Add a `bind conn.Bind` parameter to `bringUpWGInterface` in `implant/sliver/transports/wireguard/wireguard.go` and pass it to `device.NewDevice` instead of `newWGUDPBind()`. Update `getSessKeys` and `WGConnect` to take the same parameter and forward it. `WGConnect` is called by `wgConnect` and `wgBeacon`; those two keep passing `newWGUDPBind()`, so UDP behavior is unchanged.
WP3.S2. Add `WGConnectWithBind(address string, port uint16, bind conn.Bind)` in the same file, identical to `WGConnect` but using the given bind for both the key-exchange device and the comms device.
WP3.S3. Create `implant/sliver/transports/wireguard/bind_http.go`, inside the `IncludeWG` template guard and with no `{{` anywhere in it. Export `NewHTTPBind(origin string, pollInterval time.Duration, clientTimeout time.Duration) conn.Bind`, exported because `session.go` and `beacon.go` call it from another package. The server constructor `newWGHTTPBind` in WP2 is a different function in a different package; do not reuse its name. `Open` starts one poster goroutine and returns one `ReceiveFunc`. `Send` queues packets and wakes the poster. The poster sends one POST at a time to `origin`, header `Sliver-WG: 1`, content type `application/octet-stream`, body encoded by `util/wghttp`, and feeds response packets to the `ReceiveFunc`. An idle poster sends an empty POST every `pollInterval`. A failed POST drops the datagrams and retries on the next interval. `ParseEndpoint` accepts the origin string and returns a fixed endpoint. The TLS config uses `InsecureSkipVerify: true`, matching `implant/sliver/transports/httpclient/gohttp.go`. Proxy support reads the `proxy` query key the same way `GoHTTPDriver` does. The client timeout is `clientTimeout`.
WP3.S4. Do not import `implant/sliver/transports/httpclient` from this package.
WP3.S5. Add `implant/sliver/transports/wireguard/bind_http_test.go`: two devices, one with this bind and one with the WP2 handler over `httptest`, asserting a completed handshake and a tun TCP dial. Assert that a POST error does not close the device and that the next interval sends again.

**Done when:**
- `go test ./implant/sliver/transports/wireguard/ -run 'HTTPBind|KeyExchange'` exits 0.
- `grep -rn "httpclient" implant/sliver/transports/wireguard/` prints nothing.
- `grep -n "newWGUDPBind()" implant/sliver/transports/wireguard/wireguard.go` prints nothing (all call sites now pass a bind in).

### WP4. Compile flags and the `wg+https` scheme

**Steps:**
WP4.S1. In `server/db/models/implant.go` at line 474, change only the WG check, to `IsC2Enabled([]string{"wg", "wg+https"}, pbConfig.C2)`. Do not touch the HTTP check on the next line. `IncludeHTTP` pulls in the whole `httpclient` package and the HTTP C2 session code, which a `wg+https` implant does not use: WP3 posts through its own client inside the `IncludeWG` guard. Adding `wg+https` to the HTTP check would compile that code in for nothing and is wrong.
WP4.S2. Apply that same WG-check change in the other three places that hardcode `[]string{"wg"}`: `server/rpc/rpc-generate.go:88`, `server/generate/external.go:30`, and `server/generate/binaries.go:1202`. Leave each file's HTTP check as it stands.
WP4.S3. In `client/command/generate/generate.go`, add `ParseWGHTTPSc2`. It accepts only the `wg+https://` prefix, defaults the port to 443, and calls `hasValidC2AdvancedOptions`. It allows the query keys `net-timeout`, `tls-timeout`, `proxy`, `proxy-username`, `proxy-password`, and `wg-poll-interval` (a Go duration, minimum 1 s, maximum 10 m). Any other key is rejected.
WP4.S4. Add `--wg-https`/`-G` in `client/command/generate/commands.go` next to `--wg`, help text "wg-over-https connection strings (wg+https://host:port)". In `generate.go`, parse it with `ParseWGHTTPSc2` and append to the same C2 list the `--wg` flag feeds.
WP4.S5. In `implant/sliver/transports/session.go` and `beacon.go`, add `case "wg+https":` beside `case "wg":`. The handler parses the port (default 443), reads `wg-poll-interval` (default 10 s), computes the hold as `min(interval + 2 s, 50 s)` and the client timeout as `max(net-timeout, hold + 5 s)`, builds the bind with `wireguard.NewHTTPBind`, and calls `wireguard.WGConnectWithBind`. Hostname resolution stays as it is for `wg`.
WP4.S6. In `client/command/sessions/interactive.go`, add `case "wg+https":` to the scheme switch, parsing with `ParseWGHTTPSc2`, so a beacon that connected over `wg+https` can be reopened.
WP4.S7. Add a test in `client/command/generate/` that asserts `ParseWGHTTPSc2("wg+https://c2.example:8443")` keeps scheme and port, that a bare `c2.example:443` is rejected, and that `wg-poll-interval=500ms` is rejected.

**Done when:**
- `grep -n '"wg", "wg+https"' server/rpc/rpc-generate.go server/db/models/implant.go server/generate/external.go server/generate/binaries.go` prints four lines.
- `go test ./client/command/generate/ -run WGHTTP` exits 0.
- `grep -n 'wg+https' implant/sliver/transports/session.go implant/sliver/transports/beacon.go client/command/sessions/interactive.go` prints at least one line per file.

### WP5. Operator surface

**Steps:**
WP5.S1. In `client/forms/generate.go`, `client/forms/generate_beacon.go`, `client/forms/generate_profiles_new.go`, and `client/forms/generate_profiles_new_beacon.go`, add a select option "WireGuard over HTTPS" with value `"wg-https"` beside the existing `"wg"` option. Map `"wg-https"` to the `--wg-https` flag in all four switches that map `"wg"` to `--wg`: `applyGenerateForm` in `client/command/generate/generate.go:189`, `client/command/generate/generate-beacon.go:135`, and both switches in `client/command/generate/profiles-new.go` (lines 156 and 222).
WP5.S2. In `client/command/jobs/wg.go`, change the start message so it names both sockets: the UDP port, and the sentence "wg+https implants also require a running HTTPS listener; their URL port is the HTTPS port, not this UDP port." Do not add a flag.
WP5.S3. Confirm `handleWGSliverConnection` still uses `core.NewImplantConnection("wg", ...)` and do not change it. The session list shows `wg` for both, and `ActiveC2` already carries the full URL, which is where the scheme stays visible.

**Done when:**
- `grep -ln "wg-https" client/forms/*.go` prints all four form files.
- `grep -n "HTTPS listener" client/command/jobs/wg.go` prints one line.
- `grep -n 'NewImplantConnection("wg"' server/c2/wireguard.go` still prints one line.

### WP6. UDP forwarders (phase 2)

**Steps:**
WP6.S1. In `server/c2/wireguard.go`, store the `tNet` from `StartWGListener` in a package-level `wgNetstackCurrent` and clear it in the WP2 stop path. Add `WGNetstack() *netstack.Net` returning it.
WP6.S2. The relay dials out of the server netstack, so the DNS response is return traffic on a flow the stack itself opened, not a new inbound connection. `DialUDP` (`server/netstack/tun.go:395`) goes through `gonet.DialUDP` (`gvisor.dev/gvisor/pkg/tcpip/adapters/gonet`), and the Input drop rule (`server/netstack/tun.go:77-85`) decides whether that return packet is delivered. Determine which it does before writing a rule. Write one test that dials `WGNetstack().DialUDP` toward the implant forwarder and reads the reply, with no allow rule added. If that test reads the reply, no rule is needed and this step ends. If it times out or reads nothing, the drop rule is swallowing the reply: add `AllowUDPPort` next to `AllowTCPPort` (`server/netstack/tun.go:330`), matching `header.UDPProtocolNumber` the way `allowTCPPort` (line 130) matches TCP, call it for the relay's local port before dialing, and rerun the test. Do not add the rule on a guess.
WP6.S3. Add `string Protocol = 3;` to `WGPortForwardStartReq` in `protobuf/sliverpb/sliver.proto`. Run `make pb`.
WP6.S4. Create `implant/sliver/forwarder/udpforward.go`, inside the `IncludeWG` guard, with `NewWGUDPForwarder(targetAddress, tunIP string, tunPort int, tnet *netstack.Net)`. It calls `tnet.ListenUDP` on the tun IP, dials `net.DialUDP` toward `targetAddress`, keeps a flow table keyed by the source `ip:port` seen on the tun side, expires a flow after 60 s idle, and drops datagrams over 2048 bytes. Register it beside the TCP forwarders in `implant/sliver/forwarder/forwarder.go`.
WP6.S5. In `implant/sliver/handlers/handlers-wireguard.go` `wgStartPortfwdHandler`, switch on `fwdReq.Protocol`: empty or `"tcp"` starts `NewWGTCPForwarder` as today; `"udp"` starts `NewWGUDPForwarder`. Anything else sets `Response.Err`.
WP6.S6. Add `--protocol` (`tcp` or `udp`, default `tcp`) to `wg ports add` in `client/command/wireguard/`. Set `Protocol` on the `WGPortForwardStartReq`. For `udp`, after the RPC returns, bind a local UDP socket and relay each datagram through a new server RPC `WGUDPRelay` that calls `WGNetstack().DialUDP` toward the tun address the forwarder reported. Add that RPC to `protobuf/rpcpb/services.proto` and run `make pb`. The relay is the piece `WGPortFwdAddCmd` lacks today: the existing RPC only reaches the implant.
WP6.S7. Add an end-to-end test that stands up the WP2 handler, an implant device with the WP3 bind, a UDP forwarder, and the relay, then exchanges one datagram each way. Do not shell out to `dig`; write the datagram with `net.DialUDP` so the test is deterministic.

**Done when:**
- `make pb` exits 0.
- `go test ./implant/sliver/forwarder/ ./server/c2/ -run 'WGUDP'` exits 0.
- `grep -n "AllowUDPPort" server/netstack/tun.go` prints at least one line.
- `grep -n "wgNetstackCurrent" server/c2/wireguard.go` prints at least two lines (set and cleared).

### WP7. Docs

**Steps:**
WP7.S1. In `docs/sliver-docs/pages/docs/md/Wireguard C2.md`, add a section "WireGuard over HTTPS". State: the scheme is `wg+https://host:port` where the port is the HTTPS listener port; the operator must run both `jobs wg` and `jobs https`; the implant polls every 10 s by default and server-initiated packets wait up to one poll interval; `wg-poll-interval` on the URL changes that interval; `jobs https --long-poll-timeout` does not affect it; session transport stays `wg` and the scheme is visible in `ActiveC2`.
WP7.S2. In `docs/sliver-docs/pages/docs/md/Getting Started.md`, add `--wg-https` to the list of C2 endpoint flags at the line that names `--mtls`, `--wg`, `--http`, and `--dns`.

**Done when:**
- `grep -n "wg+https" "docs/sliver-docs/pages/docs/md/Wireguard C2.md"` prints at least one line.
- `grep -n "long-poll-timeout" "docs/sliver-docs/pages/docs/md/Wireguard C2.md"` prints one line.
- `grep -n "wg-https" "docs/sliver-docs/pages/docs/md/Getting Started.md"` prints one line.

## Verification

- `gofmt -l util/wghttp server/c2 implant/sliver/transports/wireguard implant/sliver/forwarder server/netstack client/command/generate client/command/wireguard client/command/jobs client/command/sessions` prints nothing.
- `go test ./util/wghttp/ ./server/c2/ ./implant/sliver/transports/wireguard/ ./implant/sliver/forwarder/ ./client/command/generate/` exits 0.
- `./go-tests.sh --unit-only` exits 0.
- `make pb` exits 0 after WP6, and `git status --short protobuf/` shows only regenerated stubs.
