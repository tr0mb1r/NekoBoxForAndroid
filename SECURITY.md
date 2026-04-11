# Security Policy — NekoBox Hardening Fork

This document covers the security posture of the hardened NekoBox fork
at `github.com/tr0mb1r/NekoBoxForAndroid` branch `hardening`, versioned
as `1.4.2-hardening.1` and derived from upstream `MatsuriDayo/NekoBoxForAndroid@1.4.2`.

For the full architectural discussion of what this fork does and why,
read the top-level [`README.md`](../README.md). This file focuses on
the *security* story: what's fixed, what isn't, how to verify, and how
to report issues.

---

## 1. Threat Model

### Who we're defending against

Android applications — installed on the same device as the VPN client
— that **actively try to determine whether the user is running a VPN
and what the VPN's exit IP is**, with the intent of reporting back to
a third party (advertiser, censor, regulatory body). In the Russian
April 2026 regulatory context, this includes the pre-installed /
mandated apps from Yandex, VK, Sberbank, Tinkoff, Ozon, Wildberries,
Gosuslugi, Kaspersky, and any third-party app that embeds their
tracking SDKs (AppMetrica, MyTracker, myTarget, etc.).

### Three independent attack surfaces

| # | Attack | Vector | Severity |
|---|---|---|---|
| 1 | **Localhost proxy abuse** | Unauthenticated SOCKS5 proxy on `127.0.0.1:2080` is reachable by any on-device app. Attacker connects, proxies an HTTP request, discovers the VPN server's exit IP. | Critical (burns the server) |
| 2 | **VPN state detection** | Public Android APIs expose `TRANSPORT_VPN` capability and enumerable `tun0` interface to any app with `ACCESS_NETWORK_STATE`. | High (privacy leak) |
| 3 | **Control API exfiltration** | NekoBox's optional Clash API on `127.0.0.1:9090` has no auth when enabled. `GET /configs` returns the full sing-box configuration including outbound UUID, server IP, Reality SNI, and public key. | Critical (server identity compromised) |

Upstream NekoBox 1.4.2 is vulnerable to **all three**. The hardening
fork closes the first two as hard bans and adds authentication to the
third.

---

## 2. What the Fork Fixes

### Phase 1 — SOCKS5 authentication (Attack 1, auth axis)

The sing-box `Inbound_MixedOptions` now always emits a populated
`users` field with a freshly-generated credential pair:

- 24 bytes from `java.security.SecureRandom`
- Split into two 96-bit halves, URL-safe Base64 encoded, no padding
- Stored in a volatile `ProxyAuth` singleton, cleared on VPN stop

Generation path: `util/ProxyAuth.kt:generate()`.
Injection path: `fmt/ConfigBuilder.kt` line ~228, inside the mixed
inbound `apply` block.

**Effect**: any SOCKS5 client that cannot present the correct
username/password is rejected at the handshake level. Attackers get
no exit IP.

### Phase 2 — Random ephemeral port (Attack 1, discovery axis)

Instead of binding to the well-known `DataStore.mixedPort` (2080 by
default), the mixed inbound now uses `ProxyAuth.allocatePort()`, which
opens `ServerSocket(0, 1, 127.0.0.1)` to claim an OS-assigned ephemeral
port, reads `localPort`, and hands that specific port to sing-box.

Observed ports across test runs: `42781`, `32907`, `46655`, `42781`
again — all in the OS ephemeral range, none in
`{1080, 2080, 8080, 10808, 10809}`.

**Effect**: a port scanner hitting the standard proxy-port list finds
nothing. A full-range scan (1024-65535) costs ~64 000 connection
attempts, and even if the attacker finds the right port, Phase 1 auth
still blocks the handshake.

### Phase 3 — Clash API 256-bit secret (Attack 3)

NekoBox's optional Clash API (`DataStore.enableClashAPI = true`)
originally exposed port 9090 with no authentication. `GET /configs`
would dump the entire sing-box config. Fixed:

- `ProxyAuth.allocateClashSecret()` generates 32 SecureRandom bytes,
  URL-safe Base64 encoded
- `fmt/ConfigBuilder.kt` populates `ClashAPIOptions.secret` when
  Clash API is enabled
- Port stays fixed at 9090 so the yacd UI bookmark remains stable;
  users type the secret once on first open, browser stores it

Verified end-to-end: `GET /configs` without the Bearer token now
returns `HTTP/1.0 401 Unauthorized` (reproduced in `phase123-validation.log`).

### Phase 4 — Hostile-app scanner (Attack 2)

Five detection layers, orchestrated by `scanner/HostileAppScanner.kt`:

1. **Package name prefix** — 30 hardcoded prefixes covering Yandex,
   VK/Mail.ru, Russian banks, telcos, marketplaces, gov services,
   and AV/security vendors
2. **Signing cert SHA-256 fingerprint** — empty built-in set, populated
   via remote signature updates (see Phase 4 extensibility below)
3. **Manifest metadata + content-provider scan** — 9 meta-data keys
   (`io.appmetrica.analytics.API_KEY`, `VKSdkAppId`, etc.) and 5
   provider authority substrings
4. **DEX class prefix scan** — 19 class descriptor prefixes across
   Tier 1 (analytics: AppMetrica, MyTracker, myTarget, Yandex Ads,
   Yandex MapKit), Tier 2 (VK/Mail.ru SDKs), Tier 3 (Sber, MirPay,
   Gosuslugi), Tier 4 (Kaspersky, Tinkoff / Sber anti-fraud). Scans
   `classes*.dex` via primary `dalvik.system.DexFile.entries()` and a
   `ZipFile`-based substring fallback. **The key innovation** — catches
   ANY app embedding these SDKs, not just first-party Russian apps.
5. **Permission heuristic** — flags `QUERY_ALL_PACKAGES`, which is a
   prerequisite for enumerating installed VPN clients

Risk classifier precedence (`HostileAppScanner.classifyRisk()`):

```
CRITICAL = DEX hit + (package name OR cert match)
HIGH     = DEX hit alone OR manifest/provider match
MEDIUM   = package name OR cert match alone
LOW      = permission heuristic only
CLEAN    = none of the above
```

`toExcludeList()` returns every package with risk ≥ MEDIUM.

### Phase 5 — Auto-exclude hostile apps from the tunnel (Attack 2, routing)

At VPN start, `BoxInstance.init()` calls
`HostileScanSession.refresh(context)`, which runs `quickScan()` (Layers
1/2/3/5 only — under 500 ms for ~100 apps), subtracts any
user-specified opt-outs from `HostileScanPrefs`, and stashes the
resulting exclude list. `ConfigBuilder.kt` reads the list inside the
tun inbound's `apply` block and merges it into
`Inbound_TunOptions.exclude_package`.

**Effect**: hostile apps see the **real ISP IP**, not the VPN exit IP,
because they route around `tun0` entirely. They can still query
`TRANSPORT_VPN` for their own UID and learn that "a VPN is active
somewhere" — but since they're not routing through it, they can't
discover the exit IP and the leak vector goes dark.

Phase 1 auth still blocks them from falling back to the local SOCKS5,
so there is no escape hatch.

### Phase 4 extensibility — Remote signature updates

`scanner/HostileSignatureUpdater.kt` fetches a JSON signature feed
**over the VPN tunnel** after `box.start()` and merges it into
`SignatureRegistry`. URL is configurable via
`BuildConfig.HOSTILE_SIGS_URL` (empty by default → no-op).

Expected JSON format:

```json
{
  "version": 3,
  "package_prefixes": ["ru.new-thing.", "..."],
  "cert_fingerprints": ["A5:12:...:F7"],
  "metadata_keys": ["com.new-sdk.API_KEY"],
  "provider_authorities": ["com.new-sdk.provider"],
  "suspicious_permissions": [],
  "class_prefixes": ["com.new-sdk.analytics"]
}
```

Versioning is strictly monotonic — `applyRemote` only accepts updates
whose `version > current_version`. All errors silently fall back to
built-in signatures. Body capped at 64 KB. Timeout 10 s.

**Fork maintenance workflow**: when a new Russian SDK needs to be
detected, publish a new `signatures.json` with bumped version to a
public GitHub repo (e.g. `tr0mb1r/hostile-sigs`), and set
`HOSTILE_SIGS_URL` in `local.properties` before the release build.
Clients pick up the update on the next VPN start.

### Phase 6 — Proxy credentials UI

The `ProxyCredsFragment` (drawer → "Local Proxy Access") surfaces the
current session's random port, username, password, full SOCKS5 URL,
and Clash API secret. Three buttons: **Copy SOCKS5 URL**, **Copy Clash
secret**, **Refresh**. Prominent warning: *"Credentials regenerate on
every VPN session."*

This exists because Phase 1 auth breaks workflows where the user
manually configures external apps (Termux, manual Telegram proxy,
yacd) against NekoBox's SOCKS5. The UI lets them re-copy the new
credentials when the VPN reconnects.

---

## 3. What the Fork Does NOT Fix (Residual Risks)

| Risk | Why unfixed | Mitigation |
|---|---|---|
| `TRANSPORT_VPN` visible to apps EVEN WITHIN the exclude list | Android framework-level signal. An excluded app is still running on a device where VpnService is active, and ConnectivityManager reports VPN=true system-wide. | Apps in exclude_package see the real ISP IP, so they can't actually **do** anything with the signal (they can't block a specific server they don't know about). Full mitigation requires device separation (separate phone, work profile). |
| `tun0` interface name enumerable via `NetworkInterface.getNetworkInterfaces()` | Android API design. | LSPosed hook (root-only). Out of scope for this fork. |
| Datacenter exit IP visible to correlating third parties | Not a client-side issue. Even with full Phase 1-6 hardening, the VPN server's IP is in an AWS / Hetzner / etc. range that third parties can recognize. | Residential proxy, CDN fronting (Cloudflare WebSocket), or an ISP-backed VPS. See [`README.md`](../README.md) section 3.5. |
| New tracking SDK ships before signatures arrive | Signature lag. | Phase 4 extensibility: push an updated `signatures.json` with bumped version; clients pick it up on next VPN start. |
| Device compromised at root level | Out of scope. | Verified boot, don't root, don't install untrusted apps. |

---

## 4. How to Verify a Build

### 4.1 Signing certificate identity

Any release APK claiming to be a hardening-fork build should be
signed by:

```
Signer DN:         CN=NekoBox Hardening Fork, O=vpn-android, C=ES
Cert SHA-256:      24a183cbbeea321b28043d0b5954909d957d234bfc641c9b2de4d27947d95214
Cert SHA-1:        c20fdc990efacf689dd61aec5df74ba583e9a6d5
Validity:          2026-04-11 → 2056-04-03 (30 years)
Key algo:          RSA 4096, SHA384withRSA
```

Verify with:

```bash
apksigner verify --print-certs NekoBox-1.4.2-hardening.1-arm64-v8a.apk
```

If the printed SHA-256 does not match `24a183cbbeea321b28043d0b...`
above, the APK was not built from this tree with our signing key and
should NOT be trusted as a hardening-fork release.

### 4.2 Source-level verification

The hardening branch is publicly visible at
<https://github.com/tr0mb1r/NekoBoxForAndroid/tree/hardening>. The
chain of commits from the upstream tag `1.4.2`:

```
1c30746 Phase 4 extensibility: remote signature update mechanism
4bee6be Phase 4+5: hostile-app scanner with split-tunnel auto-exclude
68e34a9 hardening: stop tracking release.keystore, add build cruft to .gitignore
7467673 hardening: bump version to 1.4.2-hardening.1
a94123f hardening: Phase 1+2+3 localhost attack mitigation + Phase 6 creds UI
5768494 1.4.2                                                     (upstream)
```

Reproducible build from source: see [`README.md`](../README.md) section 4.

### 4.3 Runtime verification (on device)

The repo ships two regression-test artifacts in `vpn-android/` at the
workspace level:

- `baseline-leak.log` — the unpatched PoC attack against upstream,
  showing `open_proxy=SOCKS5 host=127.0.0.1 port=2080` and
  `ip_via_proxy=<vpn-exit-ip>` (the exploit working)
- `post-fix-leak.log` — the same PoC against the patched build,
  showing `open_proxy=NONE` (the exploit blocked)
- `phase123-validation.log` — the seven-step full validation run
  (`scripts/run-phase123-validation.sh`) capturing random port
  randomization, well-known port closure, Clash API 401, and
  server-side journalctl traffic traces

To re-run against your own build + your own test VPS:

```bash
terraform -chdir=terraform apply     # provision fresh VPS
scripts/redeploy-nekobox.sh          # build + clean install
scripts/run-phase123-validation.sh   # run full 7-check matrix
```

---

## 5. Reporting Security Issues

If you find a bug in this fork that weakens any of the three attack
surface mitigations — Phase 1/2 SOCKS5 auth + random port, Phase 3
Clash API secret, Phase 4/5 hostile-app split-tunnel — please:

1. **Do not** open a public GitHub issue with a working exploit
2. **Do** open a private security advisory via GitHub's "Security"
   tab on the repository, or email the fork maintainer
3. Include:
   - Which phase the bug affects
   - A minimal reproducer (PoC code is welcome)
   - Observed vs. expected behavior

Upstream NekoBox bugs that pre-date the hardening work should be
reported to `MatsuriDayo/NekoBoxForAndroid` directly.

## 6. Disclosure Timeline Policy

90 days from receipt of a private report. If the issue is actively
being exploited in the wild, we will coordinate an earlier disclosure.

---

## 7. Version History

| Version | Date | Commit | Notes |
|---|---|---|---|
| 1.4.2-hardening.1 | 2026-04-11 | `1c30746` | Phase 1-6 + extensibility, initial public release |

---

## 8. License

NekoBox is GPL-3.0. This hardening work is distributed under the same
license. The release signing key is **not** covered by the license —
it's a private credential held by the fork maintainer.
