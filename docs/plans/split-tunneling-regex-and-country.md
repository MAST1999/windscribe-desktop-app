# Plan: Regex-Based Split Tunneling + Country-Based Pass-Through

Branch: `feature/split-tunneling-regex-and-country`
Status: design / planning
Scope decision: Linux implementation first; config model designed cross-platform. Regex applies to
**process paths and domains**. Country pass-through = **destination-IP GeoIP → direct (bypass tunnel)**,
selected via a country picker backed by a **user-provided GeoIP database file**: the user downloads
DB-IP LITE or MaxMind GeoLite2 themselves and points Windscribe at the file. **No GeoIP data is
bundled or redistributed** (licensing-clean by construction, smaller installer).

---

## 1. Feature summary

Two additions to split tunneling (ST), inspired by sing-box / clash-style routing rules:

| Feature | Meaning | sing-box analogue |
|---|---|---|
| **Regex process rules** | Match process exe paths (and optionally argv) by regex instead of exact/prefix only | `process_path_regex` rule item (SRS type 17) |
| **Regex domain rules** | Match hostnames by regex; their resolved IPs bypass (or use) the tunnel | `domain_regex` rule item (SRS type 4) |
| **Country pass-through** | Traffic whose *destination IP* belongs to a selected country is routed outside the tunnel, for all processes | `geoip` / `geoip-country` route rule + `ExtractIPSet()` system-level application |

Non-goals (v1): per-country *include* semantics (forcing selected countries into the tunnel in
include mode), Windows/macOS enforcement, ASN-based rules.

---

## 2. Hard requirements

1. **Toggle latency must not regress.** ST enable/disable and settings changes stay sub-second even
   with a few selected countries and ~100 regex rules.
2. **User-supplied regex runs in a root helper.** Must be immune to catastrophic backtracking
   (ReDoS) — a stalled classifier stalls fork/exec classification for the whole system.
3. **Kill-switch interplay.** Bypassed traffic must remain accepted by the nft `st_in`/`st_out`
   filter chains when the always-on firewall is active (fail-closed firewall is the default).
4. **No new persistent kernel state.** Everything must be created/destroyed with the existing ST
   lifecycle so disable is a clean teardown.

---

## 3. Where we are today (facts from code investigation)

### 3.1 Rule data path

```
GUI/CLI → types::SplitTunneling (client-common/types/splittunneling.h)
          caps: kMaxApps=50, kMaxHostnames=50, kMaxIpRoutes=4096, kMaxStringLen=4096 (:303-306)
       → Preferences (persists inside GuiSettings, emits splitTunnelingChanged)
       → Backend::sendSplitTunneling (frontend-common/backend/backend.cpp:898-924)  ← single choke point
       → Engine::setSplitTunnelingSettingsImpl (engine/engine.cpp:2565-2583)
       → Helper_posix::setSplitTunnelingSettings (helper/helper_posix.cpp:27-31)
       → HelperCommand::setSplitTunnelingSettings frame (helper/common/helper_commands.h:28, :396-407)
          [cmdId][pid][len≤4MiB][boost::binary archive of (active, exclude, allowLan, files, ips, hosts)]
       → helper/linux/process_command.cpp:51-66 (validates IPs; one bad IP rejects the whole command)
       → SplitTunneling::setSplitTunnelingParams (helper/linux/split_tunneling/split_tunneling.cpp:30-59)
```

- **No delta protocol**: every change re-sends the full snapshot; the helper diffs internally.
- The RPC tuple is **positional** (boost archive varargs) → client and helper must change in
  lockstep, or a new command id is added.
- Rule *kinds* are an enum with only `IP`/`HOSTNAME` (`enums.h:199-202`), and
  `SplitTunnelingNetworkRoute::validate()` (`splittunneling.h:163-174`) **re-derives the type from
  the string shape** — regex/country entries need an explicit kind that survives validation.
- Serialization is versioned already (`versionForSerialization_`), CLI INI serialization exists.

### 3.2 Linux enforcement (what the kernel sees)

- **Process classification**: cgroup v1 `net_cls` (`classid 0xcafecafe`) + `ProcessMonitor`
  (netlink proc-connector, 250 ms poll). On fork/exec, `compareCmd`
  (`process_monitor.cpp:536-634`) matches: exact exe path, Flatpak app-ID, `/snap/` prefix,
  directory prefix, shebang-script argv, wine/Proton Windows-path argv (`path_matching.h`).
  **No glob/regex anywhere.** Rule compilation already happens on a dedicated worker thread with
  atomic swap (`rulesWorker`, `process_monitor.cpp:248-281`); a full `/proc` rescan runs on enable
  and after rule changes.
- **Hostname/IP rules**: helper resolves hostnames itself via WSNet (no DNS interception),
  merges resolved /32+/128 with user CIDRs, pins `ip route <dst> … proto 87` in `main`
  (one **`ip` process spawn per pin**, `ip_routes.cpp:312-335`), plus per-IP accept rules in nft.
  Diff-based updates; `RouteChangeMonitor` (rtnetlink, debounced 500 ms) re-pins on main-table
  changes (exclude mode).
- **Exclude-mode bypass**: `st_route_out` marks cgroup traffic `0xdecafbad` (connmark save/restore)
  → `ip rule prio 16384 fwmark 0xdecafbad table 69 (physical default)`, masquerade in
  `st_nat_post`. Kill-switch chains already contain **`meta mark 0xdecafbad accept`** in
  `st_in`/`st_out` — anything marked is accepted.
- **All nft changes go through `NftablesController::run`** — one in-process libnftables
  transaction (`nft_run_cmd_from_buffer`, equivalent to `nft -f -`), atomic. ST chains are flushed
  and rebuilt in a single transaction per change (`firewallcontroller.cpp:305-403`).
- **No ipset / no nft named sets** exist yet anywhere.

### 3.3 Toggle cost today (the baseline we must protect)

| Step | Cost |
|---|---|
| `cgroups-up` / `cgroups-down` scripts | Fixed: 1 bash fork + ~15–25 child spawns |
| `ProcessMonitor` enable/disable | Fixed (socket + thread) + O(#pids × #rules) `/proc` scan; **skipped if `apps_` empty** (`split_tunneling.cpp:65-74`) |
| `IpRoutes` pins | **1 `ip` spawn per changed pin** (~5–10 ms each) — dominant at high rule counts |
| nft ST chains | Full chain rebuild, 1 transaction, O(#ip-exceptions) rules |
| `MainRouteTable` coverage scan | O(#main-routes × #ips), 2 `ip -j route show` spawns |

→ **Country sets and regex rules must add zero process spawns and zero per-rule rules** to the
toggle path. The design below achieves that.

### 3.4 Reusable assets

- ISO country codes for every location: `types::Location::countryCode` (`location.h:46`) + 185
  per-country flag SVGs (`frontend/gui/svg/flags/`) + locations API — the country picker UI is
  nearly free.
- `open_source_licenses.txt` for attribution of the GeoIP data.
- `RouteChangeMonitor`, `MainRouteTable` (rapidjson `ip -j` parsing), `NftablesController` set/map
  builder helpers (`nftablescontroller.h:18-81`) — the exact primitives needed.
- vcpkg is already the dependency manager (`cmake/vcpkg.cmake`).
- Helper-side async work precedent: `DnsResolver` (WSNet) with retry timer.

---

## 4. Research findings (external)

### 4.1 How sing-box does it (and what transfers to us)

- SRS rule-set binary format: 3-byte magic `"SRS"` + version + zlib; typed rule items
  (`domain`, `domain_regex`, `ip_cidr`, `process_path`, **`process_path_regex`**); IP sets stored
  as **merged `{from,to}` ranges**, not CIDRs.
  (https://singbox-internals.hidandelion.com/advanced/rule-sets.html)
- sing-box computes **`RuleSetMetadata`** (e.g. `ContainsProcessRule`) so the hot path skips
  expensive lookups when no rule needs them — we'll do the same (`hasRegexRules_`,
  `hasCountryRules_` flags).
- sing-box's `ExtractIPSet()` deliberately pushes IP rules **down to the system routing level**
  instead of per-connection matching — same philosophy as ours: regex at classification time,
  countries in the kernel data path.
- **Key architectural difference**: sing-box/clash match domains per-connection because they are
  userspace proxies (they see SNI/DNS metadata). A route-based split tunnel has **no per-connection
  vantage point** — domain matching must happen at the DNS layer. This drives the phasing in §5.4.
- clash/mihomo: same rule taxonomy (`DOMAIN-REGEX`, `GEOIP` mmdb, trie-based domain matcher).
  v2fly `geoip.dat`: protobuf of per-country CIDR lists, generated monthly from GeoLite2.

### 4.2 GeoIP data — licensing and acquisition model

| Source | License | Usable? |
|---|---|---|
| MaxMind **GeoLite2** | GeoLite EULA; *redistribution* in a product requires a paid license (~$10k/yr class) | **Yes — only if user-downloaded.** The end user accepts the EULA and obtains the file themselves; the app never ships the data (https://www.maxmind.com/en/geolite/eula, /en/site-license-overview) |
| **DB-IP LITE** (ip-to-country) | **CC BY 4.0** — free even for commercial redistribution, attribution required | **Yes** — the easiest option for users: direct download, no account (https://db-ip.com/db/lite.php) |
| sapics/ip-location-db | CC BY 4.0 aggregations | Yes (https://github.com/sapics/ip-location-db) |
| v2fly geoip.dat | Generated *from* GeoLite2 → EULA-tainted, even user-side murky | Avoid |

**Decision: bring-your-own-database (BYOD).** Windscribe bundles *no* GeoIP data. The user
downloads a supported file and selects its path in the ST settings. This mirrors the established
pfSense/OPNsense model for GeoLite2 (they integrate parsing but require the user to supply the
DB), keeps the installer ~4 MB smaller, and removes attribution/EULA obligations from the app
itself. Supported inputs (v1), detected by content, not extension:

- **DB-IP LITE `dbip-country-lite.csv`** — single CSV, `ip_range_start,ip_range_end,country_code`; simplest.
- **MaxMind GeoLite2-Country CSV zip contents** — `GeoLite2-Country-Blocks-IPv4.csv` +
  `-IPv6.csv` + `Locations-en.csv` (geoname_id → ISO code); two-step mapping, same parse loop.
- *(Stretch)* MaxMind `.mmdb` via `libmaxminddb` (MIT) — requires walking the trie to enumerate
  ranges (the lib only does point lookups); defer unless CSV support proves annoying for users.

### 4.3 Kernel mechanics for country sets — measured reality

- nftables named sets with `flags interval` are the right structure; `auto-merge` merges
  overlapping/adjacent ranges in the userspace frontend
  (https://www.netfilter.org/projects/nftables/manpage.html).
- **Cautionary data point** (OpenWRT forum, 2023 — https://forum.openwrt.org/t/nftables-chokes-on-very-large-sets/172580):
  a *200k-element* interval set made **every** nft operation crawl (`nft list ruleset` 13 s,
  adding 1 element to an unrelated set 20 s) on a weak MIPS router; merging to ~80k elements made
  it acceptable. Population via one batch transaction stayed fast (~3 s) even on that hardware.
- Read-across to our case: (a) desktop x86-64/arm64 CPUs and RAM are 1–2 orders faster; (b) our
  helper **never dumps the ruleset** and applies changes as single in-process transactions; (c) a
  *single country* merges to ~5–30k ranges (whole-DB, all countries ≈ 200k). Selected-country sets
  are comfortably in the safe zone, and we pre-merge ranges ourselves instead of relying on
  `auto-merge`.
- Kernel set memory ≈ few hundred bytes/element → 30k elements ≈ ~8 MB. Negligible on desktops.
- `ip route` FIB (alternative design) is also fine at this scale (LC-trie, that's its day job) —
  but it needs per-country *accept* rules for the kill-switch, which drags us back to a big nft
  set anyway. See §5.5 for why the mark-based design wins.

### 4.4 Regex engine choice

| Engine | Match cost | Compile cost | ReDoS-safe | Footprint | Verdict |
|---|---|---|---|---|---|
| `std::regex` | backtracking, can explode | ~0.1–1 ms/pattern | **No** | stdlib | Fallback only |
| **RE2** | linear (DFA/NFA), µs-level | ~50–200 µs/pattern | **Yes** (designed for untrusted patterns) | vcpkg `re2` port | **Chosen** |
| Hyperscan/**Vectorscan** | fastest multi-pattern (tens of thousands of patterns) | very high; large DBs | yes | heavy dep; ARM needs Vectorscan fork | Overkill for ≤100 patterns (https://github.com/ClickHouse/vectorscan, https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/) |

100 sequential RE2 matches per fork/exec event ≈ 50–200 µs — irrelevant at desktop process-creation
rates. RE2's linear-time guarantee is the decisive property for rule #2.

### 4.5 Prior art

- sing-box/clash/mihomo/xray: rule-based routing (the model we borrow).
- Mullvad/Proton: app/IP-based split tunneling only; per-country ST exists mainly in
  router/CLI firewall tooling (nft geoip howtos), not in mainstream desktop clients — this feature
  would be genuinely differentiating.

---

## 5. Proposed design

### 5.1 Data model (client, cross-platform)

In `types/splittunneling.h` + `enums.h`:

- Extend `SPLIT_TUNNELING_NETWORK_ROUTE_TYPE`: add `REGEXP` (domain regex) and `COUNTRY`
  (value = ISO-3166 alpha-2, lowercased). Keep the existing flat list; `validate()` gains
  explicit-kind branches (regex: parse + length checks; country: `NetworkingValidation` ISO check)
  **instead of shape-derivation** for the new kinds.
- Extend `SplitTunnelingApp` with `isRegex` (bool). A regex app entry's `fullName` *is* the
  pattern; the JSON ctor's file-existence drop must not apply to regex entries.
- New caps: `kMaxRegexRules = 100` (combined domains+process), `kMaxCountryRules = 10`,
  pattern length ≤ 512. Bump all three `versionForSerialization_` values.
- CLI INI: regex entries serialized as `re:<pattern>` lines, countries as `country:<cc>` lines in
  the existing `SplitTunnelingRoutes` string lists.

### 5.2 IPC protocol

Add **`HelperCommand::setSplitTunnelingSettingsV2`** (new id, same frame format) carrying
`(V1 tuple…, vector<string> regexProcessRules, vector<string> regexDomainRules, vector<string> countryCodes, string geoipDbPath)`.
V1 handler stays untouched → old-client/new-helper and new-client/old-helper both degrade safely
(new features off). The `kMaxHelperFrameSize` (4 MiB) headroom is ample: country *codes* are 2 bytes
and the DB path is a single string — the ranges themselves never cross the IPC.

### 5.3 Regex process rules (Linux) — clean fit

- `AppRule` (`process_monitor.h:26-34`) gains `std::optional<re2::RE2> pattern` (RE2 objects are
  immutable → safe for the atomic `rules_` swap).
- Compile in `ruleFor` (`process_monitor.cpp:360-399`) — already on the rules worker thread,
  off the toggle critical path. Compile failure → rule dropped + logged (client pre-validates too).
- Match in `compareCmd` (at `:544`): regex rules test the resolved exe path and (lazily, like the
  wine gate at `:592-614`) argv tokens. cwd matching is **deliberately excluded** (existing
  escape-hatch rationale, comment `:607-614`).
- Pure helpers live in `path_matching.h` (or a sibling `regex_matching.h`) unit-tested in
  `tests/pathmatching.test.cpp` (framework-free, links RE2 only in the helper target).
- Cost: compile once per rule change (worker thread); O(#regex × 1 match) per fork/exec event.
  No toggle-path change; `scanAndAddAll` cost grows by #regex per pid — acceptable at ≤100.

### 5.4 Regex domain rules (Linux) — the honest hard part

Route-based ST has no per-connection domain vantage point. Options:

| Option | Mechanism | Assessment |
|---|---|---|
| **A. DNS interposition** | nft redirect of outbound udp/tcp/53 (and DoH bootstrap risk) to a small helper resolver; resolver matches the qname against regexes, resolves, feeds IPs into a small dynamic nft set (timeouts) | Correct sing-box-like semantics; **new infra** (mini-resolver in helper). DoH/DoT traffic bypasses it → leaks classification |
| B. Resolve-and-pin | Only usable for *literal* hostnames (already exists today) | Cannot enumerate regex matches — doesn't work |
| C. Defer | v1 ships regex for **process paths** only; domain regex documented as roadmap | Smallest risk; users still get domain coverage via exact hostnames (50) + IP CIDRs (4096) |

**Recommendation: C now, A as Phase 3.** Phase 3 sketch (so the v1 model doesn't box us in):
the helper already owns DNS-adjacent machinery patterns (`ctrld` management, `dnsleakprotect`
chains); a `DomainRegexResolver` threading `qname → regex set → dynamic nft set` slots beside
`HostnamesManager`, and the v2 IPC already carries the patterns. Note in UI copy that domain regex
applies at the DNS layer when it ships.

### 5.5 Country pass-through (Linux) — reuse the mark pipeline

Everything needed already exists; the feature is mostly *population* of existing structures:

1. **Data acquisition (user-provided file, BYOD)** — no bundled data. The user downloads
   DB-IP LITE (no account) or GeoLite2-Country CSV (accepting MaxMind's EULA themselves) and
   selects the file/folder path in the ST settings. Windscribe only ever *reads* the file.
2. **Ingestion & caching (helper-side)** — a `CountryRangesLoader` parses the selected file and
   builds an in-memory per-country index of **pre-merged** `(from, to)` ranges
   (~all-countries worst case ≈ 200k ranges, a few MB RSS; single country ≈ 5–30k ranges).
   - Parse cost (~0.3–1 s for a 500k-row CSV) happens **once per file**, on a worker thread, *not*
     on the toggle path. The helper is a long-running daemon → the parsed index stays resident;
     it is invalidated only when the file's `(size, mtime)` changes (checked on enable, so the
     user just re-downloads a monthly file over the old one — no re-selection needed).
   - Toggle path touch: build the element list for the selected countries from the resident index
     by a sorted-array scan (ms-level) — no parsing, no IPC bulk, no subprocess.
   - Parse feedback is surfaced to the client (ranges parsed, DB provider, build date if
     available, per-country range counts) for the UI's validation state.
3. **Client**: sends only the selected ISO codes + the DB path in the v2 command. UI = new
   "Countries" section in the ST addresses screen: a DB file picker with validation state
   (empty state links to the DB-IP/GeoLite2 download pages), then a flag grid (reuse
   `svg/flags` + `imageresourcessvg`), multi-select up to `kMaxCountryRules`.
4. **Helper (`FirewallController::buildSplitTunnelRules`, `firewallcontroller.cpp:305-393`)** —
   all inside the *existing single nft transaction*:
   ```
   add set inet windscribe ws_countries { type ipv4_addr; flags interval; }
   add set inet windscribe ws_countries6 { type ipv6_addr; flags interval; }
   flush set inet windscribe ws_countries / ws_countries6
   add element … ×N            ← merged ranges for selected countries, from the resident parsed index
   add rule st_route_out  ip  daddr @ws_countries  meta mark set 0xdecafbad ct mark set 0xdecafbad
   add rule st_route_out  ip6 daddr @ws_countries6 meta mark set 0xdecafbad ct mark set 0xdecafbad
   add rule st_nat_post  (matching @ws_countries → masquerade)   ← alongside the cgroup rule
   ```
   - Marked country traffic then rides the **existing** `ip rule prio 16384 → table 69` policy
     routing and the **existing** `meta mark 0xdecafbad accept` entries in `st_in`/`st_out`
     (kill-switch-safe for free, rule #3).
   - Zero new `ip rule`/`ip route` entries, **zero new process spawns**; table 69 (and the whole
     bypass) still appears/disappears with the ST lifecycle (rule #4).
   - Set elements come from the resident parsed index (§5.5 item 2) — a sorted-array scan for the
     selected countries, ms-level, re-scanned only when the selection or the DB file changes.
     Ranges are **pre-merged at parse time**, **no `auto-merge`** (we control range count; avoids
     the frontend merge cost and the pathology class from §4.3).
5. **Semantics**: destination-IP based, applies to *all processes* (exactly like sing-box
   `geoip` rules and like today's per-IP exceptions, which are also not cgroup-scoped).
   Matches happen on the resolved destination IP — CDN-hosted sites may egress via the country
   their CDN node is in; documented in UI copy. **Include mode: no-op** (all non-cgroup traffic is
   already direct); shown greyed-out in include mode in v1.
6. **Interaction with per-IP/hostname rules**: country ranges are strictly wider; user CIDR pins
   (`proto 87` in `main`) are destination routes that win earlier (prio 16383 main-suppress vs
   mark rule 16384) — matching today's precedence where specific pins beat marks. Verify in
   integration tests.

### 5.6 Cross-platform notes (design only, no code in v1)

- **Windows**: country CIDRs map onto `WINDSCRIBE_CALLOUT_DATA.excludeAddresses`
  (`src/splittunneling/windows/WindscribeCallout.h:40-90`) — the provider-context blob is a single
  WFP add, so expansion client-side (or a shared range-list format) is cheap. Regex *process*
  rules are structurally hard there (WFP `ALE_APP_ID` = exact blob equality) → needs callout-driver
  work (`CalloutFunctions.c`); document as limitation.
- **macOS**: expanded country CIDRs feed `IpHostnamesManager` / the extension plist
  (`additive-key` pattern, `splittunnelextensionmanager_mac.mm:40-42`) with zero provider changes;
  regex process matching slots into `Settings.mm::isSplitTunnelApplicable:` (`:338-381`).
- The v2 IPC tuple is designed so Win/mac helpers can adopt it incrementally (unknown fields are
  simply the new lists they may ignore until implemented).

### 5.7 Validation & security

- Client: RE2-parse check via a small Qt-side wrapper (link RE2 into client-common), length/NUL
  caps, reject `(?…)`-flag-heavy patterns? (no — RE2 supports them safely; rely on linear time).
- Helper: same validation re-applied (`validation_posix.cpp` gains `isValidRegex`,
  `isValidCountryCode`); invalid entries dropped, never command-rejecting (aligns with Win/mac
  posture; the current Linux "one bad IP rejects whole command" behavior is not extended).
- Country codes whitelisted against the DB's country table.
- **GeoIP file handling (BYOD)**: the helper reads a user-chosen path as root — validate before
  trusting: parse defensively (bounded row length, row-count cap, NUL/binary sniffing), treat any
  parse error as "no country rules" with a user-visible state, never reject the whole ST command
  because of a bad DB file. Path is stored client-side (Preferences) and re-sent each v2 command;
  the helper keeps only the *parsed index*, not the path, in any persistent state.
  TOCTOU on re-read is acceptable (worst case: a partially updated monthly CSV → parse error →
  rules off until next successful parse).

---

## 6. Performance analysis (toggle budget)

| Scenario | Δ vs today | Why |
|---|---|---|
| ST toggle, no new rules | **0** | New code paths gated on empty rule lists (flags set like sing-box metadata) |
| + 100 regex process rules | **~0 ms** on toggle | Compile+swap on rules worker thread (async); `/proc` rescan O(pids × (rules+regex)) happens off-toggle, same as today |
| + 1–3 countries (~5–90k merged ranges) | **+ one transaction commit**, est. 10–150 ms on desktop x86; ~3–8 MB kernel set memory | Single atomic nft transaction we already perform; elements are the only added work; no forks, no new `ip` invocations |
| + 10 countries (cap) | worst case ~+0.3–0.5 s commit | Still one transaction; far below the 80k-element "acceptable" zone from §4.3 even at 4–6 v4 ranges merged |
| Regex domain rules (Phase 3) | + DNS-redirect latency only for DNS traffic; toggle unaffected (set updates async) | Resolver runs on its own thread like `DnsResolver` |
| First enable with a fresh GeoIP file | one-time +0.3–1 s parse, off the critical path (worker thread) | CSV parse cached in the resident helper index; subsequent toggles pay nothing until the file changes |

Guardrails encoded in the design: country cap (10), pre-merged ranges, single-transaction
application, no ruleset dumps, parse-once/cache-forever indexing keyed on `(size, mtime)`.

---

## 7. Phased roadmap

**Phase 1 — Country pass-through (Linux)** *(ships the bigger win first; exercises v2 IPC + nft sets)*
1. `CountryRangesLoader`: content-sniffing parser for DB-IP LITE CSV and GeoLite2-Country CSV
   (blocks v4/v6 + Locations mapping), pre-merge to `(from,to)` ranges, resident index with
   `(size, mtime)` invalidation + worker-thread parsing (`src/helper/linux/split_tunneling/`).
2. Client model: `COUNTRY` route type, cap, validation, serialization bump
   (`types/splittunneling.h`, `enums.h`, `networkingvalidation.*`) + tests in
   `settingsvalidation.test.cpp`.
3. IPC: `setSplitTunnelingSettingsV2` (helper_commands, all three `process_command.cpp`s; Win/mac
   parse-and-ignore new fields for now).
4. Helper Linux: nft set builders + mark/masquerade rules in `buildSplitTunnelRules` fed from the
   parsed index; include-mode no-op; teardown in disable path.
5. UI: DB file picker with validation state (empty state links to DB-IP/GeoLite2 downloads) +
   countries flag-picker section; CLI INI support (`country:<cc>` lines).
6. Tests: helper unit tests for parsing both CSV shapes, merging, and invalidation; nft builder
   golden test; manual perf script (time toggle with 1/3/10 countries); kill-switch-on
   integration check; bad-file/corrupt-file graceful-degradation test.

**Phase 2 — Regex process rules (Linux)**
1. RE2 via vcpkg (`cmake/vcpkg.cmake`, helper + client-common targets).
2. Model: `isRegex` app flag + caps + validation (`re2::RE2::RE2(pattern).ok()`), serialization.
3. `AppRule.pattern`, compile in `ruleFor`, match in `compareCmd` (exe + gated argv);
   `regex_matching.h` + `pathmatching.test.cpp` cases (word-boundary pitfalls, `\\?\`-prefixed,
   wine paths, flatpak/snap interplay).
4. UI: "Add regex" affordance in app rules; CLI `re:` lines.
5. Perf check: classification latency with 100 regexes (microbench in `helperutils.test` style).

**Phase 3 — Regex domain rules (Linux, design per §5.4-A)**
1. DNS redirect chain + helper mini-resolver (async, own thread) → dynamic nft set with timeouts.
2. Reuse v2 IPC patterns (already carried); UI enable + copy about DNS-layer semantics.

**Phase 4 — Windows/macOS adoption** per §5.6.

Each phase is independently shippable and revertable.

---

## 8. Risks / open questions

1. **nft set size pathology** (§4.3): mitigated by caps + pre-merging + desktop hardware; verify
   empirically in Phase 1 perf script before widening caps.
2. **GeoIP accuracy**: DB-IP LITE is country-level and community-fed; mismatched CDN edge IPs will
   occasionally surprise users → set expectations in UI copy (same caveat sing-box users accept).
3. **Precedence questions**: user expects specific-IP rules to beat country rules — current kernel
   ordering gives that; lock it with integration tests.
4. **Upstream acceptance**: RE2 is a new dependency (vcpkg port — small, no system deps). If
   upstream balks, fallback is `std::regex` with strict caps + documented ReDoS boundary
   (client-side validation only, no untrusted patterns in helper without RE2).
5. **Phase 3 DNS redirect** interacts with ctrld/custom-DNS features — needs its own design review
   before implementation.
6. **BYOD UX friction** (the cost of the licensing win): the user must obtain a file before country
   rules work, and monthly freshness is on them. Mitigations: empty-state deep links to the
   DB-IP/GeoLite2 download pages, clear "DB loaded: provider/date, N ranges" status, stale-file
   warning when the file is older than ~2 months, and `(size, mtime)` auto-invalidation so
   re-downloading over the same path "just works".
7. **GeoLite2 zip**: MaxMind ships the CSVs zipped — v1 asks users to select the extracted CSV
   (or the extraction folder); in-zip parsing (Qt supports via `miniz`) listed as a follow-up
   convenience.

---

## 9. Sources

- sing-box rule-sets/SRS internals — https://singbox-internals.hidandelion.com/advanced/rule-sets.html
- sing-box rule-set docs — https://sing-box.sagernet.org/configuration/rule-set/ , /configuration/rule-set/source-format/
- nft(8) manpage (sets, interval, auto-merge) — https://www.netfilter.org/projects/nftables/manpage.html
- OpenWRT forum: nftables chokes on very large sets (measurements) — https://forum.openwrt.org/t/nftables-chokes-on-very-large-sets/172580
- GeoLite2 EULA (no redistribution) — https://www.maxmind.com/en/geolite/eula , https://www.maxmind.com/en/site-license-overview
- DB-IP LITE (CC BY 4.0) — https://db-ip.com/db/lite.php
- sapics/ip-location-db (CC BY 4.0 alt sources) — https://github.com/sapics/ip-location-db
- Vectorscan (portable Hyperscan) — https://github.com/ClickHouse/vectorscan
- Regex engine comparison (Hyperscan/RE2/std::regex) — https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/
- RE2 design (linear time, untrusted patterns) — https://swtch.com/~rsc/regexp/regexp3.html
- v2fly/geoip (GeoIP.dat pipeline) — https://github.com/v2fly/geoip
- MaxMind DB format spec (binary search tree, µs lookups) — https://maxmind.github.io/MaxMind-DB/
