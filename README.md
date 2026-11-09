# keepalivedwho

Which include file:line declared this `vrrp_instance` /
`virtual_server` / VIP — and is it gated by a config-id
conditional?

`keepalived -t` validates a config; it never answers provenance
questions. `keepalived -d` dumps the merged config for *this*
node's config-id — the include chain already flattened, the `@`
conditionals already resolved, no file:line attached to any
declaration — and it cannot show the declarations that were gated
*out* for this node, or be run against a config that is not this
node's. grep prints every candidate line and adjudicates none of
them — and it cannot see that plain `include` silently tolerates
a missing file while `includea` makes the same miss a config
error (KV03), which is exactly the distinction that decides
whether a missing VIP file means "not declared" or "config
broken". `keepalivedwho` is a static model of keepalived's
documented configuration rules that answers the question with
file:line provenance, and says GATED-UNKNOWN or UNKNOWN (naming
the blocker) whenever the answer is not statically knowable.

## Usage

```
keepalivedwho VIP [--config-id ID] [--conf FILE]...
keepalivedwho VIP:PORT [--config-id ID] [--conf FILE]...
keepalivedwho INSTANCE [--config-id ID] [--conf FILE]...
keepalivedwho fwmark N [--config-id ID] [--conf FILE]...
keepalivedwho --list-instances [--conf FILE]...
keepalivedwho --list-vips [--conf FILE]...
keepalivedwho --list-servers [--conf FILE]...
```

- One positional query: a bare IP (VIP search across VRRP VIPs
  and virtual_servers), an `IP:PORT` (virtual_server only), an
  instance/group name (instance search), or the two-token
  `fwmark N` (fwmark virtual_server). A name that matches both
  an instance and a virtual_server_group is answered for both,
  labeled by kind — never silently one of them. A query carrying
  a mask (`10.0.0.5/24`) matches on address equality; the mask
  is shown for comparison, never as a filter (KV10).
- `--config-id ID` resolves `@` conditionals deterministically
  (KV05). Without it, `@`-gated lines are [gated-unknown] —
  never silently included, never silently dropped. The tool
  deliberately does **not** default to the local hostname (the
  daemon's default): it is usually run off-node, where the local
  hostname is the wrong node.
- `--conf` is repeatable; files are concatenated in the order
  given (a keepalivedwho convenience — keepalived itself takes
  one `-f` file; the concatenation is bannered). Default:
  `/etc/keepalived/keepalived.conf` if it exists, else exit 2.
- `--list-instances` lists every `vrrp_instance` and
  `vrrp_sync_group` in load order, with header file:line,
  interface, VRID, state, priority, VIP count, and gate state.
  `--list-vips` lists every VIP (`virtual_ipaddress` +
  `virtual_ipaddress_excluded`) with address, mask, owning
  instance, file:line, excluded flag, and gate state.
  `--list-servers` lists every `virtual_server` and
  `virtual_server_group` with form, file:line, protocol,
  scheduler, quorum, real-server count, and group members.
  Inventory modes exit 0 with ≥1 item, 1 with none.
- `--json` renders the same structure machine-readably; `--quiet`
  prints the verdict line only; `--version` prints the version.

## Examples

```bash
# Which file declared VIP 10.0.0.5, and is it gated?
keepalivedwho 10.0.0.5 --conf /etc/keepalived/keepalived.conf

# Same query, resolved for node "main"
keepalivedwho 10.0.0.5 --config-id main --conf keepalived.conf

# Which virtual_server serves 10.0.0.5:443?
keepalivedwho 10.0.0.5:443 --conf keepalived.conf

# What does this instance declare, with file:lines?
keepalivedwho VI_1 --conf keepalived.conf

# Map the whole config
keepalivedwho --list-vips --conf keepalived.conf
keepalivedwho --list-instances --conf keepalived.conf
```

## Verdicts

| Verdict | Meaning | Exit |
|---|---|---|
| `FOUND` | Declaration(s) located; the decider is the file:line of the declaring line | 0 |
| `GATED-UNKNOWN` | The only matching declaration(s) are gated-unknown (KV05/KV17); blocker cited | 1 |
| `NOT-FOUND` | No declaration in the loaded tree | 1 |
| `NOT-A-VIP` | Matches only a `static_ipaddress` entry (KV16) | 1 |
| `AMBIGUOUS` | Duplicate instance names, same VIP on ≥2 instances, or duplicate virtual_server IP:port (KV13); all candidates cited | 1 |
| `UNKNOWN` | Poisoned by an unparseable line in the queried declaration (KV21), a `~SEQ`/`~LST` line that could generate the answer (KV07), a `${_RANDOM}` line (KV06), or an unfollowed `@`-prefixed/`$`-pattern include (KV04); blocker cited | 1 |

Every run also prints findings, an unmodeled inventory (scripts,
`~SEQ`/`~LST` lines, `${_RANDOM}` lines, static addresses), and a
coverage section (files read with byte/line counts and include
expansions with their variant and effective `include_check`
level, instances and VIPs defined, gated lines, script counts,
unparseable lines).

## Pinned semantics (KV01–KV24, see DESIGN-keepalivedwho.md)

- **KV01** Verdict scope is declaration provenance, never
  election: mastership is never adjudicated
  ([mastership-not-adjudicated] on every instance answer).
- **KV02** Include chain: in-place expansion at the directive
  point, relative includes resolved against the including file's
  directory, glob matches in byte-wise sorted order, csh-style
  brace expansion implemented here (Python's `glob` does not
  expand braces), include cycles fatal (exit 2).
- **KV03** Include variants and the `include_check` level stack:
  plain `include` silently tolerates a missing file (warning);
  `includea` / an active `include_check` makes the same miss a
  config error (fatal, exit 2). The level is positional and
  stack-scoped: saved on file entry, restored on exit.
- **KV04** Include detection runs before `@`-conditional and `$`
  substitution processing: an `@`-prefixed include line or an
  include pattern containing `$` is not followed (finding, and
  UNKNOWN if the unfollowed subtree could hold the answer).
- **KV05** `@config-id` conditionals are three-valued: without
  `--config-id` a `@`-gated line is [gated-unknown]. The tool
  does not default to the local hostname.
- **KV06** `$PARAM` substitution is modeled positionally and
  recursively; `${_PWD}` / `${_INSTANCE}` / `${_HASH}` /
  `${_BANG}` are pre-defined; `${_RANDOM}` is [random-unknown];
  an undefined `$PARAM` is left as-is. A bare `$PARAM` is
  replaced only when followed by whitespace (or end of line);
  `${PARAM}` need not be.
- **KV07** `~SEQ`/`~LST` lines are unmodeled, never expanded:
  [seq-unknown], inventoried, UNKNOWN-poisoning for queries
  they could generate.
- **KV09** `vrrp_instance` context fields (state, interface,
  VRID, priority, advert_int, nopreempt, …) are reported, never
  verdicted.
- **KV10** VIP matching ignores the mask; `virtual_ipaddress_excluded`
  entries still count as VIPs ([excluded-from-adverts]).
- **KV11** `virtual_server`: `IP[:port]` / `fwmark` / `group`
  forms; a port-less (persistent) VS matches a port-qualified
  query on address equality alone, with a finding
  [docs-inferred].
- **KV12** `virtual_server_group` ranges are tested by
  membership arithmetic, never enumeration.
- **KV13** Duplicates are flagged, never first-wins: duplicate
  instance names, same VIP on two instances, duplicate VS
  IP:port, duplicate group names are AMBIGUOUS.
- **KV14** Sync groups and tracking are context, never verdicts.
- **KV15** Scripts are inventoried, never executed.
- **KV16** `static_ipaddress` entries are NOT VIPs: a query
  matching only one is NOT-A-VIP.
- **KV17** Three-valued gating propagation (Kleene core for
  declarations): an ungated declaration decides; a gated
  declaration degrades the verdict exactly when it could change
  the answer.
- **KV18** Exact verdict vocabulary (see table above).
- **KV19** Inventory modes `--list-instances` / `--list-vips` /
  `--list-servers`.
- **KV20** Coverage on every run.
- **KV21** Unparseable lines poison the selected answer only;
  unparseable lines outside the queried declaration are
  warnings. One broken instance must not blind the tool to the
  other forty.
- **KV22** Priority/state/preempt are context; the "why didn't
  it take it" shape ends with [mastership-not-adjudicated].
- **KV23** Empty instances are FOUND with zero VIPs.
- **KV24** Include variants are 2.2-era and later; `auth_hmac`
  keys are inventoried as present, never with values.

## Limitations

- **KV01** — mastership / election is never adjudicated: who is
  MASTER now needs the peer's file, the peer's runtime state,
  and the adverts actually seen. The tool reports the local
  numbers and states explicitly what the file cannot answer.
- **KV05** — without `--config-id`, every `@`-gated line is
  [gated-unknown]. That is deliberate (the daemon's hostname
  default would be the wrong node for an off-node run), but it
  means a shared HA-pair config answers GATED-UNKNOWN for gated
  declarations until you pass `--config-id`.
- **KV07** — `~SEQ`/`~LST` lines are not expanded. A query whose
  answer could lie in generated lines is UNKNOWN, naming the
  generating line. One `~SEQ` line can generate 65,024
  instances; expansion is a v2 question, not a silent v1
  behavior.
- **KV10** — the VIP mask is ignored for matching (it describes
  the subnet the address is added with, not a different
  address). A query carrying a mask matches on address equality.
- **KV22** — track weights are reported as configured numbers
  only, never applied to the priority: whether a track script is
  currently succeeding is runtime state.
- `include_check` lines inside a gated block, and `@`-gated
  `include_check` lines without `--config-id`, leave the level
  unchanged with a finding; the level for later includes is
  then uncertain rather than wrong. This is a known v1 edge.
- Unbalanced braces are a finding with best-effort extraction,
  not a fatal error (the tool is not a validator; see below).
- Runtime state can diverge from the files; every verdict is
  on-disk policy.
- `keepalivedwho` is **not a validator**: `keepalived -t`
  remains the validation path. Real keepalived refuses to start
  on any config error; keepalivedwho degrades — broken blocks
  it was not asked about are warning findings, dangling
  references are findings, and only defects that can change
  *this query's* answer poison the verdict to UNKNOWN. One
  broken instance must not blind the tool to the other forty.
  The one exception is load failure: a missing include under an
  active check level (KV03) or an include cycle (KV02) is fatal
  (exit 2), because the daemon would not load the config at all
  and there is no tree to answer over.

## Out of scope

- **Mastership / election** — who is MASTER now, on this node
  or the peer: needs peer files + runtime state (KV01/KV22).
- **Health checking** — checker outcomes, quorum transitions,
  real-server up/down: runtime state (KV11/KV15).
- **Script outcomes** — track_script results, notify delivery:
  scripts never executed (KV15).
- **Generated configurations** — `~SEQ`/`~LST` expansion (KV07);
  `${_RANDOM}` values (KV06).
- **BFD / garp groups / linkbeat** — `bfd` instances,
  `garp_group`, `linkbeat_interfaces`: inventoried, not modeled.
- **Runtime state** — what the *running* daemon has in memory
  (loaded-vs-disk honesty banner): a reload can change the
  effective config, and `keepalived -d` is the dump of the live
  one; every verdict is labeled on-disk policy.
- **Static addresses/routes/rules as VIPs** — answered as
  NOT-A-VIP, never as owned VIPs (KV16).

## Tests

86 tests (stdlib unittest, `python3 test_keepalivedwho.py`):
core provenance, the include chain and check-level stack,
conditionals, substitution, VIP matching, duplicates,
scripts/context/negatives, honesty, safety. No keepalived binary
exists on the build box, so there is no live-agreement test —
fixture trees are the only oracle, exactly as the manual text is
the only authority.

## Pre-publish checklist

- [x] Tests green (86/86)
- [x] Dogfood: clicheck 15/15, doccover 9/9 clean
- [x] Bench-audit map extended (A1–A7 clean)
- [x] README + CHANGELOG + LICENSE (MIT) in place
- [x] CI workflow (.github/workflows/tests.yml)
- [x] Prepublish-check clean

## License

MIT — LICENSE file added at the prepublish step.
