# keepalivedwho — hazard-first design review

**Status:** BUILD APPROVED (2026-11-09).
**Question:** which include file:line declared this `vrrp_instance` /
`virtual_server` / VIP — and is it gated by a config-id conditional?
**Shape:** `keepalivedwho VIP|INSTANCE [--config-id ID] [--conf FILE]...`
over keepalived.conf plus its include chain. Flags (who-family
standard): `--json`, `--quiet`, `--version`, plus `--list-instances`,
`--list-vips`, and `--list-servers`.
**Pinned from:** keepalived.conf(5) as published at keepalived.org
(current, read 2026-11-09 — include + variants, `include_check`,
`@` conditionals, `$PARAM` substitution, `~SEQ`/`~LST`,
`vrrp_instance`, `vrrp_sync_group`, `virtual_server`,
`virtual_server_group`); keepalived.conf(5) Debian bullseye
(older, plain `include` only — used to bound the version range of
the include variants); keepalived(8) Arch, 2025-03-29
(`-f` default path, `-i/--config-id`, `-t/--config-test`,
`-d/--dump-conf`, `-e/--all-config`); glob(3P) POSIX (glob sorts
by default). Semantics pinned to the keepalived 2.2-era – 2.3.x
range; version-gated differences are called out where they appear.
No keepalived binary exists on this box (`keepalived` is not
installed) and no live experiments were run, so every claim below
is `[documented]` (man pages), `[docs-inferred]` (follows from a
documented rule), or `[hypothesized]` (best-supported guess,
flippable) — never `[observed]`. There is no live-agreement test
to skip-guard against: `keepalived -t` validates syntax but dumps
no per-declaration provenance (see Thinness verdict), so fixture
trees are the only oracle, exactly as the manual text is the only
authority. Claims are tagged throughout. A claim that turns out
wrong must flip the design, not get quietly absorbed.

## Thinness verdict: APPROVED, and no native holder answers the question

1. **`keepalived -t/--config-test` validates; it does not
   adjudicate.** A config check answers "does this parse and will
   it run" (exit 0/3/4/5), never "which file declared VIP
   10.0.0.5, and is that declaration gated on this node's
   config-id" [documented — keepalived(8): `-t` checks the
   configuration file and exits; exit 3 = cannot run, 4 =
   errors but will run after modifying, 5 = script security].
2. **`keepalived -d/--dump-conf` dumps the merged config, not
   provenance.** It prints the effective configuration data for
   *this* node's config-id — the include chain already flattened,
   the `@` conditionals already resolved, no file:line attached to
   any declaration [documented — keepalived(8): `-d` dumps the
   configuration data]. It cannot say which include file a VIP
   came from, cannot show the declarations that were gated *out*
   for this node, and cannot be run against a config that is not
   this node's. It is the nearest native holder and it answers a
   different question.
3. **grep cannot do include chains under three-valued gating.**
   The answer lives at the end of an include chain (KV02) behind
   a `@config-id` gate (KV05) that may be undecidable without
   `--config-id`; grep prints all the lines, resolves no globs,
   follows no relative paths, and adjudicates none of the gates —
   and it cannot see that plain `include` silently tolerates a
   missing file while `includea` makes the same miss a config
   error (KV03), which is exactly the distinction that decides
   whether a missing VIP file means "not declared" or "config
   broken".

If the build cannot reproduce KV05 (gated-unknown, never silently
included or dropped), KV11 (duplicate names/VIPs are AMBIGUOUS,
never first-wins), and KV02/KV03 (the include chain with its
check levels) against fixture trees, it does not ship — those
three are the tool's reason to exist.

## Pinned semantics

### Files and lines

- keepalived.conf is a hierarchy of blocks delimited by `{` and
  `}` pairs; keywords are placed in blocks and subblocks
  [documented]. Comments start with `#` or `!` to the end of the
  line and can start anywhere in a line [documented]. Quoted
  strings use `"` or `'` characters and are delimited by
  whitespace; `\a \b \E \f \n \r \t \v \nnn \xXX \cC` escapes are
  supported [documented]. v1's tokenizer must handle all three,
  or real-world notify scripts (`notify_master "/path/notify.sh
  'a b'"`) break.
- **KV08 — tokenizer:** braces may share a line with a keyword
  (`vrrp_instance VI_1 {`); `{`/`}` are tokens, and brace balance
  is tracked across the merged include stream (KV02). A block
  header is `KEYWORD args {` on one logical line. Keywords are
  matched case-sensitively as written in the man page (lowercase)
  [hypothesized — the manual never states keyword case rules; a
  differently-cased block keyword is an unparseable-line finding
  (KV21), not a silent miss, so being wrong here is loud, not
  wrong-answer quiet].

### KV01 — Verdict scope: declaration provenance, not election [design rule]

keepalivedwho answers *where a declaration lives and whether it
is gated*, never *who is MASTER now*. Mastership depends on peer
priorities, peer state, live VRRP adverts, and runtime track
results — none of which are in the file. Consequences:

- A VIP query returns the declaring instance(s), the file:line of
  each VIP entry, the instance's context (state, priority,
  `nopreempt`, interface, VRID — KV09/KV22), and the gating
  status (KV05/KV17). It never claims the querying node owns the
  VIP.
- An INSTANCE query returns the instance header's file:line, its
  VIPs (each with file:line), its sync-group membership, and its
  context — the map a human greps for today, with provenance.
- The "why did this node not take it" shape (KV22): the tool
  prints the local numbers and states explicitly what it cannot
  know (the peer's file, the peer's runtime state), rather than
  adjudicating the election.

### KV02 — Loading model: the include chain [documented + docs-inferred]

- `include FILENAME` — FILENAME may be fully qualified or
  relative, and may include wildcards, including csh-style brace
  expressions such as `"{foo/{,cat,dog},bar}"` if glob() supports
  them [documented]. Includes may appear from within the main
  file or from subsequently included files [documented], and at
  any nesting depth — inclusion is textual and in place at the
  point of the directive, and brace balance is tracked across the
  merged stream [docs-inferred — the man page describes inclusion
  as file inclusion at the directive point, with no depth or
  position restriction; the build pins in-place expansion with a
  fixture of an include inside a `global_defs` block and an
  include inside a `vrrp_instance` block].
- **Relative resolution:** "After opening an included file, the
  current directory is set to the directory of the file itself, so
  any relative paths included from a file are relative to the
  directory of the including file itself" [documented]. v1
  resolves every relative include against the including file's
  directory and says so in a finding whenever a relative include
  is followed (the AA10 lesson applied — the daemon's working
  directory is not the base).
- **Glob order:** glob() returns pathnames sorted by default
  [documented — glob(3P): "The pathnames shall be in sort order
  as defined by the current setting of the LC_COLLATE category";
  GLOB_NOSORT is what disables it]. v1 expands each include
  pattern to its matches in byte-wise sorted order (the C-locale
  reading) and banners the sort order in coverage — the load
  order is deterministic and stated, not inherited from the
  filesystem. **Brace expansion is the tool's own job:**
  Python's `glob` module does not expand `{a,b}`; v1 implements
  csh-style brace expansion itself (nested braces, empty
  alternatives such as `{,cat,dog}`) and then globs each
  alternative [design rule — the man page says braces work "if
  glob() supports them", i.e. the C library's glob; the build
  pins brace expansion with a fixture].
- **One filename per include line** [documented — the format is
  `include FILENAME`, singular]. A line with extra tokens after
  the filename is an unparseable-line finding (KV21).
- **Cycle detection:** an include cycle (A includes B includes A)
  → fatal finding, exit 2. The man page states no cycle rule;
  v1 treats a cycle as fatal rather than looping forever
  [design rule — the squidwho SQ19 lesson: a loader that cannot
  terminate cannot answer].
- `--conf` may be repeated; files are concatenated in the order
  given (a v1 convenience — keepalived itself takes one `-f`
  file; the tool banners the concatenation in coverage).
  Default discovery when `--conf` is absent:
  `/etc/keepalived/keepalived.conf` if it exists; else exit 2
  with the searched path named — never a silent guess at another
  tree [documented default path — keepalived(8)].

### KV03 — include variants and include_check levels [documented]

- The variants "add additional include checks to the current
  include_check level" [documented]:
  `includer` = `include_check readable`;
  `includem` = `include_check match`;
  `includew` = `include_check wildcard_match`;
  `includeb` = `include_check brace_match`;
  `includea` = all include_check checks.
- `include_check [OPTIONS]` (a `global_defs` keyword) — "Treat
  any missing include file as an error. The OPTIONS can be any
  combination of: `readable` — error if a match is not a readable
  file; `match` — error if no file matches (unless wildcard
  specified); `wildcard_match` — error if no file matches (even
  if wildcard specified); `brace_match` — error if a brace
  expansion does not match a file. Note: match, wildcard_match
  and brace_match include the readable check." [documented].
  `+opt` adds a check, `-opt` removes one (e.g. `include_check
  +match -wildcard_match`); no option = all options [documented].
- **The setting is positional and stack-scoped:** "The setting of
  include_check is saved when a new include file is opened, and
  restored when the file is closed. This means that the
  include_check setting when reading a file cannot be changed by
  a subsequently included file. To change the setting for all
  included files, include_check should be set at the beginning of
  the configuration file" [documented]. v1 tracks the current
  level as a stack pushed on file entry and popped on exit, and
  reports the effective level for each include in coverage.
- **Plain `include` tolerates missing files:** "The basic include
  keyword is retained for backward compatibility, since it does
  not produce config errors if files could not be opened etc."
  [documented]. v1: a plain `include` whose pattern matches
  nothing, or whose file is unreadable, is a **warning finding**
  and loading continues — the verdict stands over the files that
  did load. A variant/`include_check` failure (e.g. `includea`
  with no match, `includem` with a literal path that does not
  exist, `includew` with a wildcard that matches nothing) is a
  **config error: fatal finding, exit 2** — the real daemon would
  refuse the config, so a verdict over a half-loaded tree would
  be a manufactured answer. This asymmetry is the single most
  consequential loading rule in the file, and the build pins both
  branches with fixtures.
- **Musl caveat:** "If the libc glob() function does not support
  GLOB_ALTDIRFUNC (e.g. Musl libc as on Alpine Linux etc.), then
  only includea, includer and includew of the above options will
  work" [documented]. The tool does not know the target libc;
  the README notes the caveat and the tool treats all six
  variants as defined. A config that relies on `includem` /
  `includeb` on a musl host is a deployment question the tool
  cannot answer — named in coverage, not silently resolved.
- `keepalived -e/--all-config` ("Don't load if any configuration
  file is missing or cannot be read" [documented]) is a
  command-line override, not a config keyword; v1 does not model
  it (no `--strict` flag in v1 — an open question, KV-open).

### KV04 — Includes do not work with @ conditionals or $ substitution [documented]

"include handling will not work with if the include line uses
conditional configuration or parameter substitution, since the
detection of the include keywords is done before the processing
on conditional configuration and parameter substitution"
[documented]. Consequences, pinned as design rules:

- An include line with a leading `@` (`@main include
  vip-main.conf`) is **not followed**: the tool raises a finding
  naming the line, and the verdict is UNKNOWN if the unfollowed
  file could contain the answer (it might — the tool cannot know
  what is in a file it did not read). Whether the real daemon
  ignores the line, errors on it, or treats the remainder as a
  config line is not stated in the manual — [hypothesized] the
  tool's not-followed + UNKNOWN treatment; a live contradiction
  flips this rule, not the finding.
- An include pattern containing a `$PARAM` reference is likewise
  not followed (same finding class). A literal `$` in a filename
  that is not a defined parameter is left as-is by the daemon's
  substitution pass ("If a parameter is not defined, it will not
  be replaced at all" [documented]) — but the include detector
  runs before substitution, so the pattern is still not followed
  as an include; v1 treats any `$` in an include pattern as
  not-followed, finding raised.

### KV05 — @config-id conditionals and three-valued gating [documented + design rule]

- "The config-id defaults to the first part of the node name as
  returned by uname, and can be overridden with the -i or
  --config-id command line option" [documented; keepalived(8):
  "defaults to hostname without the domain name"]. "Any
  configuration line starting with '@' is a conditional
  configuration line. The word immediately following (i.e.
  without any space) the '@' character is compared against the
  config-id, and if they don't match, the configuration line is
  ignored. Alternatively, '@^' is a negative comparison, so if
  the word immediately following does NOT match the config-id,
  the configuration line IS included." [documented]. The
  conditional applies to **any** line, including block headers
  (`@main vrrp_instance VI_1 {` gates the whole instance) and
  lines inside list blocks (`@^main 1.2.3.4` inside
  `unicast_peer`) [documented — the man page's own example gates
  both `router_id` lines and `unicast_src_ip` / `unicast_peer`
  entries].
- **Three-valued gating (the ROADMAP hazard, confirmed):**
  without `--config-id`, a `@`-gated line is
  **[gated-unknown]** — never silently included, never silently
  dropped. With `--config-id ID`, `@ID` lines are included,
  `@^ID` lines are dropped, and every other `@`-gated line is
  dropped, all deterministically. A declaration whose only
  matching copy is gated-unknown yields verdict
  `GATED-UNKNOWN` (KV18) naming the gated line(s) as the
  blocker; a declaration with an ungated copy *and* a gated copy
  is FOUND on the ungated copy, with the gated copy listed as a
  gated duplicate (KV13's finding, not a second verdict).
- **Deliberate divergence from the daemon default (documented
  here, bannered on every run):** the daemon defaults config-id
  to the local hostname, but keepalivedwho does **not** default
  to its own hostname. The tool is almost always run off-node
  (a laptop debugging an HA pair), where the local hostname is
  the *wrong* node — silently using it would manufacture the
  exact wrong answer the tool exists to prevent. `--config-id`
  is the reproducible form; without it, gated content is
  [gated-unknown] and the output carries the
  `[config-id-not-given]` banner. This is the correct reading of
  the ROADMAP hazard: the daemon *has* a default, and the tool
  refuses it on purpose.
- A gated **block header** gates everything inside the block
  (KV17's propagation): a `@main vrrp_instance VI_1 {` line with
  no `--config-id` makes the instance and all its VIPs
  gated-unknown. A gated **line inside** a block gates only that
  line: `@backup priority 200` with `--config-id main` is
  dropped (the instance keeps its ungated `priority 100`, or
  has no priority line at all — reported as context-absent,
  never as a default the file does not state).

### KV06 — $PARAM substitution is modeled [documented]

- "Substitutable parameters can be specified. The format for
  defining a parameter is: $PARAMETER=VALUE where there must be
  no space before the '=' and only whitespace may preceed to
  '$'. Empty values are allowed. Parameter names can be made up
  of any combination of A-Za-z0-9 and _, but cannot start with a
  digit." [documented]. "After a parameter is defined, any
  occurrence of $PARAMETER followed by whitespace, or any
  occurrence of ${PARAMETER} (which need not be followed by
  whitespace) will be replaced by VALUE. Replacement is
  recursive… the substitution is done at replacement time and
  not at definition time" [documented]. Definitions are
  positional: a use before the definition is not replaced
  (the parameter is undefined at that point) [docs-inferred
  from the replacement-time rule and the examples, which define
  before use]. Multiline definitions (backslash-continued, with
  nothing after the parameter name on the first line) are
  supported and may be nested [documented].
- **Pre-defined parameters** [documented]: `${_PWD}` — the
  directory of the current configuration file (changes with
  includes); `${_INSTANCE}` — the instance name (the config-id);
  `${_RANDOM [MIN [MAX]]}` — a random integer; `${_HASH}` — a
  `#` character; `${_BANG}` — a `!` character.
- v1 models substitution because real templated configs depend on
  it (the man page's own conditional example is `@main
  $PRIORITY=240` + `priority $PRIORITY`): definitions are
  recorded positionally as the merged stream is read, and every
  later line is substituted before parsing, recursively, with
  `${_PWD}` resolved to the current file's directory and
  `${_INSTANCE}` to the `--config-id` value (or, with no
  `--config-id`, gated-unknown — KV05: an `${_INSTANCE}` in a
  VIP line without `--config-id` makes that line
  [gated-unknown]). `${_HASH}`/`${_BANG}` substitute to literal
  `#`/`!` (which do **not** start a comment — the substitution
  happens after comment stripping in the daemon's pipeline, and
  v1 substitutes before tokenizing but after comment detection
  on the raw line; the build pins this with a fixture).
  `${_RANDOM}` is **unmodeled**: a line containing it is
  [random-unknown] — its value is non-deterministic by design,
  and a VIP containing it cannot be matched. An undefined
  `$PARAM` is left as-is [documented]; a VIP line left containing
  a `$` reference is not a valid IP and becomes an
  unparseable-line finding (KV21).
- A `$PARAM` definition may itself be `@`-gated (`@main
  $PRIORITY=240`): the definition exists only under that
  config-id (KV05); without `--config-id` the definition is
  gated-unknown, and any line using it is gated-unknown too.

### KV07 — ~SEQ / ~LST blocks are unmodeled, never expanded [documented + design rule]

- "A line starting ~SEQ(var, start, step, end) will cause the
  remainder of the line to be processed multiple times" and
  "~LST(var, val1, val2, val3)" likewise; blocks can be nested
  and combined, and the man page's own example generates 65,024
  vrrp instances from one line [documented]. v1 does **not**
  expand `~SEQ`/`~LST` lines: any line they would generate is
  [seq-unknown], inventoried in coverage with the line's
  file:line, and a query whose answer could lie in generated
  lines is UNKNOWN naming the `~SEQ`/`~LST` line as the blocker.
  Expanding is arithmetic and tempting, but the expansion factor
  is unbounded by the file (65,024 instances from 3 lines) and
  the generated names are the thing being queried — a tool that
  expands them answers a different, enumerated question. The
  README names this as the v1 ceiling; expansion is a v2 open
  question, not a silent v1 behavior.

### KV09 — vrrp_instance: syntax and context fields [documented]

- `vrrp_instance <STRING> { … }` [documented]. The fields v1
  extracts as **context** (reported in an instance answer, never
  verdicts — KV01): `state MASTER|BACKUP`; `interface`;
  `virtual_router_id` (1–255, "used to differentiate multiple
  instances of vrrpd running on the same network interface");
  `priority` (1–255, 255 = "address owner"; "highest priority
  wins"; "All systems should have different priorities in order
  to make behaviour deterministic"); `advert_int`;
  `nopreempt` / `preempt` / `preempt_delay` ("A higher priority
  VRRP instance will normally preempt a lower priority instance
  when it comes online. nopreempt stops the higher priority
  machine taking over"); `accept` / `no_accept`; `unicast_src_ip`
  / `unicast_peer { … }` / `mcast_src_ip`; `use_vmac` /
  `use_ipvlan`; `version 2|3`; `authentication { auth_type
  PASS|AH; auth_pass … }` (first 8 chars used; "non-compliant…
  avoid using if possible") and the newer `auth_hmac { … }`
  (mutually exclusive with `authentication`).
- An instance with **no VIPs** is valid but warned about by the
  daemon ("keepalived warns if no VIPs are configured") unless
  `no_virtual_ipaddress` is set [documented]. v1: an instance
  query for such an instance is FOUND with zero VIPs and a
  finding naming `no_virtual_ipaddress` or its absence (KV23).
- `vrrp_instance` is "related to a unique interface" per the
  man page's overview ("Each VRRP Instance is related to a
  unique interface") — but the same interface may host several
  instances (different VRIDs) [docs-inferred from the VRID
  discussion]. v1 does not treat shared interfaces as an error.

### KV10 — VIP declaration syntax and matching [documented + design rule]

- `virtual_ipaddress { <IPADDR>[/<MASK>] [brd <IPADDR>] [dev
  <STRING>] [use_vmac] [scope <SCOPE>] [label <LABEL>] [peer
  <IPADDR>] [home] [-nodad] [mngtmpaddr] [noprefixroute]
  [autojoin] [no_track] [preferred_lft nn|forever] … }`
  [documented]. "addresses add|del on change to MASTER, to
  BACKUP" [documented]. The first token is the address; the rest
  are options (order-insensitive within the line; `dev`,
  `scope`, `label`, `peer`, `brd` take a value; the rest are
  flags) [docs-inferred from the option list — the man page
  lists options without stating order; the build pins
  order-insensitive parsing with a fixture].
- **Matching:** a query IP matches a VIP entry iff the address
  parts are equal as IP addresses (IPv4 and IPv6 both supported,
  `ipaddress` stdlib). The entry's `/MASK` is **ignored for
  matching** and shown as context (a query for `10.0.0.5`
  matches `10.0.0.5/24` and `10.0.0.5/32` alike — the mask
  describes the subnet the address is added with, not a
  different address). A query carrying a mask (`10.0.0.5/24`)
  matches on address equality and the mask is shown for
  comparison, never as a filter [design rule — the mask is not
  part of the VIP's identity; a tool that required mask equality
  would miss the declaration on a differently-masked query].
- **`virtual_ipaddress_excluded { … }` counts as a VIP.**
  "VRRP IP excluded from VRRP… The IPs are add|del as for
  virtual_ipaddress" [documented] — excluded addresses are
  still configured on the node when MASTER; they are only left
  out of the VRRP adverts (to decrease advert size with many
  IPs, or to mix IPv4 and IPv6 since "all addresses in
  virtual_ipaddress must be of the same family"). A VIP query
  matching an excluded entry is FOUND with the
  `[excluded-from-adverts]` flag and a finding: a peer will not
  see this address in adverts, which is exactly the kind of
  thing that makes "why did the peer not take it" confusing.
  The excluded block's option list omits `use_vmac` and
  `preferred_lft` [documented — the man page's excluded syntax
  lists neither]; v1 accepts the documented option set and
  treats an undocumented option there as an unparseable-line
  finding (KV21).
- An address line with extra unrecognized tokens, or a token
  that is not a valid IP address, is an unparseable-line finding
  (KV21) — it might be a VIP v1 cannot read, so it poisons a
  VIP query (UNKNOWN), never a silent skip.

### KV11 — virtual_server: three forms, port rules [documented + docs-inferred]

- "A virtual_server can be a declaration of one of
  `<IPADDR> [<PORT>]`, `fwmark <INTEGER>` or `group <STRING>`"
  [documented]. Inside: `lvs_sched`, `lvs_method`,
  `protocol TCP|UDP|SCTP`, `persistence_timeout`,
  `quorum`, `quorum_up`/`quorum_down` scripts,
  `real_server <IPADDR> [<PORT>] { weight …; <checker> { … } }`,
  `sorry_server <IPADDR> [<PORT>]` [documented].
- **Port:** "The port for the virtual server can only be omitted
  if the virtual service is persistent" [documented]. A
  port-less virtual_server matches a port-qualified query
  (`10.0.0.5:443`) on address equality alone, with a finding
  naming the omission [docs-inferred — the port-less form is
  the persistent-service form, which serves the address across
  ports; the build pins the match with a fixture and flags the
  inference as flippable]. A bare-IP query (`10.0.0.5`) matches
  a virtual_server on address equality regardless of its port,
  and the answer lists the port(s) declared.
- **fwmark virtual_servers have no IP:** a VIP query can never
  match them. They are answerable by the query form
  `keepalivedwho fwmark N` (KV18) and are listed by
  `--list-servers`. A `fwmark` virtual_server whose real servers
  are all tunnelled takes its address family from them
  [documented] — reported as context, not modeled further.
- `real_server` / `sorry_server` entries are inventoried with
  file:line (they are the answer's "what this VS serves"), with
  `weight` and checker types listed; checker bodies
  (`HTTP_GET`, `TCP_CHECK`, `MISC_CHECK`, …) are never
  evaluated and their scripts never executed (KV15).

### KV12 — virtual_server_group and ranges [documented]

- `virtual_server_group <STRING> { <IPADDR> [<PORT>] …;
  <IPADDR RANGE> [<PORT>] …; fwmark <INTEGER> [inet|inet6] … }`
  [documented]. Ranges take three forms (or IPv6 equivalents):
  `XXX.YYY.ZZZ.WWW-VVV` (e.g. `192.168.200.1-10`, inclusive),
  `AAA.BBB.CCC.DDD-EEE.FFF.GGG.HHH`, and `III.JJJ.KKK.LLL/nn`
  (CIDR, e.g. `192.168.202.8/29`) [documented].
- v1 expands ranges **by membership test, never by
  enumeration**: a query IP is tested against each range
  arithmetically (the /29 form can denote 8 addresses; a /16
  would denote 65,536 — enumeration would be a DoS on the tool
  itself). A matching group member yields a FOUND answer naming
  the group (file:line of the member line), the range as written,
  and every `virtual_server group <NAME>` that uses the group
  (each with file:line). A group with no virtual_server using it
  is reported as defined-but-unused, with a finding.
- "do not configure more than one TCP, one UDP and one SCTP
  virtual server with the same IP address family using the same
  virtual server group" [documented] — v1 reports a violation
  as a finding (two same-protocol virtual_servers sharing a
  group), not as an AMBIGUOUS verdict: the group membership is
  still unambiguous, the config is just suspect.

### KV13 — Duplicates: flagged, never first-wins [design rule + hypothesized daemon behavior]

- **Duplicate `vrrp_instance` names:** two instances with the
  same name in the loaded tree → every query for that name is
  `AMBIGUOUS` (KV18) with both header file:lines cited. The man
  page does not state what the daemon does with duplicate
  instance names [hypothesized — likely a startup error or a
  silent overwrite; unverified, no source read]; the tool does
  not guess — it reports both. **Never silently first-wins:**
  a tool that picked the first definition would answer the HA
  question with the wrong file half the time.
- **Same VIP on two instances:** a VIP declared in two different
  instances (same address, either `virtual_ipaddress` block) →
  a VIP query for it is `AMBIGUOUS` with both instance +
  file:line citations. (Within one node this is a misconfiguration
  — both instances would try to own the address; across the
  intended reading it is usually a copy-paste error, not a
  design.) A VIP declared twice in the *same* instance (same
  block or across `virtual_ipaddress` + `virtual_ipaddress_excluded`)
  is a duplicate-declaration finding on a FOUND answer, both
  lines cited — the instance is unambiguous, the repetition is
  not.
- **Duplicate `virtual_server` IP:port** (same IP and port, same
  protocol where stated) → AMBIGUOUS, both cited. A duplicate
  `virtual_server group` name → AMBIGUOUS for group queries.
- **Same VRID + interface + address family** on two instances:
  the man page warns that duplicating VRIDs "has been known to
  cause problems with some network switches" and that "in
  general it is important not to duplicate a virtual_router_id
  on the same network interface" (with unicast/multicast
  exceptions) [documented]. v1 reports it as a finding on any
  instance answer involving either instance — a warning, not
  an AMBIGUOUS verdict: the instances are distinct, the VRID
  collision is a deployment smell.

### KV14 — Sync groups and tracking are context, never verdicts [documented]

- `vrrp_sync_group <STRING> { group { <instance names> … };
  track_interface/track_script/track_file/track_process/
  track_bfd { … }; notify_* … }` [documented]: "define a bundle
  of VRRP instance to get synchronized together so that
  transition of one instance will be reflected to others".
  An instance answer lists its sync-group membership(s) with
  file:line. A `track_script`/`track_interface` weight "will add
  or subtract the weight to/from the priority" [documented] —
  but whether the script is currently succeeding is runtime
  state, so weights are reported as configured numbers only,
  never applied to the priority in an answer (KV22). A sync
  group naming an instance that is never defined is a dangling
  reference finding; the group is still listed.
- `track_interface`/`track_script`/`track_file`/`track_process`/
  `track_bfd` blocks inside a `vrrp_instance` are the same:
  inventoried (names + weights + file:line), never evaluated.

### KV15 — Scripts are inventoried, never executed [documented + family rule]

- Three script classes exist: "(a) Notify scripts… (b) vrrp
  tracking scripts… (c) LVS checker misc scripts" [documented],
  plus `startup_script`/`shutdown_script` in `global_defs` and
  `quorum_up`/`quorum_down` on virtual_servers. "By default the
  scripts will be executed by user keepalived_script if that
  user exists, or if not by root" [documented] — which is
  precisely why this tool never executes them. v1 records every
  script path it sees (`script` in `vrrp_script`, `notify*`,
  `quorum_up/down`, `misc_path`, `startup/shutdown_script`)
  with file:line in the unmodeled inventory, and never spawns a
  subprocess. Test-asserted: no subprocess invocation anywhere
  in the tool (family harness). A `vrrp_script` name referenced
  by a `track_script` block that is never defined is a dangling
  reference finding.

### KV16 — static_* addresses are NOT VIPs [documented]

- `static_ipaddress { … }` / `static_routes` / `static_rules`
  are "NOT moved by vrrpd, they stay on the machine"
  [documented]. A query IP matching only a `static_ipaddress`
  entry is a precise negative: verdict `NOT-A-VIP` (KV18) —
  "this address is statically configured on this node, not
  VRRP-managed; no instance owns it". The distinction matters
  because the operator's question ("who owns this VIP") has a
  different answer for a static address, and a bare NOT-FOUND
  would hide it. Static entries are listed in coverage.

### KV17 — Gating propagation (three-valued declarations) [design rule]

Every declaration carries a gate state: UNGATED, GATED-INCLUDED
(`@ID` matched, or `@^OTHER` not matched, under `--config-id`),
or GATED-UNKNOWN (no `--config-id`, or the gate depends on a
gated-unknown `$PARAM` definition — KV06). Propagation:

- A gated block header gates the whole block (KV05).
- A gated line inside a block gates only that line.
- A gated `$PARAM` definition (KV06) gates every line that uses
  the parameter.
- A gated `include` line is not followed at all (KV04) — the
  whole subtree is [include-gated-unknown], distinct from a
  followed file's gated lines.
- Combination for a query: if any UNGATED declaration matches →
  FOUND (gated matches listed alongside as gated duplicates).
  If only GATED-UNKNOWN declarations match → GATED-UNKNOWN,
  blocker cited. If only GATED-INCLUDED declarations match under
  a given `--config-id` → FOUND (the gate resolved). If no
  declaration matches and gated-unknown declarations exist
  *anywhere that could contain a match* (an unreadable gated
  subtree, a `~SEQ` line — KV07) → UNKNOWN, blocker cited;
  otherwise NOT-FOUND. This is the Kleene core, restated for
  declarations instead of rules: a gated-unknown declaration
  degrades the verdict exactly when it could change the answer,
  and is harmlessly absorbed (with a finding) when an ungated
  declaration already decides it.

### KV18 — Verdict vocabulary (exact)

- `FOUND` (exit 0): declaration(s) located; decider is the
  file:line of the declaring line (VIP entry, instance header,
  virtual_server header, group member line). For a VIP: the
  owning instance(s) or virtual_server(s) named with their
  headers' file:lines.
- `GATED-UNKNOWN` (exit 1): the only matching declaration(s)
  are gated-unknown (KV05/KV17); blocker cited (file:line of
  the gated declaration).
- `NOT-FOUND` (exit 1): no declaration in the loaded tree.
- `NOT-A-VIP` (exit 1): matches only a `static_ipaddress` entry
  (KV16).
- `AMBIGUOUS` (exit 1): duplicate instance names, same VIP on
  ≥2 instances, or duplicate virtual_server IP:port (KV13);
  all candidates cited.
- `UNKNOWN` (exit 1): poisoned by an unparseable line in the
  queried declaration (KV21), a `~SEQ`/`~LST` line that could
  generate the answer (KV07), a `${_RANDOM}` line (KV06), or
  an unfollowed `@`-prefixed/`$`-pattern include (KV04);
  blocker cited.
- There is no other output vocabulary for the verdict line;
  `--quiet` prints the verdict line only.

### KV19 — Inventory modes [design rule]

- `--list-instances`: every `vrrp_instance` and
  `vrrp_sync_group` in load order, with header file:line,
  interface, VRID, state, priority, VIP count, and gate state.
  Exit 0 with ≥1 item, exit 1 with none.
- `--list-vips`: every VIP (virtual_ipaddress +
  virtual_ipaddress_excluded) in load order, with address,
  mask, owning instance, file:line, excluded flag, gate state.
  Exit 0 with ≥1 item, exit 1 with none.
- `--list-servers`: every `virtual_server` and
  `virtual_server_group` in load order, with form (IP:port /
  fwmark / group), file:line, protocol, scheduler, quorum,
  real-server count, and group members (ranges as written).
  Exit 0 with ≥1 item, exit 1 with none.
- The inventory modes are the map a human greps for today, and
  the dogfood surface for the loader: if the loader cannot list
  it, it cannot answer it.

### KV20 — Coverage on every run [design rule]

Output always lists: files read (with byte/line counts, include
expansion noted per directive with its variant and effective
`include_check` level), instances defined (name, header
file:line), VIPs defined (count by instance, excluded count),
virtual_servers and groups (counts), gated lines (count, with
file:lines when `--config-id` is absent), `~SEQ`/`~LST` lines,
`${_RANDOM}` lines, script inventory (KV15 counts by class),
static addresses (KV16 count), and skipped/unparseable lines
with counts. A verdict over a partially read config is never
presented as complete.

### KV21 — Unparseable lines poison the selected answer [design rule]

A line that matches no known block/keyword shape, a VIP line
with an invalid IP, an `include` line with extra tokens, a
`virtual_router_id` outside 1–255, or a `priority` outside
1–255 → verdict UNKNOWN, citing file:line (an unrecognized line
could be a declaration v1 doesn't know). Recognized-but-
unevaluated keywords (the long tail: `global_defs` tuning knobs,
`garp_*` delays, `smtp_*`, `vrrp_mcast_group4/6`,
`lvs_sync_daemon`, BFD blocks, `linkbeat_interfaces`, checker
bodies, …) are parsed-or-skipped cleanly and never poison — the
recognizer must be generous (any keyword in the man page's
block vocabulary for that block type → skip the line), the
router strict. Unparseable lines outside the queried declaration
→ warning findings only. One broken instance must not blind the
tool to the other forty.

### KV22 — Priority/state/preempt are context: the "why didn't it take it" shape [documented + design rule]

- Election inputs in the file: `state` (initial state only —
  "If the priority is 255, then the instance will transition
  immediately to MASTER if state MASTER is specified; otherwise
  the instance will wait between 3 and 4 advert intervals"
  [documented]); `priority` ("highest priority wins");
  `nopreempt` ("stops the higher priority machine taking over
  the master role" — and "For this to work, the initial state
  must not be MASTER"); `preempt_delay`; track weights (KV14);
  `advert_int` (the master-down timer is "3 advert intervals
  plus a skew time" [documented]).
- The tool reports all of these as context on an instance answer
  and explicitly lists what the file cannot answer: the peer
  node's priority/state (different file, possibly different
  config-id gating), the live track results, and the adverts
  actually seen. The instance answer therefore ends with a
  `[mastership-not-adjudicated]` banner whenever the query is
  phrased as a why-didn't-it-take-it question (i.e. on every
  instance answer — the banner is unconditional, because the
  question is the tool's reason to exist and the temptation to
  over-answer is the hazard).

### KV23 — Empty instances and no_virtual_ipaddress [documented]

An instance with no VIPs is FOUND with zero VIPs. If
`no_virtual_ipaddress` is set, a finding notes the daemon's own
rule ("Specifying no_virtual_ipaddress supresses warnings for no
VIPs, and allows VRRPv3 to be used with no VIPs" [documented],
with the VRRPv3 protocol-violation warning quoted). If it is not
set, a finding notes the daemon warns about the empty instance.
Either way the verdict is FOUND — emptiness is a property of the
answer, not a failure to answer.

### KV24 — Version note: include variants are 2.2-era and later [docs-inferred + open]

The six include variants and `include_check` appear in the
bookworm-era man page (dated 2022-01-15, keepalived 2.2.x era)
and the current keepalived.org doc, and are absent from the
bullseye-era man page (plain `include` only). v1 recognizes all
six variants regardless of the target version — it does not know
the daemon version, and a variant keyword on an old daemon is a
config error the daemon would report, not a provenance question
the tool can answer. The README states the variants need
keepalived 2.2-era or later; the exact introducing release is an
open question (KV-open). Likewise `auth_hmac` is current-doc
only; v1 recognizes the block and reports its keys as context
(without values — secrets are never printed; a key line is
inventoried as `key <id> <present>`, never with its value).

## CLI, exits, and output contract

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
  and virtual_servers), an `IP:PORT` (virtual_server only),
  an instance/group name (instance search), or the two-token
  `fwmark N` (fwmark virtual_server). A name that matches both
  an instance and a virtual_server_group is answered for both,
  labeled by kind — never silently one of them.
- `--config-id ID` optional (KV05); `--conf` repeatable (KV02);
  default `/etc/keepalived/keepalived.conf`.
- `--list-instances` / `--list-vips` / `--list-servers`:
  inventory modes (KV19); exit 0 with ≥1 item listed, exit 1
  with none.
- Exit 0: verdict `FOUND` rendered, or an inventory mode with
  ≥1 item. Exit 1: `GATED-UNKNOWN`, `NOT-FOUND`, `NOT-A-VIP`,
  `AMBIGUOUS`, `UNKNOWN`, or an inventory mode with nothing
  listed. Exit 2: usage error, missing config, include cycle
  (KV02), include_check failure (KV03), or a malformed query
  (unparseable IP, bad `fwmark N`).
- Output order (text): verdict line; decider citation(s)
  (file:line of the declaring line, plus the owning instance /
  virtual_server header's file:line); the declaration context
  (interface, VRID, state, priority, nopreempt, sync-group
  membership, excluded flag, gate state); findings; unmodeled
  inventory (scripts KV15, `~SEQ`/`~LST` KV07, `${_RANDOM}`
  KV06, static addresses KV16); coverage (KV20).
  `--json` renders the same structure (verdict, decider,
  context, findings, coverage) machine-readably.
- Read-only by construction: opens config and include files for
  reading only, never executes keepalived, never runs a script,
  never opens a socket, never writes. Test-asserted: no
  subprocess invocation, no network, no writes, and no
  environment reads (the config-id is never taken from the
  environment — KV05).

## Out of scope (bannered, never silently modeled)

- **Mastership / election** — who is MASTER now, on this node or
  the peer: needs peer files + runtime state (KV01/KV22).
- **Health checking** — checker outcomes, quorum transitions,
  real-server up/down: runtime state (KV11/KV15).
- **Script outcomes** — track_script results, notify delivery:
  scripts never executed (KV15).
- **Generated configurations** — `~SEQ`/`~LST` expansion (KV07);
  `${_RANDOM}` values (KV06).
- **BFD / garp groups / linkbeat** — `bfd` instances,
  `garp_group`, `linkbeat_interfaces`: inventoried, not modeled.
- **Runtime state** — what the *running* daemon has in memory
  (loaded-vs-disk honesty banner, AA14's sibling): a reload can
  change the effective config, and `keepalived -d` is the dump
  of the live one; every verdict is labeled on-disk policy.
- **Static addresses/routes/rules as VIPs** — answered as
  NOT-A-VIP, never as owned VIPs (KV16).

## Not a validator (deliberate divergence, documented)

Real keepalived refuses to start on any config error (exit 3/4
under `-t`); keepalivedwho degrades: broken blocks it was not
asked about are warning findings (KV20/KV21), dangling
references are findings (KV14/KV15), and only defects that can
change *this query's* answer poison the verdict to UNKNOWN.
One broken instance must not blind the tool to the other forty.
The README must say this in one paragraph, and must say
`keepalived -t` remains the validation path. The one exception
is load failure: a missing include under an active check level
(KV03) or an include cycle (KV02) is fatal (exit 2), because
the daemon would not load the config at all and there is no
tree to answer over.

## Hazards reviewed (why this design is safe to build)

1. **The gated-unknown hazard is the catastrophic failure
   (KV05/KV17).** A config shared across an HA pair gates
   priorities, unicast addresses, and whole instances on
   config-id. A tool that silently included gated lines would
   answer "this node owns the VIP" from the *peer's* lines; a
   tool that silently dropped them would answer NOT-FOUND for a
   VIP this node does own. Both are worse than no tool. Hence
   [gated-unknown] without `--config-id`, never a hostname
   default, and GATED-UNKNOWN as a first-class verdict — and
   the divergence from the daemon's hostname default is
   documented, not hidden.
2. **Plain `include` vs `includea` is a silent-tolerance trap
   (KV03).** The same missing file is a warning under plain
   `include` and a config error under `includea` — and the
   level is positional and stack-scoped, so the *same* include
   line means different things depending on where
   `include_check` was set. A loader that treated all includes
   alike would either fatal on valid optional-file configs or
   silently answer over a broken strict config. The level stack
   is the fix, and the fixtures pin both branches plus the
   save/restore.
3. **Include detection runs before @/$ processing (KV04).**
   `@main include vip-main.conf` looks conditional and is not:
   the include detector never sees it as an include. A tool
   that followed it would load files the daemon never loads;
   a tool that ignored it silently would miss declarations.
   Hence: not followed, finding raised, UNKNOWN if the
   unfollowed subtree could hold the answer.
4. **Duplicates are the HA-pair failure mode (KV13).** Two
   instances with one name, or one VIP on two instances, is
   exactly the misconfiguration that makes an HA pair flap —
   and exactly the case where first-wins silently picks a file.
   AMBIGUOUS with all candidates cited is the only honest
   output; the daemon's own behavior on duplicate names is
   unverified and the tool does not guess it.
5. **Excluded VIPs are still VIPs (KV10).** An operator grepping
   `virtual_ipaddress` misses `virtual_ipaddress_excluded`
   entirely, and a peer never sees excluded addresses in
   adverts — the two facts together are the classic "the VIP
   is configured but the peer doesn't see it" mystery. The tool
   counts excluded entries and flags them.
6. **Generated lines explode (KV07).** One `~SEQ` line can
   generate 65,024 instances. A tool that expanded sequence
   blocks would hang or OOM on the man page's own example.
   [seq-unknown] with the generating line cited is the ceiling.
7. **Scripts are the execution hazard (KV15).** keepalived
   configs are full of executable paths run as root by default.
   A provenance tool that executed anything — a `vrrp_script`,
   a `notify_master`, a `MISC_CHECK` — would be a remote-code
   execution bug wearing a CLI. Pure text parsing, test-
   asserted no-subprocess, payloads in comments, script lines,
   and notify lines in the never-executes tests.
8. **The election is not in the file (KV01/KV22).** The tool's
   whole use case is "why did this node not take it", and the
   file alone cannot answer it — priority is only half the
   election. A tool that printed a mastership verdict from one
   file would be confidently wrong whenever the peer disagreed.
   Hence context + the unconditional
   `[mastership-not-adjudicated]` banner.

## Test plan (hermetic fixture configs; stdlib-only runner)

~55 tests, plain `python3` (no pytest — the aptpinswho lesson):

- **BG1 (core provenance, KV01/KV09/KV10/KV11/KV19):** VIP in
  the main file (FOUND, instance + file:line); VIP in an
  included file (file:line in the include); instance query
  lists VIPs with file:lines; virtual_server IP:port query;
  bare-IP query matching both a VRRP VIP and a virtual_server
  (both reported, labeled); group-member VIP via
  `virtual_server group`; `fwmark N` query; NOT-FOUND with
  exit 1; name matching both an instance and a group (both
  answered, labeled).
- **BG2 (include chain, KV02/KV03):** nested includes (3 deep);
  relative include resolved against the including file's
  directory (finding); glob sorted order (two files, order
  pinned in the answer's candidate listing); brace expansion
  incl. nested + empty alternative; plain `include` missing
  file → warning, verdict stands; `includea` no-match → fatal
  exit 2; `includem` literal missing → fatal; `includew`
  wildcard no-match → fatal; `includeb` brace no-match →
  fatal; `includer` unreadable → fatal; `include_check
  +match -wildcard_match` toggling; `include_check` save/restore
  across a file boundary (a level set inside an included file
  does not leak out); include cycle → fatal exit 2;
  multi-`--conf` concatenation order.
- **BG3 (conditionals, KV05/KV17):** `@main` line with
  `--config-id main` → FOUND; with `--config-id backup` →
  NOT-FOUND with a gated note; `@^main` negative both ways;
  no `--config-id` → GATED-UNKNOWN (exit 1, blocker cited);
  gated instance header gates all its VIPs; gated VIP line
  only (sibling VIP still FOUND); gated `$PRIORITY` definition
  (KV06) makes the using line gated-unknown; ungated copy +
  gated copy → FOUND with the gated duplicate listed.
- **BG4 (substitution, KV06/KV07):** `$PARAM` basic + `${PARAM}`;
  recursive substitution; definition-after-use not replaced
  (line left literal → unparseable finding); conditional
  definition `@main $PRIORITY=240` with matching/mismatching
  `--config-id`; `${_PWD}` in a script path (inventoried);
  `${_HASH}`/`${_BANG}` do not start comments;
  `${_RANDOM}` line → [random-unknown]; `~SEQ` line →
  [seq-unknown] + UNKNOWN for a query it could generate;
  `~LST` likewise; undefined `$PARAM` left literal.
- **BG5 (VIP matching, KV10/KV11/KV12):** mask ignored for
  match, shown as context; excluded VIP FOUND with
  `[excluded-from-adverts]`; same VIP in both blocks of one
  instance → FOUND + duplicate finding; IPv6 VIP; `dev`/`scope`/
  `label` options shown as context; virtual_server range
  membership (dash range, full range, CIDR /29 — by arithmetic,
  not enumeration); port-less persistent VS matches a
  port-qualified query with a finding; fwmark VS never matches
  a VIP query.
- **BG6 (duplicates, KV13):** duplicate instance names →
  AMBIGUOUS, both cited; same VIP on two instances →
  AMBIGUOUS; duplicate virtual_server IP:port → AMBIGUOUS;
  duplicate group name → AMBIGUOUS for group queries; same
  VRID + interface → warning finding, verdict stands.
- **BG7 (scripts/context/negatives, KV14/KV15/KV16/KV22/KV23):**
  track_script/notify/quorum_up scripts inventoried, never
  executed (marker-file test); sync-group membership shown on
  instance answers; dangling sync-group member → finding;
  priority/state/nopreempt shown as context with the
  `[mastership-not-adjudicated]` banner; static_ipaddress
  query → NOT-A-VIP; no_virtual_ipaddress instance → FOUND
  with zero VIPs + finding; instance with no VIPs and no
  `no_virtual_ipaddress` → FOUND + warning finding.
- **BG8 (honesty, KV18/KV20/KV21):** unparseable line in the
  queried instance → UNKNOWN, in an unrelated block → warning
  only; coverage completeness (every fixture asserts the
  coverage section names all files, instances, and VIPs);
  `--list-instances` / `--list-vips` / `--list-servers` output
  incl. gate states; `--json` fidelity vs text verdicts; exit
  codes 0/1/2 across the matrix.
- **BG9 (safety):** never-executes payloads in comments,
  `vrrp_script` script lines, `notify_*` lines, and
  `MISC_CHECK` misc_path lines; no-network/no-write assertion
  (family harness); auth_hmac key values never printed.

Dogfood: doccover + clicheck clean before the v1 commit, per
bench convention. README carries a Limitations section naming
KV01/KV05/KV07/KV10/KV22 and the Out-of-scope list explicitly,
plus a pre-publish checklist.

## Build order

1. Tokenizer + loader (comments/quotes/braces, KV02 include
   chain + KV03 check-level stack, KV04 non-interaction,
   KV05 @-gating, KV06 $PARAM substitution, KV21 recognizer).
2. Block model (vrrp_instance / vrrp_sync_group / vrrp_script /
   virtual_server / virtual_server_group) + VIP extraction
   (KV09–KV12) + duplicates (KV13).
3. Query engine (VIP/instance/fwmark, KV17 gating, KV18
   vocabulary) + renderers (text/JSON) + coverage (KV20) +
   inventory modes (KV19).
4. Dogfood: doccover + clicheck --strict; bench-audit map
   extension; prepublish-check clean; README + CHANGELOG.

## Open questions / flippable hypotheses

1. **Duplicate instance names — daemon behavior unverified.**
   The man page does not state it; no source was read. If the
   daemon errors at startup, AMBIGUOUS stays correct (the
   config is broken either way). If it silently overwrites,
   the tool's AMBIGUOUS is still the honest output for a
   provenance question — the design does not flip on this, but
   the README's claim about the daemon should be corrected if
   a source read shows otherwise.
2. **Glob sort locale.** v1 pins byte-wise sort and banners it;
   glibc glob() sorts by LC_COLLATE, which in a non-C locale
   can order differently (e.g. case-insensitively). If a live
   contradiction appears, the sort becomes locale-aware.
3. **Port-less persistent virtual_server matching any port**
   (KV11) is [docs-inferred] from "the port can only be omitted
   if the virtual service is persistent" — if a port-less VS in
   fact serves no port-qualified query, the finding flips to a
   non-match.
4. **@-prefixed include lines (KV04):** "will not work" is the
   man page's whole statement. If the daemon errors rather than
   ignores, the tool's UNKNOWN should become exit 2 (fatal).
   A source read or a live `-t` run settles it.
5. **Include variants' introducing release (KV24):** present in
   the 2022-01-15 (bookworm, 2.2.x-era) man page, absent from
   the bullseye-era page. The exact release (2.2.0? earlier?)
   is unconfirmed; the README's version note should be
   corrected if the changelog says otherwise.
6. **Keyword case-sensitivity (KV08)** is [hypothesized]; the
   manual never states it. A live contradiction flips the tag,
   not the unparseable-line treatment.
7. **`~SEQ`/`~LST` expansion (KV07):** v1 does not expand. If
   real configs use `~SEQ` pervasively for VIP generation, v2
   should expand bounded ranges (with a cap) rather than leave
   every generated VIP UNKNOWN — but the cap and the
   [seq-unknown] fallback stay.
8. **Exact `include_check` failure mode:** the man page says
   "treat as an error" without stating the exit path; v1 treats
   it as fatal (exit 2), mirroring the daemon refusing the
   config. If a live `-t` run shows a check failure is only a
   warning (exit 4's "will run after modifying" bucket), the
   exit code flips to 1-with-finding.

## Sources (read 2026-11-09)

- keepalived.conf(5), keepalived.org (current):
  https://www.keepalived.org/documentation/keepalived-conf/
  (include + variants, include_check, @ conditionals, $PARAM
  substitution, ~SEQ/~LST, vrrp_instance, vrrp_sync_group,
  vrrp_script, virtual_server, virtual_server_group,
  virtual_ipaddress_excluded, static_*; auth_hmac)
- keepalived.conf(5), Debian bullseye:
  https://manpages.debian.org/bullseye/keepalived/keepalived.conf.5.en.html
  (older text: plain include only; used to bound KV24)
- keepalived(8), Arch, 2025-03-29:
  https://man.archlinux.org/man/keepalived.8.en
  (-f default, -i/--config-id, -t/--config-test exits 0/3/4/5,
  -d/--dump-conf, -e/--all-config)
- glob(3P), POSIX:
  https://man.archlinux.org/man/glob.3p.txt
  (pathnames in sort order by default; GLOB_NOSORT disables)
