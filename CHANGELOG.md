# CHANGELOG — keepalivedwho

## 1.0.0 (2026-11-09)

Initial release. Static model of keepalived's documented
configuration rules (keepalived.conf(5) current + Debian
bullseye, keepalived(8) Arch 2025-03-29, glob(3P) POSIX): which
include file:line declared this `vrrp_instance` /
`virtual_server` / VIP, and is it gated by a config-id
conditional.

KV01 verdict scope is declaration provenance, never election
([mastership-not-adjudicated] on every instance answer); KV02
include chain (in-place expansion, relative resolution against
the including file's directory, byte-wise sorted glob, csh-style
brace expansion incl. nested + empty alternatives, cycle fatal);
KV03 include variants and the include_check level stack (plain
`include` tolerates a missing file as a warning,
`includea`/active `include_check` makes the same miss fatal;
level positional and stack-scoped with save/restore across file
boundaries); KV04 include detection before @/$ processing
(`@`-prefixed and `$`-pattern includes not followed, UNKNOWN if
the unfollowed subtree could hold the answer); KV05 @config-id
conditionals three-valued ([gated-unknown] without --config-id,
deliberate divergence from the daemon's hostname default, no
hostname fallback); KV06 $PARAM substitution modeled
positionally and recursively, with ${_PWD}/${_INSTANCE}/
${_HASH}/${_BANG} pre-defined, ${_RANDOM} [random-unknown],
undefined params left as-is, bare $PARAM replaced only when
followed by whitespace; KV07 ~SEQ/~LST unmodeled, never
expanded, [seq-unknown] with kind-scoped UNKNOWN-poisoning;
KV09 vrrp_instance context fields; KV10 VIP matching ignores the
mask, virtual_ipaddress_excluded entries count as VIPs
([excluded-from-adverts]); KV11 virtual_server IP[:port]/fwmark/
group forms, port-less persistent VS matches port-qualified
queries with a finding; KV12 virtual_server_group ranges by
membership arithmetic, never enumeration; KV13 duplicates
flagged, never first-wins (AMBIGUOUS); KV14 sync groups and
tracking as context; KV15 scripts inventoried, never executed;
KV16 static_ipaddress entries are NOT VIPs; KV17 three-valued
gating propagation (Kleene core); KV18 exact verdict vocabulary
FOUND / GATED-UNKNOWN / NOT-FOUND / NOT-A-VIP / AMBIGUOUS /
UNKNOWN; KV19 --list-instances / --list-vips / --list-servers;
KV20 coverage on every run; KV21 unparseable lines poison the
selected answer only (scoped by declaration kind); KV22
priority/state/preempt as context; KV23 empty instances FOUND
with zero VIPs; KV24 include variants are 2.2-era and later,
auth_hmac keys inventoried as present, never with values. Exit
0/1/2; --json/--quiet/--version; read-only, no subprocess, no
network, no environment reads (test-asserted).

Claims are [documented]/[docs-inferred]/[hypothesized] only — no
keepalived binary on the build box, so there is no live-agreement
test; 86 hermetic fixture-tree tests, all green.

Build corrections during v1: escape decoding in quoted strings
rewritten (the first tokenizer appended the escaped char
literally instead of decoding `\n`/`\xXX`/`\cC`); a `url { }`
subblock inside HTTP_GET was flagged unparseable (checker bodies
now skip nested blocks cleanly); the VIP decider cited the entry
line instead of the instance header; scoped unparseable lines
initially did not block a FOUND verdict (KV21 scoping now
checked before FOUND, with global blockers — unfollowed
includes, ~SEQ lines, ${_RANDOM} lines — absorbed with a
finding when an ungated declaration already decides, per
KV17's Kleene core); a gated-unknown `$PARAM` used in a context
line (e.g. `priority $PRIORITY`) no longer manufactures a
gated-unknown instance candidate (the field is simply unknown);
`${_RANDOM}` in a VIP address is a [random-unknown] blocker,
not an unparseable line; the strict man-page rule that a bare
`$PARAM` is replaced only when followed by whitespace is pinned
by test (`$A/24` is left literal).
