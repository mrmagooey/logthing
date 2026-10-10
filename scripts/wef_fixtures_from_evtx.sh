#!/usr/bin/env bash
# Regenerate tests/fixtures/wef/events/*.xml from public EVTX samples.
#
# Usage: scripts/wef_fixtures_from_evtx.sh        (needs network, curl, python3,
#                                                  and `cargo install evtx --locked`)
# Source: omerbenamram/evtx samples (Apache-2.0), pinned by commit SHA below. The OTRF
# Security-Datasets repo (MIT) ships JSON zips, not EVTX, so it contributes nothing.
# Never use EVTX-ATTACK-SAMPLES (GPL-3). Takes the first record per (file, channel, id),
# strips the <?xml?> banner and "Record N" line, and writes <channel>_<id>.xml.
# Idempotent: re-running rewrites identical files. synth_* / rendered_* are derived below.
set -euo pipefail

SHA=7479d02dfaa3bdeb41c5ea87195e84116a032cfc
BASE=https://raw.githubusercontent.com/omerbenamram/evtx/$SHA/samples
OUT="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/wef/events"
DUMP=${EVTX_DUMP:-$(command -v evtx_dump || echo "$HOME/.cargo/bin/evtx_dump")}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

# file | EventID | Channel | output name
WANTED="
security_big_sample.evtx|4624|Security|security_4624
Security_short_selected.evtx|4625|Security|security_4625
security_big_sample.evtx|4688|Security|security_4688
security_big_sample.evtx|4768|Security|security_4768
security_big_sample.evtx|4769|Security|security_4769
security_big_sample.evtx|4672|Security|security_4672
sysmon.evtx|1|Microsoft-Windows-Sysmon/Operational|sysmon_1
sysmon.evtx|3|Microsoft-Windows-Sysmon/Operational|sysmon_3
system.evtx|7045|System|system_7045
"
# PowerShell 4104: no permitted source has it; see PROVENANCE.md.

for f in $(echo "$WANTED" | cut -d'|' -f1 | sort -u); do
    curl -sfL -o "$TMP/$f" "$BASE/$f"
    "$DUMP" -o xml "$TMP/$f" > "$TMP/$f.xml" 2>/dev/null
done

echo "$WANTED" | while IFS='|' read -r file id chan name; do
    [ -n "$file" ] || continue
    python3 - "$TMP/$file.xml" "$id" "$chan" "$OUT/$name.xml" <<'PY'
import re, sys
src, eid, chan, out = sys.argv[1:]
text = open(src, encoding="utf-8").read()
for m in re.finditer(r"<Event xmlns=.*?</Event>", text, re.S):
    ev = m.group(0)
    if (re.search(r"<EventID[^>]*>%s</EventID>" % eid, ev)
            and "<Channel>%s</Channel>" % chan in ev):
        open(out, "w", encoding="utf-8").write(ev + "\n")
        break
else:
    sys.exit("no record for %s/%s" % (chan, eid))
PY
done

# Synthetic derivatives (labelled in PROVENANCE.md).
python3 - "$OUT" <<'PY'
import sys
d = sys.argv[1]
s = open(d + "/security_4624.xml", encoding="utf-8").read()
i = s.index("<Data Name=")
j = s.index(">", i) + 1
open(d + "/synth_illegal_char.xml", "w", encoding="utf-8").write(s[:j] + "\x04" + s[j:])
r = open(d + "/system_7045.xml", encoding="utf-8").read().rstrip("\n")
ri = ("<RenderingInfo Culture=\"en-US\"><Message>A service was installed in the system."
      "</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode>"
      "<Channel>System</Channel><Provider>Service Control Manager</Provider>"
      "<Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo>")
open(d + "/rendered_7045.xml", "w", encoding="utf-8").write(
    r.replace("</Event>", ri + "</Event>") + "\n")
PY
