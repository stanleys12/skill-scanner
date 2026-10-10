#!/bin/zsh
# Build the upload-ready Agensi zip into dist/skill-scanner.zip.
# SKILL.md at the root, everything the scanner needs, nothing else. Well under 50 MB.
set -eu
ROOT=${0:A:h:h}
cd "$ROOT"
mkdir -p dist
OUT="dist/skill-scanner.zip"
rm -f "$OUT"

# Sanity: SKILL.md must exist and have frontmatter before we ship it.
head -1 SKILL.md | grep -q '^---$' || { print "SKILL.md is missing YAML frontmatter"; exit 1; }

zip -rq "$OUT" \
  SKILL.md README.md LICENSE skilljail.yaml \
  scanner scripts tests \
  -x '*/__pycache__/*' -x '*.pyc' -x '*.DS_Store' -x 'dist/*'

SIZE=$(( $(stat -f%z "$OUT") / 1024 ))
print "built: $OUT  (${SIZE} KB)"
unzip -l "$OUT" | awk 'NR>3 && $4!="" {print "  "$4}' | head -30
print "  ..."
print "root SKILL.md present: $(unzip -l "$OUT" | grep -q ' SKILL.md$' && print yes || print NO)"
