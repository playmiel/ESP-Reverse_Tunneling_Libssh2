#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[lint-lang] Scanning repository for French language remnants..."

EXIT=0

# Files to scan (source, headers, markdown, configs)
INCLUDE_EXT=".(cpp|h|hpp|c|ino|md|txt|conf|ini|yml|yaml|py|sh)$"

# 1. Accented characters (likely French) (exclude this script itself)
if grep -RIn --exclude-dir=".git" --exclude="scripts/check_no_french.sh" -E "[àÀâÂäÄéÉèÈêÊëËîÎïÏôÔöÖùÙûÛüÜçÇœŒ]" . >/tmp/french_accents.txt 2>/dev/null; then
  echo "[lint-lang][ERROR] Accented characters found (potential French):"
  cat /tmp/french_accents.txt
  EXIT=1
fi

# 2. Common French words (boundary matched, case-insensitive) (exclude this script itself)
FRENCH_WORDS="(bonjour|serveur|connexion|vérification|échec|réseau|clé|clés|empreinte|sécurité|attente|initialisation|configuration|tentatives?)"
if grep -RIn --exclude-dir=".git" --exclude="scripts/check_no_french.sh" -E "\b${FRENCH_WORDS}\b" . >/tmp/french_words.txt 2>/dev/null; then
  echo "[lint-lang][ERROR] French words detected:"
  cat /tmp/french_words.txt
  EXIT=1
fi

# 3. Optional: skip CHANGELOG or LICENSE if present

if [ $EXIT -ne 0 ]; then
  echo "[lint-lang] Failure: French content detected. Please translate to English."
else
  echo "[lint-lang] Success: No French language remnants detected."
fi

exit $EXIT