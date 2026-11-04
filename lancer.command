#!/bin/sh
# Lance l'Atelier de rapports (macOS et Linux). Première exécution : installe les bibliothèques.
cd "$(dirname "$0")" || exit 1
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3.9 ou plus récent est requis : https://www.python.org/downloads/"; exit 1; }
if [ ! -x .venv/bin/python ]; then
  echo "Première installation : création de l'environnement Python..."
  "$PY" -m venv .venv || exit 1
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt || { echo "Installation des bibliothèques impossible."; exit 1; }
fi
# Bibliothèques ajoutées depuis la dernière installation : mise à jour automatique quand requirements.txt change
STAMP=$(cksum < requirements.txt)
if [ "$(cat .venv/.requirements.stamp 2>/dev/null)" != "$STAMP" ]; then
  echo "Mise à jour des bibliothèques..."
  .venv/bin/python -m pip install --quiet -r requirements.txt || { echo "Installation des bibliothèques impossible."; exit 1; }
fi
echo "$STAMP" > .venv/.requirements.stamp
exec .venv/bin/python app.py "$@"
