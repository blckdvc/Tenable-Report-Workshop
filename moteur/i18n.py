"""Internationalisation : langue de l'interface et des rapports (français, anglais, espagnol, italien).

Les textes du code sont écrits en français ; la fonction `tr()` les traduit à partir des catalogues
`moteur/langues/*.json` (clé = texte français, tel qu'il est écrit dans le code). Un texte absent d'un catalogue
reste en français. Les variables s'écrivent {nom} dans le texte et se passent en arguments nommés :

    tr("{n} machines concernées", n=12)

Les noms de nombres (pluriel) passent par `plur()`, les dates par `date_longue()` et `mois()`.
La langue courante est propre à chaque fil d'exécution (une requête web = un fil).
"""
import datetime
import glob
import json
import os
import threading

DEFAUT = "fr"
# code, nom dans sa langue, code régional, nom du fichier de règles de remédiation
LANGUES = [
    {"code": "fr", "nom": "Français", "locale": "fr-FR"},
    {"code": "en", "nom": "English", "locale": "en-GB"},
    {"code": "es", "nom": "Español", "locale": "es-ES"},
    {"code": "it", "nom": "Italiano", "locale": "it-IT"},
]
CODES = [l["code"] for l in LANGUES]
RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOSSIER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "langues")

MOIS = {
    "fr": ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
    "es": ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
    "it": ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"],
}

_ctx = threading.local()
_catalogues = {}


def _charger():
    """Fusionne tous les fichiers moteur/langues/*.json : {"en": {...}, "es": {...}, "it": {...}}."""
    cat = {c: {} for c in CODES if c != DEFAUT}
    for chemin in sorted(glob.glob(os.path.join(DOSSIER, "*.json"))):
        with open(chemin, encoding="utf-8") as f:
            data = json.load(f)
        for code, textes in data.items():
            if code in cat:
                cat[code].update(textes)
    return cat


def recharger():
    _catalogues.clear()
    _catalogues.update(_charger())


def valide(code):
    return code if code in CODES else DEFAUT


def langue():
    return getattr(_ctx, "code", DEFAUT)


def set_langue(code):
    _ctx.code = valide(code)
    return _ctx.code


def tr(texte, **kw):
    """Traduit `texte` (français) dans la langue courante, puis remplace les {variables}."""
    if not _catalogues:
        recharger()
    t = texte if langue() == DEFAUT else _catalogues.get(langue(), {}).get(texte, texte)
    return t.format(**kw) if kw else t


def plur(n, mot, mots=None):
    """« 1 machine », « 3 machines » dans la langue courante.

    `mot` est le singulier français ; `mots` son pluriel français (par défaut mot + « s »). Les autres langues
    lisent le catalogue : clé = `mot`, valeur = « singulier|pluriel ». En français, 0 et 1 sont au singulier."""
    if not _catalogues:
        recharger()
    if langue() == DEFAUT:
        return f"{n} {mot if n <= 1 else (mots or mot + 's')}"
    val = _catalogues.get(langue(), {}).get(mot)
    if not val or "|" not in val:
        return f"{n} {mot if n <= 1 else (mots or mot + 's')}"
    un, plusieurs = val.split("|", 1)
    return f"{n} {un if n == 1 else plusieurs}"


def mois(i):
    """Nom du mois i (1 à 12) dans la langue courante."""
    return MOIS[langue()][i - 1]


def date_longue(d=None):
    """« 21 octobre 2026 » / « 21 October 2026 » / « 21 de octubre de 2026 » / « 21 ottobre 2026 »."""
    d = d or datetime.date.today()
    if langue() == "es":
        return f"{d.day} de {mois(d.month)} de {d.year}"
    return f"{d.day}{'er' if d.day == 1 and langue() == 'fr' else ''} {mois(d.month)} {d.year}"

