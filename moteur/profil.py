"""Format portable d'un profil : stockage de la source par produit, export et import d'un profil autonome.

Sur disque, la source d'un profil est rangée par produit (un profil copié sur un autre poste ne traîne pas de réglages d'un
autre outil) :  {"produit": "sc", "securitycenter": {…}, "vulnmanagement": {…}}.  En mémoire et dans l'API, elle reste « à plat »
({"produit", "repositories", "cidr", …}) : les profils écrits avant ce format sont lus tels quels et réécrits au nouveau format.

Un profil exporté est un seul fichier JSON : le logo y est embarqué (base64) et aucun secret n'y figure (les clés d'API et
le mot de passe SMTP restent dans config.json, propre au poste).
"""
import base64
import json

from . import securitycenter as SC
from . import vulnmanagement as VMC

FORMAT = "tenable-report-workshop-profil"
VERSION = 2
CLES_SC = tuple(SC.SOURCE_DEFAUT)
CLES_VM = tuple(VMC.SOURCE_DEFAUT)
TAILLE_MAX = 3_000_000                          # octets : un profil exporté reste petit (le logo est son seul gros élément)
EXTENSIONS_LOGO = {"png": ".png", "jpg": ".jpg", "jpeg": ".jpg"}


def depuis_disque(source):
    """Source stockée (ancien format à plat ou format par produit) -> source à plat."""
    s = source if isinstance(source, dict) else {}
    if "securitycenter" not in s and "vulnmanagement" not in s:
        return dict(s)
    plat = {k: v for k, v in s.items() if k not in ("securitycenter", "vulnmanagement")}
    for bloc in ("securitycenter", "vulnmanagement"):
        if isinstance(s.get(bloc), dict):
            plat.update(s[bloc])
    return plat


def vers_disque(plat):
    """Source à plat -> source rangée par produit."""
    plat = plat or {}
    return {"produit": plat.get("produit", "sc"),
            "securitycenter": {k: plat[k] for k in CLES_SC if k in plat},
            "vulnmanagement": {k: plat[k] for k in CLES_VM if k in plat}}


def exporter(profil, logo_octets=None, logo_ext=None):
    """Profil (tel que lu par l'application) -> dictionnaire du fichier d'export."""
    h = {k: v for k, v in profil["habillage"].items() if k != "logo"}
    if logo_octets and logo_ext:
        h["logo"] = {"extension": logo_ext.lstrip(".").lower(), "donnees": base64.b64encode(logo_octets).decode("ascii")}
    return {"format": FORMAT, "version": VERSION, "nom": profil.get("nom"), "langue": profil.get("langue"),
            "habillage": h, "perimetre": profil["perimetre"], "modele": profil.get("modele"),
            "source": vers_disque(profil["source"]), "mail": profil["mail"], "smtp": profil.get("smtp") or {}}


class ImportInvalide(ValueError):
    pass


def lire_import(texte):
    """Texte d'un fichier d'export -> (dict d'import avec source à plat, logo (octets, extension) ou None).

    Lève ImportInvalide (message en français, à traduire par l'appelant) si le fichier n'est pas un profil exporté."""
    if len(texte) > TAILLE_MAX:
        raise ImportInvalide("trop_gros")
    try:
        d = json.loads(texte)
    except ValueError:
        raise ImportInvalide("illisible")
    if not isinstance(d, dict) or d.get("format") != FORMAT:
        raise ImportInvalide("format")
    if not isinstance(d.get("version"), int) or d["version"] > VERSION:
        raise ImportInvalide("version")
    logo = None
    h = dict(d.get("habillage") or {}) if isinstance(d.get("habillage"), dict) else {}
    brut = h.pop("logo", None)
    if isinstance(brut, dict) and brut.get("donnees"):
        ext = EXTENSIONS_LOGO.get(str(brut.get("extension") or "").lower())
        try:
            octets = base64.b64decode(brut["donnees"], validate=True)
        except (ValueError, TypeError):
            raise ImportInvalide("logo")
        if not ext:
            raise ImportInvalide("logo")
        logo = (octets, ext)
    out = {"nom": d.get("nom"), "langue": d.get("langue"), "habillage": h, "modele": d.get("modele"),
           "perimetre": d.get("perimetre") if isinstance(d.get("perimetre"), dict) else {},
           "source": depuis_disque(d.get("source")), "mail": d.get("mail") if isinstance(d.get("mail"), dict) else {},
           "smtp": d.get("smtp") if isinstance(d.get("smtp"), dict) else {}}
    return out, logo
