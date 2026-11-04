"""Thèmes visuels : « atelier » (habillage libre du profil) et « tenable » (charte graphique Tenable).

Le thème est un réglage de l'application (config.json, section « interface »). Il s'applique à l'interface,
aux rapports PDF et au plan d'action Excel. En thème Tenable :
- police Aeonik (Light pour les grands titres, Regular pour le texte, Medium pour les titres, Semibold au plus) ;
- Soft Black et gris neutres à la place de la couleur d'accent du profil ; coins droits, aucune ombre, aucun dégradé ;
- un seul emploi du Hilighter par composition : la bande de surlignage derrière un mot du titre de couverture
  (le texte reste en Soft Black, le Hilighter n'est jamais une couleur de texte) ;
- les couleurs de sévérité des graphiques restent des couleurs de données.
"""
import os

from . import config as CFG

THEMES = ("atelier", "tenable")
SOFT_BLACK = "#1E2426"
FULL_BLACK = "#192124"
HILIGHTER = "#E7FF00"
GRIS_050, GRIS_200, GRIS_300, GRIS_400, GRIS_700 = "#F2F2F2", "#D9D9D9", "#CCCCCC", "#969696", "#5B6062"
COUVERTURES = ("claire", "sombre")

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGO_RATIO = 1339 / 347                       # logo Tenable (iris + « tenable »), recadré sur son contenu


AEONIK = ("Light", "Regular", "Medium", "SemiBold")


def aeonik_disponible():
    """Aeonik est une police commerciale, non fournie avec le projet : déposez Aeonik-Light/Regular/Medium/SemiBold.ttf
    dans polices/ pour l'utiliser en thème Tenable. Sans ces fichiers, le thème Tenable retombe sur Inter."""
    return all(os.path.isfile(os.path.join(RACINE, "polices", f"Aeonik-{w}.ttf")) for w in AEONIK)


def logo_tenable(sombre=False):
    """Logo Tenable en PNG : blanc pour un fond sombre, Soft Black pour un fond clair."""
    return os.path.join(RACINE, "polices", "tenable-logo-%s.png" % ("blanc" if sombre else "noir"))


def theme_actif():
    t = CFG.lire(avec_env=False, traduire=False).get("interface", {}).get("theme")
    return t if t in THEMES else "atelier"


def definir_theme(theme):
    if theme not in THEMES:
        raise ValueError(theme)
    CFG.ecrire({"interface": {"theme": theme}})


def appliquer(habillage, theme=None):
    """Habillage prêt pour le moteur : porte le thème ; en thème Tenable la couleur du profil est remplacée par la charte."""
    h = dict(habillage or {})
    t = theme if theme in THEMES else theme_actif()
    h["theme"] = t
    if t == "tenable":
        h["couleur"] = SOFT_BLACK
        if h.get("couverture") not in COUVERTURES:
            h["couverture"] = "claire"
    return h
