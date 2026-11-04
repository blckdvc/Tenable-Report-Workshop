"""Définitions des scores Tenable affichés dans les rapports : VPR (vulnérabilité), ACR et AES (machine), CES (ensemble de machines).

Les textes sont écrits en français et traduits à l'affichage (pas à l'import) : SCORES se lit comme avant
(`sc["definition"]`, `sc["niveaux"]`…) mais chaque champ est rendu dans la langue courante. Pour la source,
utiliser `source()`."""
from .i18n import tr, langue


def _ctx(prefixe, mot):
    """Traduction d'un mot dont la forme dépend du contexte (clé « prefixe:mot ») ; repli sur la clé générale."""
    if langue() == "fr":
        return mot
    t = tr(prefixe + ":" + mot)
    return tr(mot) if t == prefixe + ":" + mot else t


class _Score(dict):
    """Définition d'un score dont les champs textuels sont traduits à la lecture."""
    _SIMPLES = ("echelle", "definition")

    def __getitem__(self, k):
        v = super().__getitem__(k)
        if k in self._SIMPLES:
            return tr(v)
        if k == "cible":
            return _ctx("cible", v)
        if k == "niveaux":
            return [(_ctx("niveau", n), tr(x)) for n, x in v]
        return v

    def get(self, k, defaut=None):
        return self[k] if k in self else defaut


SCORES = [_Score(**d) for d in [
    dict(sigle="VPR", nom="Vulnerability Priority Rating", echelle="0,1 à 10,0", cible="vulnérabilité",
         definition=("Note dynamique qui estime la probabilité qu'une vulnérabilité soit exploitée prochainement. Elle complète le CVSS, "
                     "qui mesure la gravité théorique, en tenant compte de la menace réelle : maturité des codes d'exploitation, "
                     "probabilité d'exploitation, présence dans le catalogue CISA KEV. Elle est recalculée chaque jour par Tenable et ne "
                     "peut pas être modifiée. Les vulnérabilités sans CVE n'ont en général pas de VPR."),
         niveaux=[("Critique", "9,0 à 10,0"), ("Élevé", "7,0 à 8,9"), ("Moyen", "4,0 à 6,9"), ("Faible", "0,1 à 3,9")]),
    dict(sigle="ACR", nom="Asset Criticality Rating", echelle="1 à 10", cible="machine",
         definition=("Note de criticité d'une machine pour l'activité : plus elle est élevée, plus l'impact d'une compromission est important. "
                     "Elle est déduite du type d'équipement (hyperviseur, imprimante…), de son rôle (serveur de fichiers, de messagerie…, "
                     "parfois inféré des logiciels installés) et de son exposition à Internet. Recalculée toutes les 24 heures ; une valeur "
                     "saisie manuellement dans Tenable est prioritaire. Un scan non authentifié peut donner une estimation incomplète."),
         niveaux=[("Critique", "9 à 10"), ("Élevé", "7 à 8"), ("Moyen", "4 à 6"), ("Faible", "1 à 3")]),
    dict(sigle="AES", nom="Asset Exposure Score", echelle="0 à 1 000", cible="machine",
         definition=("Note d'exposition d'une machine au risque : plus elle est élevée, plus la machine est exposée. Elle combine la "
                     "criticité de la machine (ACR, d'origine ou saisie manuellement) et le VPR des vulnérabilités qui l'affectent."),
         niveaux=[("Élevé", "650 à 1 000"), ("Moyen", "350 à 649"), ("Faible", "0 à 349")]),
    dict(sigle="CES", nom="Cyber Exposure Score", echelle="0 à 1 000", cible="ensemble de machines",
         definition=("Note d'exposition globale d'un ensemble de machines (l'organisation ou un périmètre). Tenable la déduit des AES des "
                     "machines, sur la même échelle de 0 à 1 000 et avec les mêmes niveaux. Dans ce rapport, le CES du périmètre est estimé "
                     "par la moyenne des AES des machines analysées (une machine, une voix)."),
         niveaux=[("Élevé", "650 à 1 000"), ("Moyen", "350 à 649"), ("Faible", "0 à 349")]),
]]
SOURCE = "Source : documentation Tenable (Security Center, CVSS vs. VPR)."   # texte français : afficher via source()


def source():
    return tr(SOURCE)


def fmt(v):
    """Score affiché en entier ; tiret si la valeur est absente."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return "—"
    return "—" if v != v else f"{v:.0f}"


def niveau_acr(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return ""
    return "" if v != v else _ctx("niveau", "Critique" if v >= 9 else "Élevé" if v >= 7 else "Moyen" if v >= 4 else "Faible")


def niveau_aes(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return ""
    return "" if v != v else _ctx("niveau", "Élevé" if v >= 650 else "Moyen" if v >= 350 else "Faible")


def _sev(v, seuils):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v != v:
        return None
    for seuil, sev in seuils:
        if v >= seuil:
            return sev
    return "Low"


def sev_acr(v):
    """Clé de sévérité (couleur) correspondant au niveau d'un ACR, ou None si la valeur est absente."""
    return _sev(v, [(9, "Critical"), (7, "High"), (4, "Medium")])


def sev_aes(v):
    return _sev(v, [(650, "High"), (350, "Medium")])
