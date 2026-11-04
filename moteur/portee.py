"""Périmètre choisi dans Security Center (listes d'actifs) ou Vulnerability Management (tags).

Dans la source d'un profil, la sélection est enregistrée en texte :
  - Security Center : `asset_list` (identifiants séparés par des virgules) et `asset_noms` (JSON {identifiant: nom}) ;
  - Vulnerability Management : `tags` (JSON {catégorie: [valeurs]}).
La « portée » est la même sélection, mise en forme pour être transportée avec un export puis affichée en couverture :
    {"produit": "sc" | "vm", "listes": ["DMZ", "Serveurs Paris"], "tags": {"Site": ["Paris"]}}

Règle de combinaison : OU entre les listes d'actifs d'une sélection, OU entre les valeurs d'une même catégorie de tags,
ET entre catégories de tags différentes (c'est la sémantique des filtres de l'export de Vulnerability Management).
"""
import json
import re

from .i18n import tr

MAX_LISTES, MAX_CATEGORIES, MAX_VALEURS = 50, 20, 100


def _json(texte, defaut):
    try:
        v = json.loads(texte) if isinstance(texte, str) and texte.strip() else texte
    except ValueError:
        return defaut
    return v if isinstance(v, type(defaut)) else defaut


def ids_listes(source):
    return [x for x in re.split(r"[,;\s]+", str((source or {}).get("asset_list") or "")) if x]


def tags_source(source):
    """{catégorie: [valeurs]} lu dans la source d'un profil ; vide si absent ou illisible."""
    brut = _json((source or {}).get("tags"), {})
    out = {}
    for cat, vals in brut.items():
        vals = [str(v) for v in (vals if isinstance(vals, list) else [vals]) if str(v).strip()]
        if str(cat).strip() and vals:
            out[str(cat).strip()] = vals
    return out


def portee(source):
    """Portée (voir l'en-tête) d'une source de profil, ou None quand rien n'est sélectionné."""
    source = source or {}
    if source.get("produit") == "vm":
        t = tags_source(source)
        return {"produit": "vm", "listes": [], "tags": t} if t else None
    ids = ids_listes(source)
    if not ids or str(source.get("query_id") or "").strip():           # une requête enregistrée remplace les filtres
        return None
    noms = _json(source.get("asset_noms"), {})
    return {"produit": "sc", "listes": [str(noms.get(i) or f"#{i}") for i in ids], "tags": {}}


def depuis_selection(sel):
    """Sélection envoyée par l'interface ({listes: [{id, nom}], tags: {…}}) -> champs de source à fusionner. Valide les formes."""
    sel = sel if isinstance(sel, dict) else {}
    listes = sel.get("listes") or []
    tags = sel.get("tags") or {}
    if not isinstance(listes, list) or not isinstance(tags, dict) or len(listes) > MAX_LISTES or len(tags) > MAX_CATEGORIES:
        raise ValueError("selection")
    ids, noms = [], {}
    for x in listes:
        i = str(x.get("id") if isinstance(x, dict) else x).strip()
        if not re.fullmatch(r"[0-9]+", i):
            raise ValueError("selection")
        ids.append(i)
        noms[i] = str(x.get("nom") or "")[:120] if isinstance(x, dict) else ""
    propre = {}
    for cat, vals in tags.items():
        vals = [str(v).strip()[:200] for v in (vals if isinstance(vals, list) else [vals]) if str(v).strip()]
        if str(cat).strip() and vals:
            if len(vals) > MAX_VALEURS:
                raise ValueError("selection")
            propre[str(cat).strip()[:200]] = vals
    return {"asset_list": ", ".join(ids), "asset_noms": json.dumps(noms, ensure_ascii=False) if ids else "",
            "tags": json.dumps(propre, ensure_ascii=False) if propre else ""}


def libelle(p):
    """Texte de la couverture, dans la langue courante. Chaîne vide quand il n'y a pas de portée."""
    if not p:
        return ""
    if p.get("listes"):
        return tr("Listes d'actifs : {liste}", liste=", ".join(p["listes"]))
    if p.get("tags"):
        return tr("Tags : {liste}", liste=" ; ".join(f"{c} = {', '.join(v)}" for c, v in p["tags"].items()))
    return ""


COLONNE = "Scope"                     # colonne du CSV récupéré par l'API : la portée y est inscrite (JSON), pour la retrouver plus tard


def inscrire(chemin, p):
    """Ajoute la portée `p` au CSV `chemin` (colonne « Scope »), pour qu'elle suive le fichier : rechargé à la main, comparé
    plus tard ou utilisé en ligne de commande, le rapport affiche toujours le périmètre. Sans portée, rien n'est ajouté."""
    if not p:
        return
    import csv
    valeur = json.dumps(p, ensure_ascii=False)
    with open(chemin, encoding="utf-8-sig", newline="") as f:          # au niveau du texte : les valeurs restent intactes
        lignes = list(csv.reader(f))
    if not lignes or COLONNE in lignes[0]:
        return
    lignes = [lignes[0] + [COLONNE]] + [l + [valeur] for l in lignes[1:]]
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(lignes)


def lire(df):
    """Portée inscrite dans un export (colonne « Scope »), ou None."""
    if COLONNE not in df.columns:
        return None
    for v in df[COLONNE].dropna().astype(str):
        p = _json(v, {})
        if p.get("produit") in ("sc", "vm") and isinstance(p.get("listes", []), list) and isinstance(p.get("tags", {}), dict):
            return {"produit": p["produit"], "listes": [str(x) for x in p.get("listes") or []],
                    "tags": {str(c): [str(x) for x in (v if isinstance(v, list) else [v])] for c, v in (p.get("tags") or {}).items()}}
        break
    return None


def identique(a, b):
    def cle(p):
        p = p or {}
        return (sorted(p.get("listes") or []), sorted((c, sorted(v)) for c, v in (p.get("tags") or {}).items()))
    return cle(a) == cle(b)
