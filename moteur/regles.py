"""Regroupe les vulnérabilités d'un export Tenable Security Center en solutions (actions de remédiation).

Les règles sont lues dans regles/base.csv (regroupement) et regles/textes_<langue>.csv (textes), modifiables dans Excel. Pour chaque
vulnérabilité, la première règle dont le motif correspond au nom du plugin
(et, si elle est renseignée, à la famille Tenable) est retenue. Les vulnérabilités
qui partagent la même clé forment une seule solution.

Colonnes des règles (séparateur « ; » ; base.csv : id, cle, famille, motif ; textes : id, titre, action, commentaire) :
  cle         identifiant de la solution ; peut contenir {produit}, {kb}, {famille}…
  famille     expression régulière facultative sur la colonne « Family » de l'export
  motif       expression régulière sur le nom du plugin ; les groupes nommés
              (?P<produit>…), (?P<paquet>…), (?P<kb>…), (?P<avis>…)… alimentent les textes
  titre       titre de la solution
  action      texte de l'action à mener
  commentaire libre, ignoré par le script

Champs utilisables dans titre et action :
  {produit} {kb} {os} {ms} {famille}   valeur extraite du premier intitulé
  {paquets} {avis} {notes} {bulletins} {cves}   listes cumulées sur toutes les vulnérabilités
  {cible}      « en version X ou ultérieure », d'après les intitulés « Produit < X »
  {branches}   versions correctives des autres branches, si l'intitulé en cite plusieurs
  {mois}       mois de publication le plus récent, en français
  {precision}  « (version X ou ultérieure) » si l'intitulé cite une version, sinon vide
  {ref_avis}   « (avis : …) » si l'intitulé cite des identifiants d'avis éditeur, sinon vide
  {redemarrage}  phrase de redémarrage si le noyau est concerné
"""
import csv
import os
import re
import uuid
from collections import defaultdict

import pandas as pd

from .i18n import tr, plur, mois, langue, valide, RACINE, CODES
from . import vm as VM

SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
class _NomsSeverite(dict):
    """Noms de sévérité dans la langue courante : SEV_FR["High"] → « Élevée », « High », « Alta », « Alta »…"""
    def __getitem__(self, k):
        return tr(super().__getitem__(k))


SEV_FR = _NomsSeverite({"Critical": "Critique", "High": "Élevée", "Medium": "Moyenne", "Low": "Faible"})
WEIGHT = {"Critical": 40, "High": 10, "Medium": 3, "Low": 1}      # pondération Tenable SC
# Pondération par VPR : le VPR (0,1 à 10) pèse directement ; s'il manque, on prend le milieu de la plage de la sévérité
VPR_DEFAUT = {"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 2.0}
ACR_DEFAUT = 5.0     # criticité d'une machine sans ACR : valeur par défaut de Tenable
PONDERATIONS = {"severite": "weight", "vpr": "vprw", "vpr_acr": "vpracr"}
REQUIRED = ["Plugin", "Plugin Name", "Severity", "IP Address"]
# colonnes facultatives de l'export : criticité (ACR, 1 à 10) et exposition (AES, 0 à 1000) de la machine
ALIAS_SCORES = {"acr": "ACR", "acr score": "ACR", "acrscore": "ACR", "asset criticality rating": "ACR",
                "aes": "AES", "aes score": "AES", "assetexposurescore": "AES", "asset exposure score": "AES"}
COLONNES = ["cle", "famille", "motif", "titre", "action", "commentaire"]
COL_BASE = ["id", "cle", "famille", "motif"]               # regroupement : commun à toutes les langues
COL_TEXTES = ["id", "titre", "action", "commentaire"]      # textes : un fichier par langue


class ErreurDonnees(Exception):
    """Erreur de lecture ou de contenu d'un export, avec un message lisible par l'utilisateur."""
DEFAULT_RULES = None                                         # règles de la langue courante

MOIS_EN = ["January", "February", "March", "April", "May", "June", "July", "August",
           "September", "October", "November", "December"]
MOIS_FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
           "septembre", "octobre", "novembre", "décembre"]
AVIS = re.compile(r"\b(VMSA-\d{4}-\d{4}|cisco-sa-[\w-]+|FG-IR-\d{2}-\d+|JSA\d+|APSB\d{2}-\d+|SVD-\d{4}-\d{4}|K\d{6,9}|"
                  r"CTX\d+|SSA-\d{6}|SEVD-[\d-]+|SD\d{3,5}|HPESB\w+|ESA-\d{4}-\d+|SNWLID-[\d-]+|sk\d+|IJ\d+|"
                  r"CONFSERVER-\d+|JRASERVER-\d+|DSA-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3})\b")
LISTES = {"paquet": "paquets", "avis": "avis", "note": "notes", "bulletin": "bulletins", "cve": "cves"}


# ------------------------------------------------------------------ règles
def load_rules(path=None):
    """Règles compilées : celles de la langue courante, ou celles d'un fichier à 6 colonnes (test d'une saisie en cours)."""
    rules = []
    for i, row in enumerate(lire_regles_brutes(path), start=2):
        if not (row.get("motif") or "").strip():
            continue
        try:
            rules.append(dict(row, n=i, rx=re.compile(row["motif"]),
                              frx=re.compile(row["famille"]) if (row.get("famille") or "").strip() else None))
        except re.error as e:
            raise ErreurDonnees(tr("{fichier}, ligne {n} : expression régulière invalide ({err}).",
                                  fichier=os.path.basename(path or "regles/base.csv"), n=i, err=e))
    return rules


def match(rules, name, family):
    for rule in rules:
        if rule["frx"] is not None and not rule["frx"].search(family or ""):
            continue
        m = rule["rx"].search(name)
        if m:
            return rule, {k: v for k, v in m.groupdict().items() if v}
    return None, {}


# ------------------------------------------------------------------ outils texte / versions
# Jetons de version retirés à la fin d'un nom de produit : 9.0.0.M1, 11.x, 25H2, 7, « / »…
# Les nombres de 3 chiffres ou plus (365, 2016) font partie du nom et sont conservés.
_VER_TOKEN = re.compile(r"^(?:\d[\w\-]*\.[\w.\-]*,?|\d+\.?x,?|\d+H\d,?|\d{1,2},?|/|-|,|and|through|\(\S*\d\S*\))$", re.I)

_VULN_TAIL = re.compile(r"\s+(?:Multiple Vulnerabilities|Vulnerabilit(?:y|ies)|Remote Code Execution|RCE|Denial of Service|DoS|"
                        r"Privilege Escalation|Elevation of Privilege|Information Disclosure|Security Update|Security Updates)$", re.I)

def clean_product(p):
    p = re.sub(r"^Security Updates? for ", "", p.strip())
    p = _VULN_TAIL.sub("", p)
    toks = p.split()
    while len(toks) > 1 and _VER_TOKEN.match(toks[-1]):
        toks.pop()
    return " ".join(toks).strip(" ,/-")


def clean_package(p):
    p = re.sub(r"\(.*?\)", "", p)
    p = re.sub(r"\s*/\s*etc\.?$", "", p)
    return p.strip(" ,:-")


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


def fixed_versions(name):
    """Versions corrigées citées dans l'intitulé : « < X », « prior to X », « before X » ; « <= X » à part."""
    strict = re.findall(r"(?:(?<![<=])<(?!=)|\bprior to\b|\bbefore\b)\s*(?:Build\s+|V)?(\d[\w.\-]*)", name)
    le = re.findall(r"<=\s*(?:Build\s+|V)?(\d[\w.\-]*)", name)
    if not strict and not le:                     # « Vim 9.1.0764 (GHSA-…) » : la version citée est la version corrigée
        m = re.match(r"^[A-Za-z][^<(]*?\s+v?(\d+(?:\.\d+)+)\s+\((?:GHSA-|CVE-\d)", name)
        if m:
            strict = [m.group(1)]
    return [v.rstrip(".,") for v in strict], [v.rstrip(".,") for v in le]


def mois_fr(values):
    best = None
    for v in values:
        m = re.match(r"([A-Za-z]+)\s*(\d{4})", v)
        abbr = [x[:3] for x in MOIS_EN]
        if m and m.group(1)[:3].capitalize() in abbr:
            k = (int(m.group(2)), abbr.index(m.group(1)[:3].capitalize()))
            best = max(best, k) if best else k
    return f"{mois(best[1] + 1)} {best[0]}" if best else ""


def join_list(items, limit=25):
    items = sorted(set(i for i in items if i), key=str.lower)
    if len(items) > limit:
        return ", ".join(items[:limit]) + tr(" et {n} autres", n=len(items) - limit)
    return ", ".join(items)


class _Fields(dict):
    def __missing__(self, key):
        return ""


def formater(text, fields):
    """text.format_map(fields) sans jamais planter : un champ absent donne une chaîne vide, une syntaxe invalide est tolérée."""
    try:
        return text.format_map(fields)
    except (ValueError, IndexError, KeyError, AttributeError, TypeError):
        return re.sub(r"\{([^{}]*)\}", lambda m: str(fields.get(m.group(1), "")), text)


def render(text, fields):
    out = formater(text, fields)
    out = re.sub(r"\(\s*\)", "", out)            # parenthèses restées vides
    out = re.sub(r"\s+([.,])(?=\s|$)", r"\1", out)
    return re.sub(r"\s{2,}", " ", out).strip()


def fields_for(names, groups_list, family):
    f = _Fields()
    for g in groups_list:                         # valeurs « premier trouvé »
        for k, v in g.items():
            if k not in LISTES and k not in f:
                f[k] = v.strip()
    if "produit" in f:
        f["produit"] = clean_product(f["produit"])
    lists = defaultdict(list)
    for g in groups_list:
        for k, plural in LISTES.items():
            if k in g:
                lists[plural].append(clean_package(g[k]) if k == "paquet" else g[k])
    if not lists["avis"]:                         # identifiants d'avis repérés dans les intitulés
        lists["avis"] = [a for n in names for a in AVIS.findall(n)]
    for plural in LISTES.values():
        f[plural] = join_list(lists[plural], limit=6 if plural in ("avis", "cves", "bulletins", "notes") else 25)
    f["famille"] = re.sub(r"\s*Local Security Checks$", "", family or "").strip()
    pk = " ".join(lists["paquets"]).lower()
    f["redemarrage"] = tr(" Redémarrer ensuite pour charger le nouveau noyau.") if re.search(r"kernel|linux-image|\blinux\b", pk) else ""
    f["mois"] = mois_fr([g["mois"] for g in groups_list if "mois" in g])
    # version cible : la plus élevée citée ; branches : les autres versions du même intitulé
    best_name, best_v, le_best = None, None, None
    for n in names:
        strict, le = fixed_versions(n)
        for v in strict:
            if best_v is None or vkey(v) > vkey(best_v):
                best_v, best_name = v, n
        for v in le:
            if le_best is None or vkey(v) > vkey(le_best):
                le_best = v
    f["ref_avis"] = tr(" (avis : {avis})", avis=f["avis"]) if f.get("avis") else ""
    if best_v and re.search(r"<\s*Build\s+" + re.escape(best_v), best_name):
        f["cible"] = tr("en build {v} ou ultérieur", v=best_v)
        f["precision"] = tr(" (build {v} ou ultérieur)", v=best_v)
    elif best_v:
        f["cible"] = tr("en version {v} ou ultérieure", v=best_v)
        f["precision"] = tr(" (version {v} ou ultérieure)", v=best_v)
        others = sorted({v for v in fixed_versions(best_name)[0] if v != best_v}, key=vkey)
        if others:
            f["branches"] = tr(" À défaut, appliquer la version corrective de la branche installée : {versions} ou ultérieure.",
                               versions=", ".join(others))
    elif le_best:
        f["cible"] = tr("dans une version postérieure à {v}", v=le_best)
        f["precision"] = tr(" (version postérieure à {v})", v=le_best)
    else:
        f["cible"] = tr("dans sa dernière version")
    return f


# ------------------------------------------------------------------ chargement de l'export et regroupement
def read_export(path):
    df = None
    for enc in ("utf-8-sig", "latin-1"):
        try:
            df = pd.read_csv(path, low_memory=False, encoding=enc)
            break
        except UnicodeDecodeError:
            continue
        except Exception as e:
            raise ErreurDonnees(tr("Le fichier {fichier} n'est pas un fichier CSV lisible ({err}).", fichier=os.path.basename(path), err=e))
    if df is None or df.shape[1] < 2:
        raise ErreurDonnees(tr("Le fichier {fichier} ne semble pas être un export CSV de Tenable Security Center ou de Tenable Vulnerability Management.",
                               fichier=os.path.basename(path)))
    fmt = VM.format_vm(df)                                    # export de Tenable Vulnerability Management : converti en colonnes internes
    if fmt:
        df = VM.convertir(df, fmt)
    api_vm = "Source" in df.columns and df["Source"].astype(str).str.lower().eq("vm").any()   # CSV écrit par le client de l'API
    df.attrs["produit"] = "vm" if (fmt or api_vm) else "sc"
    from . import portee as PT
    df.attrs["portee"] = PT.lire(df)                          # périmètre inscrit par la récupération via l'API
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ErreurDonnees(tr("Colonnes absentes de l'export : {colonnes}. Exportez la vue « Vulnerability List » de Tenable Security Center, ou la liste des vulnérabilités de Tenable Vulnerability Management, au format CSV.",
                               colonnes=", ".join(missing)))
    for c in ("DNS Name", "NetBIOS Name", "Family"):
        if c not in df.columns:
            df[c] = None
    df = df.rename(columns={c: ALIAS_SCORES[c.strip().lower()] for c in df.columns
                            if c.strip().lower() in ALIAS_SCORES and ALIAS_SCORES[c.strip().lower()] not in df.columns})
    df["Plugin Name"] = df["Plugin Name"].fillna("").astype(str)          # une cellule vide ne doit pas faire échouer l'analyse
    if not (df["Plugin Name"].str.strip() != "").any():
        raise ErreurDonnees(tr("La colonne « Plugin Name » est vide dans cet export : les vulnérabilités ne peuvent pas être "
                               "regroupées. Si l'export vient de l'API, relancez la récupération avec la dernière version."))
    return df


def preparer(df):
    """Colonnes de travail communes : machine, nom, poids de sévérité (les constats Info sont retirés)."""
    df = df[df["Severity"].isin(WEIGHT)].copy()
    df["host"] = df["IP Address"].astype(str)
    df["dns"] = df["DNS Name"].fillna(df["NetBIOS Name"]).fillna("").astype(str)
    df["weight"] = df["Severity"].map(WEIGHT)
    vpr = pd.to_numeric(df["VPR"], errors="coerce") if "VPR" in df.columns else pd.Series(float("nan"), index=df.index)
    df["vpr_ok"] = vpr.notna()
    df["vprw"] = vpr.where(vpr.notna(), df["Severity"].map(VPR_DEFAUT))
    for c in ("ACR", "AES"):
        df[c] = pd.to_numeric(df[c], errors="coerce") if c in df.columns else float("nan")
    df["vpracr"] = df["vprw"] * df["ACR"].fillna(ACR_DEFAUT) / 10      # VPR du constat × criticité de la machine (ACR / 10)
    return df


def load(path, rules_path=None):
    return analyser(preparer(read_export(path)), load_rules(rules_path))


def analyser(df, rules, ponderation="severite"):
    """Regroupe en solutions un export déjà préparé (et éventuellement filtré).

    ponderation : « severite » (40/10/3/1), « vpr » (VPR de chaque vulnérabilité) ou « vpr_acr » (VPR × ACR/10) ; elle fixe le « % du risque » des solutions."""
    if df.empty:
        raise ErreurDonnees(tr("Aucune vulnérabilité dans le périmètre retenu : vérifiez les sévérités et les filtres de machines."))
    df = df.copy()

    # une règle par plugin
    plugins = df.drop_duplicates("Plugin")[["Plugin", "Plugin Name", "Family"]]
    assign, unmapped = {}, []
    for p in plugins.itertuples(index=False):
        rule, groups = match(rules, str(p[1]), "" if pd.isna(p[2]) else str(p[2]))
        if rule is None:
            unmapped.append(str(p[1]))
            assign[p[0]] = ("plugin:" + str(p[0]), None, {})
            continue
        key_fields = _Fields({k: v for k, v in groups.items()})
        if "produit" in key_fields:
            key_fields["produit"] = clean_product(key_fields["produit"]).lower()
        key_fields["famille"] = re.sub(r"\s*Local Security Checks$", "", "" if pd.isna(p[2]) else str(p[2]))
        assign[p[0]] = (formater(rule["cle"], key_fields), rule, groups)
    df["sol"] = df["Plugin"].map(lambda x: assign[x][0])

    occ = df.drop_duplicates(["host", "Plugin"])      # un couple machine / vulnérabilité
    total = occ["weight"].sum()                       # score de risque par sévérité (machines, comparaison)
    col = PONDERATIONS.get(ponderation, "weight")
    total_r = occ[col].sum()                          # base du « % du risque » des solutions
    has_sol = "Solution" in occ.columns
    sols = []
    for key, g in occ.groupby("sol"):
        names = sorted(g["Plugin Name"].astype(str).unique())
        plug = g.drop_duplicates("Plugin")
        matched = [assign[p] for p in plug["Plugin"]]
        family = next((x for x in plug["Family"] if isinstance(x, str)), "")
        if matched[0][1] is not None:
            # règles dans l'ordre du fichier ; une action par règle distincte
            used = sorted({id(m[1]): m[1] for m in matched}.values(), key=lambda r: r["n"])
            fields = fields_for(names, [m[2] for m in matched], family)
            title = render(used[0]["titre"], fields)
            action = " ".join(dict.fromkeys(render(r["action"], fields) for r in used))
        else:
            sol_txt = (g["Solution"].dropna().astype(str).iloc[0].strip()
                       if has_sol and g["Solution"].notna().any() else "")
            title = names[0]
            action = (tr("Solution indiquée par Tenable : {solution}", solution=sol_txt) if sol_txt
                      else tr("Appliquer le correctif de l'éditeur indiqué par Tenable (plugin {plugin}).", plugin=g["Plugin"].iloc[0]))
        hosts = (g.groupby("host").agg(dns=("dns", "first"), vulns=("Plugin", "nunique"),
                                       maxsev=("Severity", lambda s: max(s, key=SEV_ORDER.get)),
                                       weight=("weight", "sum"), acr=("ACR", "max"), aes=("AES", "max"))
                 .reset_index())
        # machines les plus exposées d'abord : AES décroissant s'il est connu, puis poids du risque
        hosts = (hosts.sort_values(["aes", "weight", "host"], ascending=[False, False, True], na_position="last")
                 if hosts["aes"].notna().any() else hosts.sort_values(["weight", "host"], ascending=[False, True]))
        sols.append(dict(key=key, title=title, action=action, names=names,
                         maxsev=max(g["Severity"], key=SEV_ORDER.get), weight=int(g["weight"].sum()), rw=float(g[col].sum()),
                         pct=100 * g[col].sum() / total_r, n_vulns=len(names), n_occ=len(g),
                         sev_counts=plug["Severity"].value_counts().to_dict(), hosts=hosts))
    sols.sort(key=lambda s: (-s["rw"], -s["weight"], -SEV_ORDER[s["maxsev"]], s["title"]))
    for i, s in enumerate(sols, 1):
        s["rank"] = i
    return df, occ, sols, total, sorted(unmapped)


def tester(name, family="", rules=None):
    """Règle appliquée à un intitulé, sous forme structurée (pour l'interface)."""
    rules = rules if rules is not None else load_rules()
    rule, groups = match(rules, name, family)
    if rule is None:
        return None
    f = fields_for([name], [groups], family)
    return {"ligne": rule["n"], "cle": rule["cle"], "titre": render(rule["titre"], f),
            "action": render(rule["action"], f), "groupes": groups}


# ------------------------------------------------------------------ stockage des règles
# regles/base.csv          id ; cle ; famille ; motif           regroupement, commun à toutes les langues
# regles/textes_<lang>.csv id ; titre ; action ; commentaire     textes de chaque langue
# Un texte absent dans la langue demandée est repris de l'anglais (langue de référence), puis du français.
DOSSIER_REGLES = os.path.join(RACINE, "regles")
REFERENCE = "en"


def chemin_base():
    return os.path.join(DOSSIER_REGLES, "base.csv")


def chemin_textes(code):
    return os.path.join(DOSSIER_REGLES, f"textes_{code}.csv")


def _lire_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as f:
        return [{k: (v or "") for k, v in row.items() if k} for row in csv.DictReader(f, delimiter=";")]


def _ecrire_csv(path, colonnes, lignes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        import shutil
        shutil.copyfile(path, path + ".bak")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colonnes, delimiter=";", quoting=csv.QUOTE_ALL)
        w.writeheader()
        for row in lignes:
            w.writerow({k: row.get(k, "") for k in colonnes})


def _attribuer_ids(lignes):
    """Identifiant stable de chaque règle : la clé si elle est unique, sinon clé~2, clé~3…"""
    vus = {}
    for r in lignes:
        n = vus[r["cle"]] = vus.get(r["cle"], 0) + 1
        r["id"] = r["cle"] if n == 1 else f"{r['cle']}~{n}"
    return lignes


def migrer_regles():
    """Première utilisation : convertit les anciens fichiers regles_<lang>.csv (6 colonnes, un par langue) en
    regles/base.csv + regles/textes_<lang>.csv. Les modifications déjà faites dans les anciens fichiers sont conservées ;
    les anciens fichiers sont renommés en .migre."""
    if os.path.exists(chemin_base()):
        return
    ancien = {c: os.path.join(RACINE, f"regles_{c}.csv") for c in CODES}
    ancien = {c: p for c, p in ancien.items() if os.path.exists(p)}
    if not ancien:
        raise ErreurDonnees(tr("Fichier de règles introuvable : {fichier}.", fichier="regles/base.csv"))
    maitre = "fr" if "fr" in ancien else next(iter(ancien))
    base = _attribuer_ids([{k: r.get(k, "") for k in ("cle", "famille", "motif")} for r in _lire_csv(ancien[maitre])])
    _ecrire_csv(chemin_base(), COL_BASE, base)
    for code, p in ancien.items():
        lignes = _lire_csv(p)
        index = {}
        for r in lignes:                                   # rapprochement par (clé, motif), puis par position
            index.setdefault((r.get("cle"), r.get("motif")), []).append(r)
        textes = []
        for pos, b in enumerate(base):
            cand = index.get((b["cle"], b["motif"]))
            r = cand.pop(0) if cand else (lignes[pos] if pos < len(lignes) and lignes[pos].get("cle") == b["cle"] else None)
            if r:
                textes.append({"id": b["id"], **{k: r.get(k, "") for k in ("titre", "action", "commentaire")}})
        _ecrire_csv(chemin_textes(code), COL_TEXTES, textes)
        os.replace(p, p + ".migre")


def _chaine(code):
    """Langues consultées, dans l'ordre, pour trouver le texte d'une règle."""
    ordre = [valide(code or langue()), REFERENCE, "fr"] + list(CODES)
    return list(dict.fromkeys(ordre))


def _textes(code):
    return {r["id"]: r for r in _lire_csv(chemin_textes(code)) if r.get("id")}


def lire_regles_brutes(path=None, code=None):
    """Règles de la langue (colonnes COLONNES, plus « id » et « repli » : langue d'où vient un texte non traduit).
    Avec path : lit un fichier à 6 colonnes (import ou test d'une saisie en cours)."""
    if path:
        return [{k: (r.get(k) or "") for k in COLONNES} for r in _lire_csv(path)]
    migrer_regles()
    chaine = _chaine(code)
    textes = {c: _textes(c) for c in chaine}
    out = []
    for b in _lire_csv(chemin_base()):
        row = {"id": b["id"], "cle": b["cle"], "famille": b["famille"], "motif": b["motif"],
               "titre": "", "action": "", "commentaire": "", "repli": ""}
        for c in chaine:
            t = textes[c].get(b["id"])
            if t and (t.get("titre") or "").strip():
                row.update({k: t.get(k, "") for k in ("titre", "action", "commentaire")})
                row["repli"] = "" if c == chaine[0] else c
                break
        out.append(row)
    return out


def ecrire_regles(lignes, path=None, code=None):
    """Valide puis enregistre les règles (une copie de sauvegarde .bak est conservée).
    Avec path : écrit un fichier à 6 colonnes (test). Sinon, le regroupement va dans regles/base.csv (commun à toutes
    les langues) et les textes dans regles/textes_<langue>.csv."""
    if not isinstance(lignes, list) or not lignes or not all(isinstance(r, dict) for r in lignes):
        raise ErreurDonnees(tr("Format invalide."))
    lignes = [{k: ("" if v is None else str(v)) for k, v in r.items()} for r in lignes]
    erreurs = []
    for i, row in enumerate(lignes, start=2):
        if not row.get("motif", "").strip():
            erreurs.append(tr("Ligne {n} : le motif est vide.", n=i))
            continue
        for champ in ("motif", "famille"):
            if row.get(champ, "").strip():
                try:
                    re.compile(row[champ])
                except re.error as e:
                    erreurs.append(tr("Ligne {n}, {champ} : expression régulière invalide ({err}).", n=i, champ=champ, err=e))
        if not row.get("titre", "").strip() or not row.get("cle", "").strip():
            erreurs.append(tr("Ligne {n} : la clé et le titre sont obligatoires.", n=i))
    if erreurs:
        raise ErreurDonnees(" ".join(erreurs[:5]))
    if path:
        _ecrire_csv(path, COLONNES, lignes)
        return
    migrer_regles()
    code = valide(code or langue())
    # rapproche les règles sans identifiant (ajout, import) d'une règle existante de même clé et même motif
    existantes = _lire_csv(chemin_base())
    deja = {r["id"] for r in lignes if r.get("id")}
    libres = {}
    for b in existantes:
        if b["id"] not in deja:
            libres.setdefault((b["cle"], b["motif"]), []).append(b["id"])
    utilises = set()
    base, textes = [], []
    ref = {c: _textes(c) for c in _chaine(code)[1:]}
    for r in lignes:
        rid = r.get("id") or ""
        if not rid or rid in utilises:
            cand = libres.get((r["cle"], r["motif"]))
            rid = cand.pop(0) if cand else f"{r['cle']}~{uuid.uuid4().hex[:6]}"
        utilises.add(rid)
        base.append({"id": rid, "cle": r["cle"], "famille": r.get("famille", ""), "motif": r["motif"]})
        propre = {k: r.get(k, "") for k in ("titre", "action", "commentaire")}
        repris = next((t[rid] for t in ref.values() if rid in t and (t[rid].get("titre") or "").strip()), None)
        if repris and all(propre[k] == repris.get(k, "") for k in propre) and (r.get("repli") or "") != "":
            continue                                       # texte inchangé, repris d'une autre langue : rien à écrire
        textes.append({"id": rid, **propre})
    _ecrire_csv(chemin_base(), COL_BASE, base)
    _ecrire_csv(chemin_textes(code), COL_TEXTES, textes)


def explain(name, family="", rules_path=None):
    """Affiche la règle appliquée à un intitulé : utile pour tester une nouvelle règle."""
    rules = load_rules(rules_path)
    rule, groups = match(rules, name, family)
    if rule is None:
        return tr("Aucune règle : {nom}", nom=name)
    f = fields_for([name], [groups], family)
    return (tr("Ligne {n} ({cle}) : {titre}", n=rule["n"], cle=rule["cle"], titre=render(rule["titre"], f))
            + f"\n    → {render(rule['action'], f)}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--tester":
        for n in sys.argv[2:]:
            print(explain(n))
    else:
        df, occ, sols, total, unmapped = load(sys.argv[1])
        print(tr("Sans règle :"), unmapped)
        for s in sols:
            print(f"{s['rank']:>2} {s['pct']:5.1f}% {s['maxsev']:<8} {s['n_vulns']:>3} {tr('vuln.')} {len(s['hosts']):>2} {tr('mach.')}  {s['title']}")
            print("     ", s["action"])
