"""Logiciels en fin de vie : CPE détectés par Tenable, rapprochés d'endoflife.date.

Extrait de tvm_eol_tagger.py : on ne garde que la lecture des CPE, leur rapprochement avec endoflife.date
et le classement par échéance. Tout ce qui posait des tags dans Tenable a été retiré.

Source unique des CPE, identique pour Security Center et Vulnerability Management : la sortie du plugin 45590
(Common Platform Enumeration). Elle n'existe que sur les machines analysées avec authentification (scan
authentifié ou agent) : c'est la limite à rappeler dans le rapport.

Trois étapes :
    1. collecter(client, vm, source, chemin, ...)  écrit un CSV « machine, CPE » (genre « cpe » dans l'application)
    2. AnalyseEol(chemin, ...)                      lit ce CSV et le rapproche d'endoflife.date (réseau)
    3. modeles/eol.py                               met en page le résultat
"""
import csv
import datetime as dt
import os
import re
import time

from . import portee as P
from .i18n import tr
from .regles import ErreurDonnees

try:
    import requests
except ImportError:                            # pragma: no cover
    requests = None

API_EOL = "https://endoflife.date/api/v1"
ID_PLUGIN_CPE = 45590
HORIZON_JOURS = 365                            # « sous 12 mois » ; le script d'origine prenait 180 jours
COLONNES_CSV = ["Machine", "IP Address", "CPE", "Source", "Scope"]


# --------------------------------------------------------------------------- CPE
CPE_RE = re.compile(r"cpe:(?:2\.3:|/)[aho]:[^\s,;'\"<>()]+", re.I)


def parse_cpe(cpe):
    """-> (part, éditeur, produit, version) ou None. Gère les formats 2.2 (cpe:/a:...) et 2.3."""
    cpe = cpe.strip().rstrip(".")
    if cpe.lower().startswith("cpe:2.3:"):
        f = re.split(r"(?<!\\):", cpe[8:])
    elif cpe.lower().startswith("cpe:/"):
        f = cpe[5:].split(":")
    else:
        return None
    if len(f) < 3:
        return None
    nettoyer = lambda s: s.replace("\\", "").lower()
    version = nettoyer(f[3]) if len(f) > 3 else ""
    if version in ("*", "-", ""):
        version = ""
    return f[0].lower(), nettoyer(f[1]), nettoyer(f[2]), version


def extraire_cpes(texte):
    return {m.group(0).rstrip(".,") for m in CPE_RE.finditer(texte or "")}


# --------------------------------------------------------------------------- endoflife.date
class Referentiel:
    """Client de l'API v1 d'endoflife.date : index des CPE connus, puis cycles de chaque produit (mis en cache)."""

    def __init__(self, session=None, ca_bundle=None, verifier_tls=True):
        if session is None:
            if requests is None:
                raise ErreurDonnees(tr("La bibliothèque « requests » manque : exécutez "
                                       "« .venv/bin/python -m pip install -r requirements.txt » (Windows : .venv\\Scripts\\python.exe), puis relancez."))
            session = requests.Session()
            session.headers["User-Agent"] = "atelier-rapports-tenable/1.0"
            if not verifier_tls:
                session.verify = False
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                except Exception:
                    pass
            elif ca_bundle:                                # proxy d'inspection TLS : certificat de l'autorité de l'entreprise
                session.verify = ca_bundle
        self.s = session
        self.index = {}          # (part, éditeur, produit) -> identifiant endoflife.date
        self.cache = {}          # identifiant -> résultat de /products/{identifiant}

    def _get(self, chemin):
        derniere = None
        for essai in range(4):
            try:
                r = self.s.get(f"{API_EOL}{chemin}", timeout=60)
            except Exception as e:                       # réseau, proxy, certificat
                if requests is not None and isinstance(e, requests.exceptions.SSLError):
                    raise ErreurDonnees(tr("Le certificat d'endoflife.date n'est pas reconnu, probablement à cause d'un proxy qui inspecte le trafic TLS. "
                                           "Indiquez le certificat de votre autorité (fichier PEM) dans l'onglet Configuration, section « endoflife.date », champ « Certificat de l'autorité » "
                                           "(ou dans la variable d'environnement REQUESTS_CA_BUNDLE). ({err})", err=e))
                derniere = e
                time.sleep(2 ** essai)
                continue
            if r.status_code == 429 or r.status_code >= 500:
                derniere = RuntimeError(f"HTTP {r.status_code}")
                time.sleep(2 ** essai)
                continue
            r.raise_for_status()
            return r.json()
        raise ErreurDonnees(tr("endoflife.date est injoignable depuis ce poste ({err}). Vérifiez l'accès Internet ou le proxy.",
                               err=derniere))

    def charger_index(self):
        for e in self._get("/identifiers/cpe")["result"]:
            p = parse_cpe(e["identifier"])
            if p:
                self.index[p[:3]] = e["product"]["name"]
        return len(self.index)

    def produit(self, slug):
        if slug not in self.cache:
            self.cache[slug] = self._get(f"/products/{slug}")["result"]
        return self.cache[slug]

    def cycles(self, slug):
        return self.produit(slug)["releases"]

    def libelle(self, slug):
        return self.produit(slug).get("label") or slug

    def cible(self, slug):
        """Version encore supportée à viser : la plus récente en support long (LTS) s'il y en a, sinon la plus récente.
        Renvoie « Libellé cycle », ou None si le référentiel n'en indique aucune."""
        vivants = [c for c in self.cycles(slug) if not c.get("isEol") and c.get("isMaintained", True)]
        if not vivants:
            return None
        pool = [c for c in vivants if c.get("isLts")] or vivants
        meilleur = max(pool, key=lambda c: str(c.get("releaseDate") or ""))
        return f"{self.libelle(slug)} {meilleur['name']}"

    @staticmethod
    def _num(nom):
        """'3.8' -> (3, 8) ; None si le nom du cycle n'est pas purement numérique."""
        return tuple(int(x) for x in nom.split(".")) if re.fullmatch(r"\d+(\.\d+)*", nom) else None

    def rapprocher(self, cpe):
        """cpe = (part, éditeur, produit, version) -> dict, ou None si le produit est inconnu d'endoflife.date.

        statut : EOL | SUPPORTE | SANS_VERSION (CPE sans version) | SANS_CYCLE (version absente des cycles connus).
        `deduit` vaut True quand la version est plus ancienne que le plus vieux cycle connu : elle est alors
        considérée comme en fin de vie, avec la date de ce plus vieux cycle."""
        part, editeur, produit, version = cpe
        slug = self.index.get((part, editeur, produit))
        if not slug:
            return None
        res = {"produit": slug, "version": version, "cycle": None, "statut": None, "eol_date": None,
               "sortie": None, "deduit": False}
        if not version:
            return {**res, "statut": "SANS_VERSION"}
        m = re.match(r"\d+(?:\.\d+)*", version.replace("_", "."))
        if not m:
            return {**res, "statut": "SANS_CYCLE"}
        segs = m.group(0).split(".")
        cycles = self.cycles(slug)
        par_nom = {str(c["name"]).lower(): c for c in cycles}
        cycle, deduit = None, False
        for n in range(len(segs), 0, -1):                # 3.8.10 -> 3.8.10, puis 3.8, puis 3
            cycle = par_nom.get(".".join(segs[:n]))
            if cycle:
                break
        if not cycle:                                    # plus ancienne que tous les cycles connus ?
            nums = [(self._num(str(c["name"])), c) for c in cycles]
            if nums and all(n for n, _ in nums):
                plus_vieux, c_vieux = min(nums, key=lambda x: x[0])
                if tuple(int(x) for x in segs) < plus_vieux:
                    cycle, deduit = c_vieux, True
        if not cycle:
            return {**res, "statut": "SANS_CYCLE"}
        eol_from = cycle.get("eolFrom")
        date = eol_from if isinstance(eol_from, str) else None
        if deduit or cycle.get("isEol") or (date and dt.date.fromisoformat(date) <= dt.date.today()):
            statut = "EOL"
        else:
            statut = "SUPPORTE"
        sortie = cycle.get("releaseDate") if isinstance(cycle.get("releaseDate"), str) else None
        return {**res, "cycle": cycle["name"] if not deduit else f"<{cycle['name']}",
                "statut": statut, "eol_date": date, "sortie": sortie, "deduit": deduit}


def classer(m, aujourdhui, horizon_jours=HORIZON_JOURS):
    """'depassee' | 'a_venir' (échéance dans l'horizon) | 'supporte'."""
    if m["statut"] == "EOL":
        return "depassee"
    if m["eol_date"] and (dt.date.fromisoformat(m["eol_date"]) - aujourdhui).days <= horizon_jours:
        return "a_venir"
    return "supporte"


def analyser(machines, referentiel, aujourdhui=None, horizon_jours=HORIZON_JOURS):
    """machines : {cle: {"nom", "ip", "cpes": {cpe, ...}}}.

    Renvoie {produits, non_rapproches}.
      produits       : un par (produit, cycle) déjà hors support ou dont l'échéance tombe dans l'horizon :
                       {produit, cycle, eol_date, sortie, statut, deduit, machines: [{cle, nom, ip, versions}]}
      non_rapproches : logiciels qu'on n'a pas pu situer : {cpe, cause, machines} ;
                       cause = absent (inconnu d'endoflife.date), sans_version, sans_cycle."""
    aujourdhui = aujourdhui or dt.date.today()
    produits, orphelins = {}, {}
    for cle, mach in machines.items():
        for cpe in sorted(mach["cpes"]):
            p = parse_cpe(cpe)
            if not p or p[0] not in ("a", "o"):            # matériel (h) ignoré
                continue
            m = referentiel.rapprocher(p)
            cause = ("absent" if m is None else
                     "sans_version" if m["statut"] == "SANS_VERSION" else
                     "sans_cycle" if m["statut"] == "SANS_CYCLE" else None)
            if cause:
                o = orphelins.setdefault((":".join(p[:4] if cause == "sans_cycle" else p[:3]), cause),
                                         {"cpe": cpe, "cause": cause, "machines": set()})
                o["machines"].add(cle)
                continue
            statut = classer(m, aujourdhui, horizon_jours)
            if statut == "supporte":
                continue
            e = produits.setdefault((m["produit"], m["cycle"]), {
                "produit": m["produit"], "cycle": m["cycle"], "eol_date": m["eol_date"], "sortie": m["sortie"],
                "statut": statut, "deduit": m["deduit"], "occ": {}})
            e["occ"].setdefault(cle, set()).add(p[3])
    liste = []
    for e in produits.values():
        occ = e.pop("occ")
        e["machines"] = sorted(({"cle": c, "nom": machines[c]["nom"], "ip": machines[c]["ip"], "versions": sorted(v)}
                                for c, v in occ.items()), key=lambda x: (x["ip"] or x["nom"] or ""))
        liste.append(e)
    sans = sorted(({**o, "machines": sorted(o["machines"])} for o in orphelins.values()),
                  key=lambda o: (-len(o["machines"]), o["cpe"]))
    return {"produits": liste, "non_rapproches": sans}


# --------------------------------------------------------------------------- CSV intermédiaire
def ecrire_csv(machines, chemin, produit="sc", portee=None):
    """Un CSV « une ligne par machine et par CPE ». Renvoie le nombre de lignes."""
    import json
    os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
    n = 0
    with open(chemin, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(COLONNES_CSV)
        scope = json.dumps(portee, ensure_ascii=False) if portee else ""
        for mach in machines.values():
            for cpe in sorted(mach["cpes"]):
                w.writerow([mach["nom"], mach["ip"], cpe, produit, scope])
                n += 1
    return n


def lire_csv(chemin):
    """-> (machines, produit, portee). Lève ErreurDonnees si ce n'est pas un CSV de CPE."""
    import json
    machines, produit, portee = {}, "sc", None
    try:
        with open(chemin, newline="", encoding="utf-8-sig") as f:
            lecteur = csv.DictReader(f)
            if not lecteur.fieldnames or not {"Machine", "CPE"} <= set(lecteur.fieldnames):
                raise ErreurDonnees(tr("Ce fichier n'est pas un export de CPE : récupérez-le depuis Security Center ou Vulnerability Management "
                                       "(modèle « Logiciels en fin de vie »)."))
            for ligne in lecteur:
                nom, ip = (ligne.get("Machine") or "").strip(), (ligne.get("IP Address") or "").strip()
                cle = ip or nom
                if not cle or not ligne.get("CPE"):
                    continue
                machines.setdefault(cle, {"nom": nom, "ip": ip, "cpes": set()})["cpes"].add(ligne["CPE"].strip())
                produit = ligne.get("Source") or produit
                if portee is None and ligne.get("Scope"):
                    try:
                        portee = json.loads(ligne["Scope"])
                    except ValueError:
                        pass
    except OSError as e:
        raise ErreurDonnees(tr("Fichier illisible : {err}", err=e))
    return machines, produit, portee


# --------------------------------------------------------------------------- collecte des CPE
def _machine(nom, ip, uuid=""):
    ip = (ip or "").strip()
    nom = (nom or "").strip() or ip or uuid
    return ip or nom, {"nom": nom, "ip": ip}


def cpes_vulnerability_management(client, source, journal=None):
    """CPE par machine d'après les constats du plugin 45590, via l'export de vulnérabilités de VM.

    Le périmètre du profil (tags, plage d'adresses) s'applique ; la sévérité non, le plugin 45590 étant de niveau « info »."""
    from .vulnmanagement import _plat, _prem
    corps = client.corps_vulns(source, severites=None)
    corps.setdefault("filters", {})["plugin_id"] = [ID_PLUGIN_CPE]
    machines = {}
    for rec in client._export("vulns", corps, journal=journal):
        f = _plat(rec)
        if str(_prem(f, "plugin.id", "definition.id")) != str(ID_PLUGIN_CPE):
            continue                                       # garde-fou si le filtre n'a pas été appliqué
        trouves = extraire_cpes(str(_prem(f, "output") or ""))
        if not trouves:
            continue
        ip = _prem(f, "asset.ipv4", "asset.ipv4_addresses", "asset.ipv4s")
        if isinstance(ip, (list, tuple)):
            ip = ip[0] if ip else ""
        nom = _prem(f, "asset.fqdn", "asset.hostname", "asset.name", "asset.netbios_name")
        cle, base = _machine(nom, ip, str(_prem(f, "asset.uuid", "asset.id") or ""))
        machines.setdefault(cle, {**base, "cpes": set()})["cpes"].update(trouves)
    return machines


def cpes_security_center(client, source, journal=None):
    """CPE par machine d'après les constats du plugin 45590, via l'analyse « vulndetails » de Security Center.

    Dépôts, listes d'actifs et filtres du profil s'appliquent ; une requête enregistrée est ignorée
    (elle remplacerait le filtre sur le plugin)."""
    journal = journal or (lambda m: None)
    source = {**(source or {}), "query_id": ""}
    filtres = client.filtres(source)
    filtres.append({"filterName": "pluginID", "operator": "=", "value": str(ID_PLUGIN_CPE)})
    machines, debut, total = {}, 0, None
    while total is None or debut < total:
        rep = client._appel("POST", "analysis", json={
            "type": "vuln", "sourceType": "cumulative", "sortField": "severity", "sortDir": "DESC",
            "query": {"type": "vuln", "tool": "vulndetails", "filters": filtres,
                      "startOffset": debut, "endOffset": debut + client.taille_page}})
        if not isinstance(rep, dict) or "results" not in rep:
            raise ErreurDonnees(tr("Réponse inattendue de Security Center (pas de résultats d'analyse)."))
        total = int(rep.get("totalRecords") or 0)
        page = rep["results"] or []
        if not page:
            break
        for r in page:
            texte = r.get("pluginText") or " ".join(str(v) for v in r.values() if isinstance(v, str))
            trouves = extraire_cpes(texte)
            if not trouves:
                continue
            nom = r.get("dnsName") or r.get("netbiosName")
            cle, base = _machine(nom, r.get("ip"))
            machines.setdefault(cle, {**base, "cpes": set()})["cpes"].update(trouves)
        debut += len(page)
        journal(tr("{recues} constat(s) du plugin {plugin} reçu(s) sur {total}.", recues=debut, plugin=ID_PLUGIN_CPE, total=total))
    return machines


def collecter(client, vm, source, chemin, journal=None, portee=None):
    """Interroge Security Center (vm=False) ou Vulnerability Management (vm=True) et écrit le CSV de CPE."""
    t0 = time.time()
    journal = journal or (lambda m: None)
    journal(tr("Recherche des logiciels détectés (plugin {plugin}, Common Platform Enumeration).", plugin=ID_PLUGIN_CPE))
    machines = (cpes_vulnerability_management if vm else cpes_security_center)(client, source, journal)
    if not machines:
        raise ErreurDonnees(tr("Aucun logiciel (CPE) n'a été trouvé. Le plugin {plugin} ne renvoie des résultats que pour les machines analysées "
                               "avec authentification (scan authentifié ou agent) : vérifiez le périmètre et les identifiants des scans.",
                               plugin=ID_PLUGIN_CPE))
    n = ecrire_csv(machines, chemin, "vm" if vm else "sc", portee)
    journal(tr("{machines} machine(s), {n} logiciel(s) détecté(s).", machines=len(machines), n=n))
    return {"lignes": n, "total": n, "secondes": round(time.time() - t0, 1)}


# --------------------------------------------------------------------------- analyse pour le rapport
def _filtrer(machines, perimetre):
    """Filtres « machines à inclure / exclure » du profil (adresse IP, réseau CIDR ou nom avec jokers)."""
    from .analyse import _correspond, _regles_machines
    inc, exc = _regles_machines((perimetre or {}).get("inclure")), _regles_machines((perimetre or {}).get("exclure"))
    if not (inc or exc):
        return machines
    return {c: m for c, m in machines.items()
            if (not inc or _correspond(inc, m["ip"], m["nom"])) and not _correspond(exc, m["ip"], m["nom"])}


def apercu_csv(chemin, perimetre=None, nom_fichier=None, portee=None):
    """Aperçu affiché après la récupération : sans réseau, avant le rapprochement avec endoflife.date."""
    machines, produit, portee_csv = lire_csv(chemin)
    garde = _filtrer(machines, perimetre)
    return {"genre": "cpe", "fichier": nom_fichier or chemin, "portee": portee or portee_csv, "produit": produit,
            "machines": len(garde), "machines_exclues": len(machines) - len(garde),
            "logiciels": len({c for m in garde.values() for c in m["cpes"]})}


_PARTAGE = {"ref": None, "ca": None, "t": 0.0}
DUREE_PARTAGE = 3600                                  # une heure : l'aperçu puis la génération réutilisent les mêmes réponses d'endoflife.date


def reglages(cfg):
    """Réglages réseau d'endoflife.date (section « endoflife » de la configuration) : à passer à AnalyseEol(**reglages(cfg))."""
    s = (cfg or {}).get("endoflife") or {}
    return {"ca_bundle": s.get("ca_bundle") or None, "verifier_tls": s.get("verifier_tls", True)}


def tester(section):
    """Test de la connexion à endoflife.date avec les réglages saisis : renvoie le nombre de produits connus."""
    ref = Referentiel(ca_bundle=(section or {}).get("ca_bundle") or None, verifier_tls=(section or {}).get("verifier_tls", True))
    return {"produits": ref.charger_index()}


def referentiel_partage(ca_bundle=None, verifier_tls=True):
    """Référentiel gardé en mémoire (index et cycles déjà lus), pour ne pas redemander endoflife.date à chaque aperçu."""
    cle = (ca_bundle, verifier_tls)
    if not (_PARTAGE["ref"] and _PARTAGE["ca"] == cle and time.time() - _PARTAGE["t"] < DUREE_PARTAGE and _PARTAGE["ref"].index):
        _PARTAGE.update(ref=Referentiel(ca_bundle=ca_bundle, verifier_tls=verifier_tls), ca=cle, t=time.time())
    return _PARTAGE["ref"]


def resume(an):
    """Aperçu affiché dans l'interface après la récupération : chiffres propres au rapport, sans le détail."""
    dep = [e for e in an.produits if e["statut"] == "depassee"]
    haut = sorted(an.produits, key=lambda e: (-len(e["machines"]), e["eol_date"] or ""))[:5]
    return {"genre": "eol", "fichier": an.nom_fichier, "portee": an.portee, "produit": an.produit,
            "machines": an.n_hosts, "machines_exclues": an.n_total - an.n_hosts,
            "produits": len(an.produits), "hors_support": len(dep), "sous_12_mois": len(an.produits) - len(dep),
            "machines_concernees": len(an.concernees), "vulns_hors_support": an.vulns_hors_support,
            "non_rapproches": len(an.non_rapproches),
            "top": [{"nom": f"{e['libelle']} {e['cycle']}", "machines": len(e["machines"]), "statut": e["statut"],
                     "eol_date": e["eol_date"], "vulns": e.get("vulns")} for e in haut]}


class AnalyseEol:
    """Résultat pour un CSV de CPE : produits hors support ou proches de l'être, logiciels non rapprochés."""

    sans_regle = ()                                       # interface commune avec Analyse (pas de règles ici)

    def __init__(self, chemin, perimetre=None, nom_fichier=None, portee=None, referentiel=None, aujourdhui=None,
                 horizon_jours=HORIZON_JOURS, analyse=None, ca_bundle=None, verifier_tls=True):
        machines, self.produit, portee_csv = lire_csv(chemin)
        self.nom_fichier = nom_fichier or chemin
        self.portee = portee or portee_csv
        self.perimetre = perimetre or {}
        self.n_total = len(machines)
        self.machines = _filtrer(machines, self.perimetre)
        self.n_hosts = len(self.machines)
        self.aujourdhui = aujourdhui or dt.date.today()
        self.horizon_jours = horizon_jours
        ref = referentiel or referentiel_partage(ca_bundle, verifier_tls)
        if not ref.index:
            ref.charger_index()
        self.ref = ref
        res = analyser(self.machines, ref, self.aujourdhui, horizon_jours)
        for e in res["produits"]:
            e["libelle"] = ref.libelle(e["produit"])
            e["cible"] = ref.cible(e["produit"])
        # plus urgents d'abord : produits hors support (les plus répandus en tête), puis échéances à venir par date
        self.produits = sorted(res["produits"], key=lambda e: (e["statut"] != "depassee", -len(e["machines"]) if e["statut"] == "depassee" else 0,
                                                              e["eol_date"] or "0000-00-00", e["produit"]))
        self.non_rapproches = res["non_rapproches"]
        self.concernees = {m["cle"] for e in self.produits for m in e["machines"]}
        self.consulte = dt.date.today()
        self.analyse = analyse                            # Analyse de l'export de vulnérabilités (facultative) : statistiques par produit
        self.vulns_hors_support = None
        if analyse is not None:
            self._rattacher_vulnerabilites(analyse)

    def _rattacher_vulnerabilites(self, analyse):
        """Ajoute à chaque produit le nombre de vulnérabilités ouvertes et l'AES maximal des machines qui le portent."""
        par = {}
        for x in analyse.machines:
            for k in (x.get("ip"), x.get("dns")):
                if isinstance(k, str) and k:
                    par[k] = x
        def trouver(m):
            return par.get(m["ip"]) or par.get(m["nom"])
        for e in self.produits:
            vus = {m["cle"]: trouver(m) for m in e["machines"]}
            vus = {c: x for c, x in vus.items() if x}
            aes = [x["aes"] for x in vus.values() if x.get("aes") == x.get("aes") and x.get("aes") is not None]
            e["vulns"] = sum(x["n"] for x in vus.values())
            e["aes"] = max(aes) if aes else None
        hors = {}
        for e in self.produits:
            if e["statut"] == "depassee":
                for m in e["machines"]:
                    x = trouver(m)
                    if x:
                        hors[m["cle"]] = x["n"]
        self.vulns_hors_support = sum(hors.values())


# --------------------------------------------------------------------------- jeu d'exemple (« Voir un exemple »)
_EX_PRODUITS = {                      # identifiant: (libellé, part, éditeur, produit CPE, cycles (nom, fin de support, sortie, LTS))
    "php": ("PHP", "a", "php", "php", [("8.3", "2027-12-31", "2023-11-23", False), ("8.1", "2026-12-31", "2021-11-25", False),
                                       ("7.4", "2022-11-28", "2019-11-28", False)]),
    "ubuntu": ("Ubuntu", "o", "canonical", "ubuntu_linux", [("24.04", "2029-05-31", "2024-04-25", True), ("18.04", "2023-05-31", "2018-04-26", True)]),
    "windows-server": ("Windows Server", "o", "microsoft", "windows_server", [("2025", "2034-10-10", "2024-11-01", False),
                                                                                ("2016", "2027-01-12", "2016-10-15", False),
                                                                                ("2012", "2023-10-10", "2013-10-18", False)]),
    "python": ("Python", "a", "python", "python", [("3.12", "2028-10-31", "2023-10-02", False), ("3.10", "2026-10-31", "2021-10-04", False),
                                                   ("3.8", "2024-10-07", "2019-10-14", False)]),
    "dotnet": (".NET", "a", "microsoft", ".net", [("10.0", "2028-11-14", "2025-11-11", True), ("8.0", "2026-11-10", "2023-11-14", True)]),
    "tomcat": ("Apache Tomcat", "a", "apache", "tomcat", [("10.1", "2027-12-31", "2022-09-23", False), ("8.5", "2024-03-31", "2016-06-13", False)]),
    "openssl": ("OpenSSL", "a", "openssl", "openssl", [("3.5", "2030-04-08", "2025-04-08", True), ("1.1.1", "2023-09-11", "2018-09-11", True)]),
}
_EX_MACHINES = [      # (nom, ip, [CPE détectés])
    ("srv-fichiers-01", "10.10.4.21", ["cpe:/o:microsoft:windows_server:2012", "cpe:/a:openssl:openssl:1.1.1w"]),
    ("srv-compta-02", "10.10.4.37", ["cpe:/o:microsoft:windows_server:2012", "cpe:/a:microsoft:.net:8.0.11"]),
    ("srv-print-01", "10.10.4.55", ["cpe:/o:microsoft:windows_server:2012"]),
    ("srv-ad-01", "10.10.4.10", ["cpe:/o:microsoft:windows_server:2016"]),
    ("srv-ad-02", "10.10.4.11", ["cpe:/o:microsoft:windows_server:2016"]),
    ("app-web-03", "10.10.8.14", ["cpe:/o:canonical:ubuntu_linux:18.04", "cpe:/a:php:php:7.4.33", "cpe:/a:python:python:3.8.10"]),
    ("app-batch-01", "10.10.8.30", ["cpe:/o:canonical:ubuntu_linux:18.04", "cpe:/a:python:python:3.10.12", "cpe:/a:apache:tomcat:8.5.99"]),
    ("app-web-04", "10.10.8.15", ["cpe:/a:php:php:8.1.27", "cpe:/a:openssl:openssl:1.1.1w"]),
    ("app-api-01", "10.10.8.40", ["cpe:/a:microsoft:.net:8.0.11", "cpe:/a:python:python:3.12.3", "cpe:/a:vendor:logiciel_maison:2.0"]),
    ("app-api-02", "10.10.8.41", ["cpe:/a:microsoft:.net:8.0.11", "cpe:/o:canonical:ubuntu_linux:24.04"]),
]


class _SessionExemple:
    """Fausse session HTTP qui répond avec le jeu d'exemple : le rapport d'exemple n'a pas besoin du réseau."""
    class _R:
        status_code = 200
        def __init__(self, data): self.data = data
        def json(self): return self.data
        def raise_for_status(self): pass

    def get(self, url, timeout=0):
        chemin = url[len(API_EOL):]
        if chemin == "/identifiers/cpe":
            return self._R({"result": [{"identifier": f"cpe:/{p}:{v}:{c}", "product": {"name": k}}
                                       for k, (_, p, v, c, _) in _EX_PRODUITS.items()]})
        libelle, *_, cycles = _EX_PRODUITS[chemin.rsplit("/", 1)[1]]
        auj = dt.date.today().isoformat()
        return self._R({"result": {"label": libelle, "releases": [
            {"name": n, "isEol": eol <= auj, "eolFrom": eol, "releaseDate": sortie, "isLts": lts, "isMaintained": eol > auj}
            for n, eol, sortie, lts in cycles]}})


def exemple(dossier, aujourdhui=None):
    """AnalyseEol construite sur des données fictives, sans réseau (pour « Voir un exemple »)."""
    machines = {ip: {"nom": nom, "ip": ip, "cpes": set(c)} for nom, ip, c in _EX_MACHINES}
    chemin = os.path.join(dossier, "cpe-exemple.csv")
    ecrire_csv(machines, chemin, "sc")
    vulns = {"srv-fichiers-01": (31, 640), "srv-compta-02": (28, 710), "srv-print-01": (22, 380), "srv-ad-01": (9, 520), "srv-ad-02": (8, 505),
             "app-web-03": (41, 790), "app-batch-01": (23, 450), "app-web-04": (6, 300), "app-api-01": (2, 210), "app-api-02": (1, 150)}
    analyse = type("AnalyseExemple", (), {"machines": [{"ip": ip, "dns": nom, "n": vulns[nom][0], "aes": vulns[nom][1]}
                                                       for nom, ip, _ in _EX_MACHINES]})()
    return AnalyseEol(chemin, nom_fichier="cpe-exemple.csv", referentiel=Referentiel(_SessionExemple()), aujourdhui=aujourdhui,
                      analyse=analyse)
