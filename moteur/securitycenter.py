"""Récupération d'un export directement depuis l'API REST de Tenable Security Center.

La requête (POST /rest/analysis, outil « vulndetails » = une ligne par couple machine / vulnérabilité) est
rejouée page par page, puis écrite dans un fichier CSV qui reprend les en-têtes de l'export de l'interface
(Plugin, Plugin Name, Severity, IP Address…). Le reste de l'application traite donc ce fichier exactement
comme un CSV déposé à la main.

Authentification : clés d'API (en-tête x-apikey), à créer dans Security Center > Users > API Keys.
"""
import json
import os
import re

import pandas as pd

try:                                             # absente d'une installation antérieure à cette fonction
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:                              # pragma: no cover
    requests = None

from . import config as CFG
from . import portee as P
from .i18n import tr
from .regles import ErreurDonnees

IDS_SEVERITE = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
OUTILS = ("vulndetails", "listvuln")      # détail par machine (conseillé) ou liste agrégée par plugin
SOURCE_DEFAUT = {
    "outil": "vulndetails",
    "source_type": "cumulative",          # cumulative (état actuel) | patched (corrigé)
    "repositories": "",                   # identifiants séparés par des virgules ; vide = tous
    "asset_list": "",                     # identifiant(s) de liste(s) d'actifs, séparés par des virgules (union)
    "asset_noms": "",                     # JSON {identifiant: nom} des listes choisies, pour la couverture
    "repositories_noms": "",              # JSON {identifiant: nom} des dépôts choisis : les identifiants sont propres à un serveur
    "query_id": "",                       # identifiant d'une requête enregistrée (remplace les filtres ci-dessus)
    "query_nom": "",                      # nom de cette requête
    "filtres": "",                        # filtres supplémentaires : liste JSON de filtres Security Center
}
COLONNES = ["Plugin", "Plugin Name", "Family", "Severity", "IP Address", "DNS Name", "NetBIOS Name",
            "Protocol", "Port", "VPR", "ACR", "AES", "CVE", "Repository", "Last Observed", "Solution", "Synopsis"]


def _nom(v):
    """Les objets de l'API ({id, name, …}) deviennent leur nom ; le reste est laissé tel quel."""
    return v.get("name", "") if isinstance(v, dict) else v


class Client:
    def __init__(self, cfg):
        if requests is None:
            raise ErreurDonnees(tr("La bibliothèque « requests » manque : exécutez "
                                   "« .venv/bin/python -m pip install -r requirements.txt » (Windows : .venv\\Scripts\\python.exe), puis relancez."))
        self.url = (cfg.get("url") or "").rstrip("/")
        if not self.url:
            raise ErreurDonnees(tr("Adresse de Security Center non renseignée : onglet Configuration > Security Center."))
        if not (cfg.get("access_key") and cfg.get("secret_key")):
            raise ErreurDonnees(tr("Clés d'API non renseignées : onglet Configuration > Security Center."))
        if not self.url.startswith(("https://", "http://")):
            self.url = "https://" + self.url
        self.taille_page = max(100, min(int(cfg.get("taille_page") or 1000), 10000))
        self.s = requests.Session()
        self.s.mount("https://", HTTPAdapter(max_retries=2))
        self.s.headers["x-apikey"] = f"accesskey={cfg['access_key']}; secretkey={cfg['secret_key']}"
        if cfg.get("verifier_tls", True):
            self.s.verify = CFG.verifier(cfg)
        else:
            self.s.verify = False
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    # ------------------------------------------------------------------ appels
    def _appel(self, methode, chemin, **kw):
        try:
            r = self.s.request(methode, f"{self.url}/rest/{chemin.lstrip('/')}", timeout=(10, 180), **kw)
        except requests.exceptions.SSLError:
            raise ErreurDonnees(tr("Certificat de Security Center non reconnu. Indiquez le certificat de votre autorité "
                                   "interne (champ « Certificat CA »), ou désactivez la vérification si c'est un test."))
        except requests.exceptions.ConnectionError:
            raise ErreurDonnees(tr("Security Center injoignable à l'adresse {url} (réseau, VPN, nom ou port).", url=self.url))
        except requests.exceptions.Timeout:
            raise ErreurDonnees(tr("Security Center n'a pas répondu à temps."))
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code in (401, 403) or (isinstance(data, dict) and data.get("error_code") in (141, 144)):
            raise ErreurDonnees(tr("Clés d'API refusées par Security Center (invalides, expirées ou droits insuffisants)."))
        if r.status_code >= 400 or (isinstance(data, dict) and data.get("error_code")):
            msg = (data.get("error_msg") if isinstance(data, dict) else "") or f"HTTP {r.status_code}"
            raise ErreurDonnees(tr("Security Center a refusé la requête : {msg}", msg=msg))
        return data.get("response") if isinstance(data, dict) else data

    # ------------------------------------------------------------------ listes (pour l'interface)
    @staticmethod
    def _fusion(rep):
        if isinstance(rep, dict):
            vus = {}
            for liste in (rep.get("manageable") or []), (rep.get("usable") or []):
                for x in liste:
                    vus[str(x.get("id"))] = x
            return list(vus.values())
        return rep or []

    def tester(self):
        reps = self.repositories()
        try:
            version = (self._appel("GET", "system") or {}).get("version", "")
        except ErreurDonnees:
            version = ""
        return {"version": version, "repositories": len(reps)}

    def repositories(self):
        return [{"id": str(x["id"]), "nom": x.get("name", ""), "type": x.get("type", "")}
                for x in self._fusion(self._appel("GET", "repository", params={"fields": "id,name,type"}))]

    def listes_actifs(self):
        return [{"id": str(x["id"]), "nom": x.get("name", ""), "type": x.get("type", ""),
                 "machines": int(x["ipCount"]) if str(x.get("ipCount") or "").isdigit() else None}
                for x in self._fusion(self._appel("GET", "asset", params={"fields": "id,name,type,ipCount"}))]

    def resoudre(self, source, journal=None):
        """Source dont les identifiants (dépôts, listes d'actifs, requête enregistrée) sont retrouvés par leur nom sur CE serveur.

        Les identifiants de Security Center sont propres à chaque serveur : un profil copié sur un autre poste ou vers un autre
        Security Center désignerait sinon d'autres objets, sans erreur. Quand le profil mémorise les noms, on cherche chaque nom
        sur le serveur et on prend l'identifiant qu'il y porte. Un nom introuvable arrête la récupération avec un message clair.
        Sans noms mémorisés (profil ancien), les identifiants sont utilisés tels quels."""
        journal = journal or (lambda m: None)
        source = {**SOURCE_DEFAUT, **(source or {})}
        ids_dep = [x.strip() for x in str(source["repositories"]).replace(";", ",").split(",") if x.strip()]
        ids_act = P.ids_listes(source)
        ids_req = [str(source["query_id"]).strip()] if str(source["query_id"]).strip() else []
        noms_dep, noms_act = P._json(source["repositories_noms"], {}), P._json(source["asset_noms"], {})
        noms_req = {ids_req[0]: source["query_nom"]} if ids_req and source["query_nom"] else {}
        out = dict(source)
        for cle, ids, noms, lister, genre in (
                ("repositories", ids_dep, noms_dep, self.repositories, tr("Le dépôt")),
                ("asset_list", ids_act, noms_act, self.listes_actifs, tr("La liste d'actifs")),
                ("query_id", ids_req, noms_req, self.requetes, tr("La requête enregistrée"))):
            if not any(noms.get(i) for i in ids):
                continue
            serveur = lister()
            par_id = {x["id"]: x["nom"] for x in serveur}
            nouveaux, renommes = [], {}
            for i in ids:
                nom = str(noms.get(i) or "")
                if not nom:
                    nouveaux.append(i)
                    continue
                trouves = [x["id"] for x in serveur if x["nom"].casefold() == nom.casefold()]
                if not trouves:
                    raise ErreurDonnees(tr("{genre} « {nom} » est introuvable sur ce Security Center. Les identifiants sont propres à "
                                           "chaque serveur : rouvrez l'onglet Configuration, cliquez sur le bouton qui liste les "
                                           "dépôts, listes d'actifs et requêtes, puis choisissez-le de nouveau.", genre=genre, nom=nom))
                j = i if i in trouves else trouves[0]
                if j != i:
                    journal(tr("{genre} « {nom} » : identifiant {nouveau} sur ce serveur (le profil mémorisait {ancien}).",
                               genre=genre, nom=nom, nouveau=j, ancien=i))
                nouveaux.append(j)
                renommes[j] = par_id.get(j) or nom
            out[cle] = ", ".join(nouveaux) if cle != "query_id" else (nouveaux[0] if nouveaux else "")
            if cle == "asset_list":
                out["asset_noms"] = json.dumps({j: renommes.get(j) or noms_act.get(j, "") for j in nouveaux}, ensure_ascii=False)
        return out

    def decompter(self, source):
        """Nombre de machines (adresses IP) portant au moins une vulnérabilité dans la sélection : outil « sumip »."""
        source = self.resoudre(source)
        rep = self._appel("POST", "analysis", json={
            "type": "vuln", "sourceType": "cumulative", "sortField": "score", "sortDir": "DESC",
            "query": {"type": "vuln", "tool": "sumip", "filters": self.filtres({**source, "filtres": ""}), "startOffset": 0, "endOffset": 1}})
        return int((rep or {}).get("totalRecords") or 0) if isinstance(rep, dict) else None

    def requetes(self):
        return [{"id": str(x["id"]), "nom": x.get("name", ""), "outil": x.get("tool", "")}
                for x in self._fusion(self._appel("GET", "query", params={"fields": "id,name,tool,type"}))
                if x.get("type", "vuln") == "vuln"]

    # ------------------------------------------------------------------ requête d'analyse
    @staticmethod
    def filtres(source, severites=None):
        f = []
        if severites:
            ids = sorted({IDS_SEVERITE[s] for s in severites if s in IDS_SEVERITE}, reverse=True)
            f.append({"filterName": "severity", "operator": "=", "value": ",".join(map(str, ids))})
        repos = [x.strip() for x in str(source.get("repositories") or "").replace(";", ",").split(",") if x.strip()]
        if repos:
            f.append({"filterName": "repository", "operator": "=", "value": [{"id": x} for x in repos]})
        ids = [x for x in re.split(r"[,;\s]+", str(source.get("asset_list") or "")) if x]
        if ids:                                       # plusieurs listes : union (OU), emboîtée comme l'attend l'API
            val = {"id": ids[0]}
            for i in ids[1:]:
                val = {"operator": "union", "operand1": val, "operand2": {"id": i}}
            f.append({"filterName": "asset", "operator": "=", "value": val})
        extra = (source.get("filtres") or "").strip()
        if extra:
            try:
                plus = json.loads(extra)
            except ValueError as e:
                raise ErreurDonnees(tr("Filtres supplémentaires : JSON invalide ({err}).", err=e))
            if isinstance(plus, dict):
                plus = [plus]
            if not isinstance(plus, list) or not all(isinstance(x, dict) and "filterName" in x for x in plus):
                raise ErreurDonnees(tr("Filtres supplémentaires : attendu une liste d'objets "
                                       "{\"filterName\": …, \"operator\": …, \"value\": …}."))
            f.extend(plus)
        return f

    @staticmethod
    def corps(source, debut, fin, severites=None):
        source = {**SOURCE_DEFAUT, **(source or {})}
        outil = source["outil"] if source["outil"] in OUTILS else "vulndetails"
        if str(source.get("query_id") or "").strip():
            requete = {"id": str(source["query_id"]).strip()}
        else:
            requete = {"type": "vuln", "tool": outil, "filters": Client.filtres(source, severites)}
        requete.update({"startOffset": debut, "endOffset": fin})
        return {"type": "vuln", "sourceType": source["source_type"] if source["source_type"] in ("cumulative", "patched")
                else "cumulative", "sortField": "severity", "sortDir": "DESC", "query": requete}

    @staticmethod
    def _ligne(r):
        return {"Plugin": r.get("pluginID"), "Plugin Name": r.get("pluginName") or r.get("name"), "Family": _nom(r.get("family")),
                "Severity": _nom(r.get("severity")), "IP Address": r.get("ip"), "DNS Name": r.get("dnsName"),
                "NetBIOS Name": r.get("netbiosName"), "Protocol": r.get("protocol"), "Port": r.get("port"),
                "VPR": r.get("vprScore"), "ACR": r.get("acrScore"),
                "AES": r.get("assetExposureScore"), "CVE": r.get("cve"), "Repository": _nom(r.get("repository")),
                "Last Observed": pd.to_datetime(int(r["lastSeen"]), unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S")
                if str(r.get("lastSeen") or "").isdigit() else "",
                "Solution": r.get("solution"), "Synopsis": r.get("synopsis")}

    def exporter_csv(self, source, chemin, severites=None, limite=2_000_000, journal=None, portee=None):
        """Interroge l'API page par page et écrit le CSV. Renvoie {lignes, secondes}. `journal(message)` : suivi (facultatif)."""
        import time
        journal = journal or (lambda m: None)
        t0, lignes, debut, total, premiere = time.time(), [], 0, None, []
        source = self.resoudre(source, journal)
        journal(tr("Interrogation de Security Center ({url}), par pages de {taille} lignes.", url=self.url, taille=self.taille_page))
        while total is None or debut < total:
            rep = self._appel("POST", "analysis", json=self.corps(source, debut, debut + self.taille_page, severites))
            if not isinstance(rep, dict) or "results" not in rep:
                raise ErreurDonnees(tr("Réponse inattendue de Security Center (pas de résultats d'analyse)."))
            total = int(rep.get("totalRecords") or 0)
            page = rep["results"] or []
            if not page:
                break
            if not lignes:
                premiere = list(page[0])                      # pour le message d'erreur si les noms manquent
            lignes.extend(self._ligne(r) for r in page)
            debut += len(page)
            journal(tr("{recues} ligne(s) reçue(s) sur {total} ({secondes} s).", recues=debut, total=total, secondes=int(time.time() - t0)))
            if debut >= limite:
                raise ErreurDonnees(tr("Plus de {limite} lignes : affinez la requête (dépôts, liste d'actifs, sévérités).", limite=limite))
        if lignes and not any(l["Plugin Name"] for l in lignes):
            raise ErreurDonnees(tr("Security Center n'a renvoyé aucun nom de vulnérabilité (champs reçus : {champs}). "
                                   "Indiquez ces champs pour adapter la correspondance.", champs=", ".join(sorted(premiere))))
        if not lignes:
            raise ErreurDonnees(tr("La requête n'a renvoyé aucune vulnérabilité : vérifiez les dépôts, la liste d'actifs et les filtres."))
        journal(tr("Écriture du fichier CSV ({n} lignes).", n=len(lignes)))
        os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
        df = pd.DataFrame(lignes, columns=COLONNES)
        if portee:
            df[P.COLONNE] = json.dumps(portee, ensure_ascii=False)
        df.to_csv(chemin, index=False, encoding="utf-8-sig")
        return {"lignes": len(lignes), "total": total, "secondes": round(time.time() - t0, 1)}
