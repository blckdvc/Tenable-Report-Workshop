"""Récupération d'un export directement depuis l'API REST de Tenable Vulnerability Management (cloud.tenable.com).

Les vulnérabilités sont demandées par export asynchrone (POST /vulns/export, suivi de l'état, téléchargement des blocs),
puis, si l'option est active, les notes ACR et AES des machines par l'export des assets (POST /assets/v2/export). Le tout est
écrit dans un fichier CSV aux colonnes internes (comme celui de Security Center) : le reste de l'application le traite
comme un CSV déposé à la main.

Authentification : en-tête X-ApiKeys (clés créées dans Vulnerability Management > Paramètres > Mon profil > Clés d'API).

Le nom des champs de la réponse a changé selon les versions de l'API (plugin.* ou definition.*, asset.ipv4 ou
asset.ipv4_addresses…) : la lecture accepte les deux et signale clairement ce qu'elle ne retrouve pas."""
import os
import time

import pandas as pd

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:                              # pragma: no cover
    requests = None

from . import portee as P
from . import vm as VM
from .i18n import tr
from .regles import ErreurDonnees

URL_DEFAUT = "https://cloud.tenable.com"
SOURCE_DEFAUT = {"cidr": "", "acr_aes": "1", "tags": ""}          # propres à Vulnerability Management (dans la source du profil)
SEV_API = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def _plat(d, pre=""):
    """Dictionnaire imbriqué -> clés pointées (asset.id, plugin.vpr.score…). Les listes restent des valeurs."""
    out = {}
    for k, v in (d or {}).items():
        cle = f"{pre}{k}"
        if isinstance(v, dict):
            out.update(_plat(v, cle + "."))
        else:
            out[cle] = v
    return out


def _prem(plat, *cles):
    for c in cles:
        v = plat.get(c)
        if v is None or (isinstance(v, float) and v != v) or v == "" or v == []:
            continue
        return v
    return None


def _texte(v):
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return v


def ligne_api(rec):
    """Un enregistrement de l'export (ancien ou nouveau modèle) -> colonnes de l'« export des propriétés » lues par vm.convertir."""
    f = _plat(rec)
    port = _prem(f, "port.port", "port")
    proto = _prem(f, "port.protocol", "protocol")
    return {
        "asset.id": _prem(f, "asset.id", "asset.uuid"),
        "asset.ipv4_addresses": _texte(_prem(f, "asset.ipv4_addresses", "asset.ipv4", "asset.ipv4s")),
        "asset.name": _prem(f, "asset.name", "asset.fqdn", "asset.hostname", "asset.netbios_name"),
        "definition.id": _prem(f, "definition.id", "plugin.id"),
        "definition.name": _prem(f, "definition.name", "plugin.name"),
        "definition.family": _prem(f, "definition.family", "plugin.family"),
        "definition.solution": _prem(f, "definition.solution", "plugin.solution"),
        "definition.synopsis": _prem(f, "definition.synopsis", "plugin.synopsis"),
        "definition.cve": _texte(_prem(f, "definition.cve", "plugin.cve")),
        "definition.description": _prem(f, "definition.description", "plugin.description"),
        "definition.vpr.score": _prem(f, "definition.vpr.score", "plugin.vpr.score", "plugin.vpr_score", "vpr.score", "vpr_score"),
        "port": port, "protocol": proto,
        "severity": _prem(f, "severity", "definition.severity", "plugin.risk_factor"),
        "state": _prem(f, "state"),
        "last_found": _prem(f, "last_found", "last_seen"),
    }


def notes_assets(assets):
    """{identifiant d'asset: (ACR, AES)} d'après les blocs de l'export des assets (ratings.acr.score, ratings.aes.score)."""
    out = {}
    for a in assets:
        f = _plat(a)
        ident = _prem(f, "id", "uuid", "asset.id")
        if ident:
            out[str(ident)] = (_prem(f, "ratings.acr.score", "acr_score", "acr"), _prem(f, "ratings.aes.score", "aes_score", "aes"))
    return out


class Client:
    def __init__(self, cfg):
        if requests is None:
            raise ErreurDonnees(tr("La bibliothèque « requests » manque : exécutez "
                                   "« .venv/bin/python -m pip install -r requirements.txt » (Windows : .venv\\Scripts\\python.exe), puis relancez."))
        self.url = (cfg.get("url") or URL_DEFAUT).rstrip("/")
        if not self.url.startswith(("https://", "http://")):
            self.url = "https://" + self.url
        if not (cfg.get("access_key") and cfg.get("secret_key")):
            raise ErreurDonnees(tr("Clés d'API non renseignées : onglet Configuration > Vulnerability Management."))
        self.delai_max = int(cfg.get("delai_max") or 3600)
        self.s = requests.Session()
        self.s.mount("https://", HTTPAdapter(max_retries=2))
        self.s.headers.update({"X-ApiKeys": f"accessKey={cfg['access_key']}; secretKey={cfg['secret_key']}",
                               "Accept": "application/json", "User-Agent": "AtelierRapportsTenable/1.0"})
        if cfg.get("verifier_tls", True):
            self.s.verify = cfg["ca_bundle"] if cfg.get("ca_bundle") else True
        else:
            self.s.verify = False
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    def _appel(self, methode, chemin, **kw):
        try:
            r = self.s.request(methode, f"{self.url}/{chemin.lstrip('/')}", timeout=(10, 180), **kw)
        except requests.exceptions.SSLError:
            raise ErreurDonnees(tr("Certificat de Vulnerability Management non reconnu. Indiquez le certificat de votre autorité "
                                   "interne (champ « Certificat CA »), ou désactivez la vérification si c'est un test."))
        except requests.exceptions.ConnectionError:
            raise ErreurDonnees(tr("Vulnerability Management injoignable à l'adresse {url} (réseau, proxy, nom ou port).", url=self.url))
        except requests.exceptions.Timeout:
            raise ErreurDonnees(tr("Vulnerability Management n'a pas répondu à temps."))
        try:
            data = r.json()
        except ValueError:
            data = None
        if r.status_code == 401:
            raise ErreurDonnees(tr("Clés d'API refusées par Vulnerability Management (invalides ou expirées)."))
        if r.status_code == 403:
            raise ErreurDonnees(tr("Droits insuffisants dans Vulnerability Management : l'export des vulnérabilités demande un rôle Basic "
                                   "ou supérieur, avec accès aux assets concernés."))
        if r.status_code == 429:
            raise ErreurDonnees(tr("Vulnerability Management limite les requêtes, ou un export identique est déjà en cours : "
                                   "patientez quelques minutes et réessayez."))
        if r.status_code >= 400:
            msg = (data.get("message") or data.get("error") or "") if isinstance(data, dict) else ""
            err = ErreurDonnees(tr("Vulnerability Management a refusé la requête : {msg}", msg=msg or f"HTTP {r.status_code}"))
            err.statut = r.status_code
            raise err
        return data

    def tester(self):
        rep = self._appel("GET", "session") or {}
        return {"utilisateur": rep.get("username") or rep.get("name") or ""}

    # ------------------------------------------------------------------ exports asynchrones
    def _export(self, base, corps, rappel=None, journal=None):
        """Lance l'export `base` (« vulns » ou « assets/v2 »), attend sa fin et renvoie la liste de tous les enregistrements.
        `journal(message)` reçoit, s'il est fourni, le suivi de chaque étape (affiché dans l'interface)."""
        journal = journal or (lambda m: None)
        rep = self._appel("POST", f"{base}/export", json=corps) or {}
        uuid = rep.get("export_uuid") or rep.get("uuid")
        if not uuid:
            raise ErreurDonnees(tr("Réponse inattendue de Vulnerability Management (pas d'identifiant d'export)."))
        journal(tr("Export créé (identifiant {uuid}), en attente de Vulnerability Management…", uuid=uuid))
        t0, vus, recs, pause = time.time(), set(), [], 2.0
        while True:
            st = self._appel("GET", f"{base}/export/{uuid}/status") or {}
            etat = str(st.get("status") or "").upper()
            if etat in ("ERROR", "CANCELLED"):
                raise ErreurDonnees(tr("L'export a échoué côté Vulnerability Management (état {etat}).", etat=etat))
            prets = st.get("chunks_available") or []
            dispo = [c for c in prets if c not in vus]
            journal(tr("État {etat} après {secondes} s : {prets} bloc(s) prêt(s), {telecharges} téléchargé(s).",
                       etat=etat or "?", secondes=int(time.time() - t0), prets=len(prets), telecharges=len(vus))
                    + (" " + tr("Nouvelle vérification dans {secondes} s.", secondes=round(pause)) if etat != "FINISHED" and not dispo else ""))
            for c in dispo:
                bloc = self._appel("GET", f"{base}/export/{uuid}/chunks/{c}")
                n = len(bloc) if isinstance(bloc, list) else 0
                recs.extend(bloc if isinstance(bloc, list) else [])
                vus.add(c)
                journal(tr("Bloc {bloc} téléchargé : {n} enregistrement(s), {total} au total.", bloc=c, n=n, total=len(recs)))
                if rappel:
                    rappel(len(recs))
            if etat == "FINISHED" and len(vus) >= len(prets):
                journal(tr("Export terminé : {total} enregistrement(s) en {secondes} s.", total=len(recs), secondes=int(time.time() - t0)))
                return recs
            if time.time() - t0 > self.delai_max:
                raise ErreurDonnees(tr("L'export de Vulnerability Management dépasse {minutes} minutes : "
                                       "limitez le périmètre (plage d'adresses) ou réessayez plus tard.", minutes=self.delai_max // 60))
            time.sleep(pause)
            pause = min(pause * 1.5, 15)

    @staticmethod
    def filtres_tags(source):
        """Filtres `tag.<catégorie>: [valeurs]` : OU entre les valeurs d'une catégorie, ET entre catégories (sémantique de l'API)."""
        return {f"tag.{cat}": vals for cat, vals in P.tags_source(source).items()}

    def tags(self):
        """Catégories de tags et leurs valeurs : [{nom, valeurs: [{nom, description}]}], triées."""
        cats, offset = {}, 0
        while True:
            rep = self._appel("GET", "tags/values", params={"limit": 1000, "offset": offset}) or {}
            vals = rep.get("values") or []
            for v in vals:
                cat = v.get("category_name") or ""
                if cat and v.get("value"):
                    cats.setdefault(cat, {})[v["value"]] = v.get("description") or ""
            offset += len(vals)
            total = int(((rep.get("pagination") or {}).get("total")) or 0)
            if not vals or offset >= total:
                break
        return [{"nom": c, "valeurs": [{"nom": n, "description": d} for n, d in sorted(v.items(), key=lambda x: x[0].lower())]}
                for c, v in sorted(cats.items(), key=lambda x: x[0].lower())]

    def decompter(self, source):
        """Nombre d'assets de la sélection (tags et plage d'adresses), d'après la liste des assets du poste de travail."""
        params = {"date_range": 90, "filter.search_type": "and"}
        filtres = [(f"tag.{c}", "set-has", ",".join(v)) for c, v in P.tags_source(source).items()]
        for i, (nom, qual, val) in enumerate(filtres):
            params.update({f"filter.{i}.filter": nom, f"filter.{i}.quality": qual, f"filter.{i}.value": val})
        rep = self._appel("GET", "workbenches/assets", params=params) or {}
        n = rep.get("total_asset_count", rep.get("total"))
        return int(n) if str(n or "").isdigit() else (len(rep["assets"]) if isinstance(rep.get("assets"), list) else None)

    @staticmethod
    def corps_vulns(source, severites=None, filtres=True):
        corps = {"num_assets": 500, "include_unlicensed": False}
        if filtres:
            f = {"state": ["open", "reopened"]}
            sev = [SEV_API[s] for s in (severites or []) if s in SEV_API]
            if sev:
                f["severity"] = sev
            if str((source or {}).get("cidr") or "").strip():
                f["cidr_range"] = str(source["cidr"]).strip()
            f.update(Client.filtres_tags(source))
            corps["filters"] = f
        return corps

    def exporter_csv(self, source, chemin, severites=None, limite=2_000_000, rappel=None, journal=None):
        """Écrit le CSV. Renvoie {lignes, secondes, avertissement}. `journal(message)` : suivi des étapes (facultatif)."""
        t0, avert = time.time(), []
        journal = journal or (lambda m: None)
        source = {**SOURCE_DEFAUT, **(source or {})}
        journal(tr("Demande d'export des vulnérabilités à {url}.", url=self.url))
        try:
            recs = self._export("vulns", self.corps_vulns(source, severites), rappel, journal)
        except ErreurDonnees as e:
            if getattr(e, "statut", None) != 400:
                raise
            if P.tags_source(source):                        # sans filtre, le périmètre choisi serait ignoré en silence
                raise ErreurDonnees(tr("Les filtres de tags ont été refusés par Vulnerability Management : {err}", err=e))
            journal(tr("Filtres refusés par Vulnerability Management : nouvel export sans filtres, le tri sera fait ici."))
            recs = self._export("vulns", self.corps_vulns(source, severites, filtres=False), rappel, journal)     # filtres refusés : tri local
            avert.append(tr("Les filtres de l'export ont été refusés par Vulnerability Management : le tri a été fait ici."))
        if len(recs) > limite:
            raise ErreurDonnees(tr("Plus de {limite} lignes : affinez la requête (plage d'adresses, sévérités).", limite=limite))
        lignes = [ligne_api(r) for r in recs]
        if not lignes:
            raise ErreurDonnees(tr("La requête n'a renvoyé aucune vulnérabilité : vérifiez la plage d'adresses et les sévérités."))
        if not any(l["definition.name"] for l in lignes):
            raise ErreurDonnees(tr("Vulnerability Management n'a renvoyé aucun nom de vulnérabilité (champs reçus : {champs}). "
                                   "Indiquez ces champs pour adapter la correspondance.", champs=", ".join(sorted(_plat(recs[0])))))
        df = pd.DataFrame(lignes)
        if str(source.get("acr_aes", "1")) == "1":
            try:
                filtres = {"cidr_range": str(source["cidr"]).strip()} if str(source.get("cidr") or "").strip() else {}
                filtres.update(self.filtres_tags(source))
                journal(tr("Demande d'export des assets (notes ACR et AES)."))
                notes = notes_assets(self._export("assets/v2", {"chunk_size": 1000, **({"filters": filtres} if filtres else {})},
                                                  journal=journal))
                df["acr"] = df["asset.id"].map(lambda a: (notes.get(str(a)) or (None, None))[0])
                df["aes"] = df["asset.id"].map(lambda a: (notes.get(str(a)) or (None, None))[1])
                if df["acr"].isna().all() and df["aes"].isna().all():
                    avert.append(tr("Aucune note ACR ou AES n'a été retrouvée pour ces machines."))
            except ErreurDonnees as e:
                journal(tr("Notes ACR et AES indisponibles : {err}", err=e))
                avert.append(tr("ACR et AES indisponibles ({err}) : le rapport est produit sans ces notes.", err=e))
        journal(tr("Conversion de {n} ligne(s) et écriture du fichier CSV.", n=len(df)))
        out = VM.convertir(df, "api")
        if severites:
            out = out[out["Severity"].isin(set(severites) | {"Info"})]
        out["Source"] = "vm"
        os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
        out.to_csv(chemin, index=False, encoding="utf-8-sig")
        return {"lignes": len(out), "total": len(recs), "secondes": round(time.time() - t0, 1), "avertissement": " ".join(avert)}
