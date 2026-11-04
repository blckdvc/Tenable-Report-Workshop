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
SOURCE_DEFAUT = {"cidr": "", "acr_aes": "1", "tags": "", "periode": "30"}   # propres à Vulnerability Management (dans la source du profil)
# Période des détections, en jours (« 0 » : toute la période). Sans filtre de date, l'export de l'API ne renvoie que les
# vulnérabilités trouvées ou corrigées dans les 30 derniers jours : une machine non rescannée depuis en disparaît.
PERIODES = ("30", "90", "180", "365", "0")


def jours_periode(source):
    v = str((source or {}).get("periode") or "30")
    return int(v) if v in PERIODES else 30
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
        if r.status_code >= 400:
            msg = (data.get("message") or data.get("error") or "") if isinstance(data, dict) else ""
            if r.status_code == 401:
                err = ErreurDonnees(tr("Clés d'API refusées par Vulnerability Management (invalides ou expirées)."))
            elif r.status_code == 403:
                err = ErreurDonnees(tr("Droits insuffisants dans Vulnerability Management pour {methode} /{chemin} (HTTP 403{msg}).",
                                       methode=methode, chemin=chemin.lstrip("/"), msg=f" : {msg}" if msg else ""))
            elif r.status_code == 429:
                err = ErreurDonnees(tr("Vulnerability Management limite les requêtes, ou un export identique est déjà en cours : "
                                       "patientez quelques minutes et réessayez."))
            else:
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

    @staticmethod
    def _params_workbench(source):
        params = {"date_range": jours_periode(source), "filter.search_type": "and"}
        filtres = [(f"tag.{c}", "set-has", ",".join(v)) for c, v in P.tags_source(source).items()]
        for i, (nom, qual, val) in enumerate(filtres):
            params.update({f"filter.{i}.filter": nom, f"filter.{i}.quality": qual, f"filter.{i}.value": val})
        return params

    def decompter(self, source):
        """Nombre d'assets de la sélection (tags et plage d'adresses), d'après la liste des assets du poste de travail."""
        rep = self._appel("GET", "workbenches/assets", params=self._params_workbench(source)) or {}
        n = rep.get("total_asset_count", rep.get("total"))
        return int(n) if str(n or "").isdigit() else (len(rep["assets"]) if isinstance(rep.get("assets"), list) else None)

    def assets_tags(self, source):
        """Identifiants des assets portant les tags de la sélection, d'après le poste de travail (5 000 assets au plus)."""
        rep = self._appel("GET", "workbenches/assets", params={**self._params_workbench(source), "limit": 5000}) or {}
        return {str(a.get("id")) for a in (rep.get("assets") or []) if isinstance(a, dict) and a.get("id")}

    def notes_acr_aes(self, source, journal):
        """{asset: (ACR, AES)}. Ordre : export des assets v2 (sans filtre : la v2 n'accepte ni tags ni plage d'adresses ;
        le rapprochement se fait par identifiant), puis liste des assets du poste de travail (5 000 au plus, mêmes tags et
        même période), puis export des assets v1. Chaque refus est noté au journal."""
        erreurs = []
        try:
            journal(tr("Demande d'export des assets (notes ACR et AES)."))
            return notes_assets(self._export("assets/v2", {"chunk_size": 1000}, journal=journal))
        except ErreurDonnees as e:
            if getattr(e, "statut", None) not in (400, 403, 404, 429):
                raise
            erreurs.append(e)
            journal(tr("Export des assets v2 refusé ({err}) : notes lues dans la liste des assets du poste de travail.", err=e))
        try:
            rep = self._appel("GET", "workbenches/assets", params={**self._params_workbench(source), "limit": 5000}) or {}
            notes = {str(a["id"]): (a.get("acr_score"), a.get("exposure_score"))
                     for a in (rep.get("assets") or []) if isinstance(a, dict) and a.get("id")}
            if any(acr is not None or aes is not None for acr, aes in notes.values()):
                journal(tr("Notes ACR et AES lues pour {n} asset(s) dans le poste de travail.", n=len(notes)))
                return notes
            journal(tr("Le poste de travail ne donne pas de notes ACR ou AES : essai avec l'export des assets v1."))
        except ErreurDonnees as e:
            erreurs.append(e)
            journal(tr("Liste des assets du poste de travail refusée ({err}) : essai avec l'export des assets v1.", err=e))
        try:
            return notes_assets(self._export("assets", {"chunk_size": 1000}, journal=journal))
        except ErreurDonnees as e:
            if erreurs and getattr(erreurs[0], "statut", None) == 403:
                raise erreurs[0]                     # le premier refus est le plus parlant (droits de la clé d'API)
            raise

    @staticmethod
    def corps_vulns(source, severites=None, filtres=True, tags=True):
        corps = {"num_assets": 500, "include_unlicensed": False}
        if filtres:
            jours = jours_periode(source)
            f = {"state": ["open", "reopened"],                  # date explicite : sans elle, l'API se limite à 30 jours
                 "last_found": int(time.time()) - jours * 86400 if jours else 1}
            sev = [SEV_API[s] for s in (severites or []) if s in SEV_API]
            if sev:
                f["severity"] = sev
            if str((source or {}).get("cidr") or "").strip():
                f["cidr_range"] = str(source["cidr"]).strip()
            if tags:
                f.update(Client.filtres_tags(source))
            corps["filters"] = f
        return corps

    def _vulns_par_tags_local(self, source, severites, rappel, journal, filtres=True):
        """Plan B quand le filtre de tags de l'export ne donne rien ou est refusé : export sans tags, puis sélection
        ici des vulnérabilités des assets portant ces tags (d'après le poste de travail)."""
        ids = self.assets_tags(source)
        journal(tr("{n} asset(s) portent ces tags selon le poste de travail de Vulnerability Management.", n=len(ids)))
        if not ids:
            return []
        recs = self._export("vulns", self.corps_vulns(source, severites, filtres=filtres, tags=False), rappel, journal)
        garde = [r for r in recs if str(_prem(_plat(r), "asset.uuid", "asset.id")) in ids]
        journal(tr("{garde} enregistrement(s) sur {total} concernent ces assets.", garde=len(garde), total=len(recs)))
        return garde

    def exporter_csv(self, source, chemin, severites=None, limite=2_000_000, rappel=None, journal=None):
        """Écrit le CSV. Renvoie {lignes, secondes, avertissement}. `journal(message)` : suivi des étapes (facultatif)."""
        t0, avert = time.time(), []
        journal = journal or (lambda m: None)
        source = {**SOURCE_DEFAUT, **(source or {})}
        journal(tr("Demande d'export des vulnérabilités à {url}.", url=self.url))
        tags = P.tags_source(source)
        jours = jours_periode(source)
        journal(tr("Période : vulnérabilités vues depuis {jours} jours.", jours=jours) if jours
                else tr("Période : toutes les vulnérabilités, quelle que soit la date du dernier scan."))
        if tags:
            journal(tr("Filtre de tags : {tags}.", tags=" ; ".join(f"{c} = {' | '.join(v)}" for c, v in tags.items())))
        try:
            recs = self._export("vulns", self.corps_vulns(source, severites), rappel, journal)
            if not recs and tags:
                journal(tr("Aucun résultat avec le filtre de tags de l'export : recherche des assets portant ces tags."))
                recs = self._vulns_par_tags_local(source, severites, rappel, journal)
                if recs:
                    avert.append(tr("Le filtre de tags de l'export n'a rien renvoyé : la sélection par tags a été faite ici."))
        except ErreurDonnees as e:
            if getattr(e, "statut", None) != 400:
                raise
            journal(tr("Filtres refusés par Vulnerability Management : nouvel export sans filtres, le tri sera fait ici."))
            if tags:                                         # le périmètre choisi n'est jamais ignoré en silence
                recs = self._vulns_par_tags_local(source, severites, rappel, journal, filtres=False)
            else:
                recs = self._export("vulns", self.corps_vulns(source, severites, filtres=False), rappel, journal)
            avert.append(tr("Les filtres de l'export ont été refusés par Vulnerability Management : le tri a été fait ici."))
        if len(recs) > limite:
            raise ErreurDonnees(tr("Plus de {limite} lignes : affinez la requête (plage d'adresses, sévérités).", limite=limite))
        lignes = [ligne_api(r) for r in recs]
        if not lignes and tags:
            raise ErreurDonnees(tr("Aucune vulnérabilité ouverte sur les assets portant ces tags ({tags}), aux sévérités demandées. "
                                   "Le journal de la récupération détaille chaque étape.",
                                   tags=" ; ".join(f"{c} = {' | '.join(v)}" for c, v in tags.items()))
                                + (" " + tr("Période actuelle : {jours} derniers jours. Si ces machines n'ont pas été rescannées depuis, "
                                            "élargissez la « Période des détections » (onglet Configuration).", jours=jours) if jours else ""))
        if not lignes:
            raise ErreurDonnees(tr("La requête n'a renvoyé aucune vulnérabilité : vérifiez la plage d'adresses et les sévérités."))
        if not any(l["definition.name"] for l in lignes):
            raise ErreurDonnees(tr("Vulnerability Management n'a renvoyé aucun nom de vulnérabilité (champs reçus : {champs}). "
                                   "Indiquez ces champs pour adapter la correspondance.", champs=", ".join(sorted(_plat(recs[0])))))
        df = pd.DataFrame(lignes)
        if str(source.get("acr_aes", "1")) == "1":
            try:
                notes = self.notes_acr_aes(source, journal)
                df["acr"] = df["asset.id"].map(lambda a: (notes.get(str(a)) or (None, None))[0])
                df["aes"] = df["asset.id"].map(lambda a: (notes.get(str(a)) or (None, None))[1])
                if df["acr"].isna().all() and df["aes"].isna().all():
                    avert.append(tr("Aucune note ACR ou AES n'a été retrouvée pour ces machines."))
            except ErreurDonnees as e:
                journal(tr("Notes ACR et AES indisponibles : {err}", err=e))
                avert.append(tr("ACR et AES indisponibles ({err}) : le rapport est produit sans ces notes.", err=e)
                             + (" " + tr("L'export des assets demande le rôle Basic avec la permission « Can View » sur les assets "
                                         "(objet « All Assets »), ou le rôle Administrator ; les notes demandent aussi une licence "
                                         "Tenable One ou Lumin.") if getattr(e, "statut", None) == 403 else ""))
        journal(tr("Conversion de {n} ligne(s) et écriture du fichier CSV.", n=len(df)))
        out = VM.convertir(df, "api")
        if severites:
            out = out[out["Severity"].isin(set(severites) | {"Info"})]
        out["Source"] = "vm"
        os.makedirs(os.path.dirname(os.path.abspath(chemin)), exist_ok=True)
        out.to_csv(chemin, index=False, encoding="utf-8-sig")
        return {"lignes": len(out), "total": len(recs), "secondes": round(time.time() - t0, 1), "avertissement": " ".join(avert)}
