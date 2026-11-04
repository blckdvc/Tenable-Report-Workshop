#!/usr/bin/env python3
"""Atelier de rapports Tenable : application locale (http://127.0.0.1) pour configurer et générer les rapports.

Lancement :  python app.py            (ouvre le navigateur)
             python app.py --port 8800 --sans-navigateur
Les exports et les rapports restent sur ce poste : le serveur n'écoute que sur 127.0.0.1.
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import unicodedata
import uuid
import webbrowser

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from moteur import charte as CH
from moteur import config as CFG
from moteur import courriel as MAIL
from moteur import portee as PT
from moteur import regles as R
from moteur import i18n
from moteur import exemple as EX
from moteur.i18n import tr, plur
from moteur import securitycenter as SC
from moteur import vulnmanagement as VMC
from moteur.analyse import PERIMETRE_DEFAUT, Analyse
from moteur.commun import HABILLAGE_DEFAUT
from moteur.modeles import MODELES, perimetre_pour

RACINE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(RACINE, "web")
PROFILS = os.path.join(RACINE, "profils")
RAPPORTS = os.path.join(RACINE, "rapports")
EXPORTS_SC = os.path.join(RACINE, "exports_security_center")     # CSV récupérés via l'API, conservés pour les comparaisons
SESSION = tempfile.mkdtemp(prefix="atelier_")
os.makedirs(PROFILS, exist_ok=True)
os.makedirs(RAPPORTS, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024        # exports volumineux acceptés
MAIL_DEFAUT = {
    "destinataires": "",
    "objet": "{titre} - {client}",
    "message": "Bonjour,\n\nVeuillez trouver ci-joint le rapport « {titre} » du {date}.\n\nCordialement",
}
EXPORTS = {}                                                 # id -> {chemin, nom, taille}
VERROU = threading.Lock()


# ---------------------------------------------------------------------------- langue
HOTES_LOCAUX = {"127.0.0.1", "localhost", "[::1]", "::1"}


@app.before_request
def _garde_locale():
    """Application locale : refuse les requêtes dont l'hôte n'est pas local (DNS rebinding) ou dont l'origine
    est un autre site (CSRF : une page web ouverte dans le navigateur ne doit pas pouvoir piloter l'application)."""
    from urllib.parse import urlsplit
    if (request.host or "").rsplit(":", 1)[0] not in HOTES_LOCAUX and (request.host or "") not in HOTES_LOCAUX:
        abort(403)
    origine = request.headers.get("Origin")
    if origine and request.method not in ("GET", "HEAD", "OPTIONS") and origine != "null":
        if (urlsplit(origine).hostname or "") not in {"127.0.0.1", "localhost", "::1"}:
            abort(403)
    elif origine == "null" and request.method not in ("GET", "HEAD", "OPTIONS"):
        abort(403)


@app.before_request
def _langue_requete():
    """Langue de la requête : en-tête X-Langue envoyé par l'interface (sinon français)."""
    i18n.set_langue(request.headers.get("X-Langue") or request.args.get("langue") or i18n.DEFAUT)


def defauts_langue(code):
    """Textes par défaut (titre, pied de page, message du courriel) dans la langue `code`."""
    avant = i18n.langue()
    i18n.set_langue(code)
    try:
        return {"titre": tr("Rapport de vulnérabilités"), "pied": tr("Données issues de Tenable Security Center"),
                "objet": "{titre} - {client}",
                "message": tr("Bonjour,\n\nVeuillez trouver ci-joint le rapport « {titre} » du {date}.\n\nCordialement")}
    finally:
        i18n.set_langue(avant)


@app.get("/api/langues")
def api_langues():
    return jsonify(i18n.LANGUES)


# ---------------------------------------------------------------------------- outils
def slug(texte, defaut="profil"):
    t = unicodedata.normalize("NFKD", texte or "").encode("ascii", "ignore").decode()
    t = re.sub(r"[^A-Za-z0-9]+", "-", t).strip("-").lower()
    return t[:60] or defaut


def corps_json():
    """Corps JSON de la requête, toujours un objet (une liste, un nombre ou un corps vide donnent {})."""
    d = request.get_json(force=True, silent=True)
    return d if isinstance(d, dict) else {}


def erreur(message, code=400):
    return jsonify({"erreur": message}), code


@app.errorhandler(R.ErreurDonnees)
def _erreur_donnees(e):
    return erreur(str(e))


@app.errorhandler(Exception)
def _erreur_inattendue(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Erreur non prévue")
    return erreur(tr("Erreur inattendue : {err}", err=e), 500)


@app.errorhandler(413)
def _trop_gros(e):
    return erreur(tr("Fichier trop volumineux (512 Mo maximum)."), 413)


# ---------------------------------------------------------------------------- profils clients
def _chemin_profil(pid):
    if not re.fullmatch(r"[a-z0-9-]+", pid or ""):
        abort(404)
    return os.path.join(PROFILS, f"{pid}.json")


SOURCE_DEFAUT = {**SC.SOURCE_DEFAUT, "produit": "sc", **VMC.SOURCE_DEFAUT}     # « sc » : Security Center, « vm » : Vulnerability Management


def lire_profil(pid):
    chemin = _chemin_profil(pid)
    if not os.path.exists(chemin):
        abort(404)
    with open(chemin, encoding="utf-8") as f:
        p = json.load(f)
    p["id"] = pid
    p["habillage"] = {**HABILLAGE_DEFAUT, **p.get("habillage", {})}
    p["perimetre"] = {**PERIMETRE_DEFAUT, **p.get("perimetre", {})}
    p["source"] = {**SOURCE_DEFAUT, **p.get("source", {})}
    p.setdefault("modele", "complet")
    p["langue"] = i18n.valide(p.get("langue"))
    p["mail"] = {**MAIL_DEFAUT, "message": defauts_langue(p["langue"])["message"], **p.get("mail", {})}
    return p


def ecrire_profil(p):
    data = {k: p[k] for k in ("nom", "langue", "habillage", "perimetre", "modele", "source", "mail") if k in p}
    data["modifie"] = datetime.datetime.now().isoformat(timespec="seconds")
    with open(_chemin_profil(p["id"]), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def creer_profil(nom, base=None, langue=None):
    pid = slug(nom)
    i = 2
    while os.path.exists(os.path.join(PROFILS, f"{pid}.json")):
        pid = f"{slug(nom)}-{i}"
        i += 1
    p = {"id": pid, "nom": nom, "habillage": dict(HABILLAGE_DEFAUT), "perimetre": dict(PERIMETRE_DEFAUT), "modele": "complet",
         "source": dict(SOURCE_DEFAUT), "mail": dict(MAIL_DEFAUT), "langue": i18n.valide(langue or i18n.langue())}
    dl = defauts_langue(p["langue"])
    p["habillage"].update({"titre": dl["titre"], "pied": dl["pied"]})
    p["mail"]["message"] = dl["message"]
    if base:
        p.update({k: json.loads(json.dumps(base[k])) for k in ("habillage", "perimetre", "modele", "source", "mail", "langue")})
        logo = base["habillage"].get("logo")
        if logo and os.path.exists(os.path.join(PROFILS, logo)):
            nouveau = f"{pid}_logo{os.path.splitext(logo)[1]}"
            shutil.copyfile(os.path.join(PROFILS, logo), os.path.join(PROFILS, nouveau))
            p["habillage"]["logo"] = nouveau
    ecrire_profil(p)
    return lire_profil(pid)


def habillage_effectif(p):
    h = dict(p["habillage"])
    dl = defauts_langue("fr")                 # textes par défaut enregistrés en français : suivent la langue courante
    for cle in ("titre", "pied"):
        if h.get(cle) == dl[cle]:
            h[cle] = defauts_langue(i18n.langue())[cle]
    h["logo"] = os.path.join(PROFILS, h["logo"]) if h.get("logo") else None
    return CH.appliquer(h)                    # thème de l'application (Atelier ou Tenable)


if not any(f.endswith(".json") for f in os.listdir(PROFILS)):
    creer_profil("Profil par défaut")


@app.get("/api/profils")
def api_profils():
    out = []
    for f in sorted(os.listdir(PROFILS)):
        if f.endswith(".json"):
            p = lire_profil(f[:-5])
            out.append({"id": p["id"], "nom": p.get("nom") or p["id"], "client": p["habillage"].get("client", ""),
                        "langue": p["langue"]})
    return jsonify(sorted(out, key=lambda x: x["nom"].lower()))


@app.get("/api/profils/<pid>")
def api_profil(pid):
    return jsonify(lire_profil(pid))


@app.post("/api/profils")
def api_profil_creer():
    d = corps_json()
    nom = str(d.get("nom") or "").strip()
    if not nom:
        return erreur(tr("Donnez un nom au profil."))
    base = lire_profil(d["copier"]) if d.get("copier") else None
    return jsonify(creer_profil(nom, base, d.get("langue")))


@app.put("/api/profils/<pid>")
def api_profil_maj(pid):
    p = lire_profil(pid)
    d = corps_json()
    if isinstance(d.get("nom"), str) and d["nom"].strip():
        p["nom"] = d["nom"].strip()
    if d.get("langue") and i18n.valide(d["langue"]) != p["langue"]:
        # les textes laissés à leur valeur par défaut suivent la nouvelle langue ; les textes personnalisés restent intacts
        ancien, nouveau = defauts_langue(p["langue"]), defauts_langue(i18n.valide(d["langue"]))
        for cle in ("titre", "pied"):
            if p["habillage"].get(cle) == ancien[cle]:
                p["habillage"][cle] = nouveau[cle]
        if p["mail"].get("message") == ancien["message"]:
            p["mail"]["message"] = nouveau["message"]
        p["langue"] = i18n.valide(d["langue"])
    if "habillage" in d:
        logo = p["habillage"].get("logo")
        p["habillage"].update({k: v for k, v in d["habillage"].items() if k in HABILLAGE_DEFAUT and k != "logo"})
        p["habillage"]["logo"] = logo
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", p["habillage"].get("couleur") or ""):
            return erreur(tr("Couleur invalide : utilisez le format #RRGGBB."))
    if "perimetre" in d:
        per = {**p["perimetre"], **{k: v for k, v in d["perimetre"].items() if k in PERIMETRE_DEFAUT}}
        per["severites"] = [s for s in per.get("severites", []) if s in ("Critical", "High", "Medium", "Low")]
        if not per["severites"]:
            return erreur(tr("Retenez au moins une sévérité."))
        try:
            per["top"] = max(1, min(100, int(per.get("top") or 20)))
        except (TypeError, ValueError):
            return erreur(tr("Le nombre de solutions doit être un entier."))
        per["ponderation"] = per.get("ponderation") if per.get("ponderation") in ("severite", "vpr", "vpr_acr") else "severite"
        p["perimetre"] = per
    if "source" in d:
        src = {**p["source"], **{k: str(v or "").strip() for k, v in d["source"].items() if k in SOURCE_DEFAUT}}
        for k in ("repositories", "asset_list", "query_id"):
            if not re.fullmatch(r"[0-9, ;]*", src[k]):
                return erreur(tr("Les identifiants Security Center sont numériques (séparés par des virgules)."))
        if src["produit"] not in ("sc", "vm"):
            return erreur(tr("Produit inconnu."))
        if not re.fullmatch(r"[0-9a-fA-F:.,/; -]*", src["cidr"]) or src["acr_aes"] not in ("0", "1"):
            return erreur(tr("Plage d'adresses invalide (exemple : 10.0.0.0/24, 10.1.0.0/16)."))
        if src["outil"] not in SC.OUTILS or src["source_type"] not in ("cumulative", "patched"):
            return erreur(tr("Outil ou type de source inconnu."))
        SC.Client.filtres(src)                                  # valide le JSON des filtres supplémentaires
        try:                                                    # sélection du périmètre : formes et tailles
            for k in ("asset_noms", "tags"):
                if src[k] and not isinstance(json.loads(src[k]), dict):
                    raise ValueError
            PT.depuis_selection({"listes": PT.ids_listes(src), "tags": PT.tags_source(src)})
        except ValueError:
            return erreur(tr("Sélection du périmètre invalide."))
        p["source"] = src
    if "mail" in d:
        m = {**p["mail"], **{k: str(v or "") for k, v in d["mail"].items() if k in MAIL_DEFAUT}}
        MAIL.adresses(m["destinataires"])                       # refuse une adresse mal formée
        p["mail"] = m
    if d.get("modele") in MODELES:
        p["modele"] = d["modele"]
    ecrire_profil(p)
    return jsonify(lire_profil(pid))


@app.delete("/api/profils/<pid>")
def api_profil_supprimer(pid):
    p = lire_profil(pid)
    restants = [f for f in os.listdir(PROFILS) if f.endswith(".json") and f != f"{pid}.json"]
    if not restants:
        return erreur(tr("Impossible de supprimer le dernier profil."))
    if p["habillage"].get("logo"):
        try:
            os.remove(os.path.join(PROFILS, p["habillage"]["logo"]))
        except OSError:
            pass
    os.remove(_chemin_profil(pid))
    return jsonify({"ok": True})


@app.post("/api/profils/<pid>/logo")
def api_logo(pid):
    p = lire_profil(pid)
    f = request.files.get("fichier")
    if not f:
        return erreur(tr("Aucun fichier reçu."))
    ext = os.path.splitext(f.filename or "")[1].lower()
    if ext not in (".png", ".jpg", ".jpeg"):
        return erreur(tr("Le logo doit être une image PNG ou JPG."))
    nom = f"{pid}_logo{ext}"
    chemin = os.path.join(PROFILS, nom)
    f.save(chemin)
    try:
        from PIL import Image
        Image.open(chemin).verify()
    except Exception:
        os.remove(chemin)
        return erreur(tr("Image illisible."))
    ancien = p["habillage"].get("logo")
    if ancien and ancien != nom:
        try:
            os.remove(os.path.join(PROFILS, ancien))
        except OSError:
            pass
    p["habillage"]["logo"] = nom
    ecrire_profil(p)
    return jsonify(lire_profil(pid))


@app.delete("/api/profils/<pid>/logo")
def api_logo_supprimer(pid):
    p = lire_profil(pid)
    if p["habillage"].get("logo"):
        try:
            os.remove(os.path.join(PROFILS, p["habillage"]["logo"]))
        except OSError:
            pass
    p["habillage"]["logo"] = None
    ecrire_profil(p)
    return jsonify(lire_profil(pid))


@app.get("/api/profils/<pid>/logo")
def api_logo_voir(pid):
    p = lire_profil(pid)
    if not p["habillage"].get("logo"):
        abort(404)
    from moteur.commun import preparer_logo          # même recadrage que dans les rapports
    chemin, _ = preparer_logo(os.path.join(PROFILS, p["habillage"]["logo"]), tempfile.mkdtemp(dir=SESSION))
    return send_file(chemin, mimetype="image/png", max_age=0)


# ---------------------------------------------------------------------------- exports
@app.post("/api/exports")
def api_export_ajouter():
    f = request.files.get("fichier")
    if not f or not f.filename:
        return erreur(tr("Aucun fichier reçu."))
    eid = uuid.uuid4().hex[:12]
    chemin = os.path.join(SESSION, f"{eid}.csv")
    f.save(chemin)
    try:
        R.read_export(chemin)
    except R.ErreurDonnees:
        os.remove(chemin)
        raise
    EXPORTS[eid] = {"chemin": chemin, "nom": os.path.basename(f.filename), "taille": os.path.getsize(chemin)}
    return jsonify({"id": eid, "nom": EXPORTS[eid]["nom"], "taille": EXPORTS[eid]["taille"]})


def _export(eid):
    if eid not in EXPORTS:
        raise R.ErreurDonnees(tr("Export introuvable : rechargez le fichier CSV."))
    return EXPORTS[eid]


@app.get("/api/exports/<eid>/apercu")
def api_apercu(eid):
    e = _export(eid)
    per = lire_profil(request.args["profil"])["perimetre"] if request.args.get("profil") else None
    return jsonify(Analyse(e["chemin"], per, nom_fichier=e["nom"], portee=e.get("portee")).resume())


@app.delete("/api/exports/<eid>")
def api_export_supprimer(eid):
    e = EXPORTS.pop(eid, None)
    if e and not e.get("conserve"):
        try:
            os.remove(e["chemin"])
        except OSError:
            pass
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------- génération
@app.get("/api/modeles")
def api_modeles():
    return jsonify([{"id": k, "nom": tr(m["nom"]), "description": tr(m["description"]), "format": m["format"],
                     "exports": m["exports"]} for k, m in MODELES.items()])


@app.post("/api/generer")
def api_generer():
    d = corps_json()
    modele = MODELES.get(d.get("modele"))
    if not modele:
        return erreur(tr("Modèle inconnu."))
    p = lire_profil(d.get("profil") or "")
    i18n.set_langue(p["langue"])              # le rapport est produit dans la langue du profil
    hab = habillage_effectif(p)
    regles = R.load_rules()
    if modele["exports"] == 2:
        if not d.get("export") or not d.get("export2"):
            return erreur(tr("La comparaison demande deux exports : le précédent et le récent."))
        e1, e2 = _export(d["export"]), _export(d["export2"])
        per = perimetre_pour(modele, p["perimetre"])
        a1 = Analyse(e1["chemin"], per, regles, nom_fichier=e1["nom"], portee=e1.get("portee"))
        a2 = Analyse(e2["chemin"], per, regles, nom_fichier=e2["nom"], portee=e2.get("portee"))
        base = os.path.splitext(e2["nom"])[0]
    else:
        e1 = _export(d.get("export"))
        a1, a2 = Analyse(e1["chemin"], perimetre_pour(modele, p["perimetre"]), regles, nom_fichier=e1["nom"], portee=e1.get("portee")), None
        base = os.path.splitext(e1["nom"])[0]
    horo = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    nom = f"{slug(p['nom'])}_{d['modele']}_{slug(base, 'export')}_{horo}.{modele['format']}"
    sortie = os.path.join(RAPPORTS, nom)
    with VERROU:                              # reportlab / matplotlib : une génération à la fois
        if a2 is not None:
            modele["module"].generer(a1, a2, hab, sortie)
        else:
            modele["module"].generer(a1, hab, sortie)
    res = {"fichier": nom, "taille": os.path.getsize(sortie), "dossier": RAPPORTS,
           "url": f"/api/rapports/{nom}", "modele": tr(modele["nom"]), "profil": p["nom"],
           "sans_regle": len(a1.sans_regle)}
    if a2 is not None and (a1.portee or a2.portee) and not PT.identique(a1.portee, a2.portee):
        res["avertissement"] = tr("Les deux exports n'ont pas le même périmètre : la comparaison porte sur des machines différentes.")
    if d.get("envoyer"):                      # envoi optionnel : un échec n'invalide pas le rapport généré
        try:
            res["mail"] = {"ok": True, **_envoyer_rapport(nom, p, d)}
        except R.ErreurDonnees as e:
            res["mail"] = {"ok": False, "erreur": str(e)}
    return jsonify(res)


@app.get("/api/rapports")
def api_rapports():
    out = []
    for f in sorted((x for x in os.listdir(RAPPORTS) if not x.startswith(".") and x.lower().endswith((".pdf", ".xlsx"))), key=lambda x: os.path.getmtime(os.path.join(RAPPORTS, x)), reverse=True)[:30]:
        c = os.path.join(RAPPORTS, f)
        out.append({"fichier": f, "taille": os.path.getsize(c), "url": f"/api/rapports/{f}",
                    "date": datetime.datetime.fromtimestamp(os.path.getmtime(c)).strftime(tr("%d/%m/%Y %H:%M"))})
    return jsonify({"dossier": RAPPORTS, "rapports": out})


@app.get("/api/rapports/<path:nom>")
def api_rapport(nom):
    if "/" in nom or "\\" in nom or nom.startswith("."):
        abort(404)
    return send_from_directory(RAPPORTS, nom, as_attachment=request.args.get("telecharger") == "1")


# ---------------------------------------------------------------------------- configuration (Security Center, SMTP)
@app.get("/api/config")
def api_config():
    return jsonify(CFG.vue_publique())


@app.get("/api/theme")
def api_theme():
    return jsonify({"theme": CH.theme_actif(), "themes": list(CH.THEMES)})


@app.put("/api/theme")
def api_theme_maj():
    t = (corps_json().get("theme") or "").strip()
    if t not in CH.THEMES:
        return erreur(tr("Thème inconnu."))
    CH.definir_theme(t)
    return jsonify({"theme": t})


@app.put("/api/config")
def api_config_maj():
    d = corps_json()
    d = {k: v for k, v in d.items() if isinstance(v, dict)}   # sections attendues : des objets
    sc = d.get("securitycenter") or {}
    if sc.get("url") and not re.match(r"^(https?://)?[\w.-]+(:\d+)?(/.*)?$", sc["url"].strip()):
        return erreur(tr("Adresse de Security Center invalide (exemple : https://securitycenter.exemple.fr)."))
    vm = d.get("vulnmanagement") or {}
    if vm.get("url") and not re.match(r"^(https?://)?[\w.-]+(:\d+)?(/.*)?$", vm["url"].strip()):
        return erreur(tr("Adresse de Vulnerability Management invalide (exemple : https://cloud.tenable.com)."))
    CFG.ecrire(d)
    return jsonify(CFG.vue_publique())


def _cfg_section(section):
    """Configuration enregistrée, surchargée par les champs en cours de saisie (secret vide = valeur enregistrée)."""
    cfg = CFG.lire()[section]
    saisie = corps_json().get(section)
    saisie = saisie if isinstance(saisie, dict) else {}
    for k, v in saisie.items():
        if k in cfg and not (k in CFG.SECRETS[section] and not v):
            cfg[k] = v
    return cfg


@app.post("/api/securitycenter/tester")
def api_sc_tester():
    return jsonify(SC.Client(_cfg_section("securitycenter")).tester())


@app.post("/api/vm/tester")
def api_vm_tester():
    return jsonify(VMC.Client(_cfg_section("vulnmanagement")).tester())


@app.get("/api/vm/requete")
def api_vm_requete():
    p = lire_profil(request.args.get("profil") or "")
    return jsonify(VMC.Client.corps_vulns(p["source"], p["perimetre"].get("severites")))


@app.get("/api/securitycenter/listes")
def api_sc_listes():
    c = SC.Client(CFG.lire()["securitycenter"])
    return jsonify({"repositories": c.repositories(), "listes_actifs": c.listes_actifs(), "requetes": c.requetes()})


@app.get("/api/vm/tags")
def api_vm_tags():
    return jsonify({"categories": VMC.Client(CFG.lire()["vulnmanagement"]).tags()})


@app.post("/api/perimetre/decompte")
def api_perimetre_decompte():
    """Nombre de machines de la sélection, avant de lancer l'export. Un échec du décompte ne bloque rien."""
    d = corps_json()
    p = lire_profil(d.get("profil") or "")
    try:
        src = {**p["source"], **PT.depuis_selection(d.get("selection"))}
    except ValueError:
        return erreur(tr("Sélection du périmètre invalide."))
    try:
        vm = src.get("produit") == "vm"
        client = VMC.Client(CFG.lire()["vulnmanagement"]) if vm else SC.Client(CFG.lire()["securitycenter"])
        return jsonify({"machines": client.decompter(src)})
    except R.ErreurDonnees as e:
        return jsonify({"machines": None, "erreur": str(e)})


@app.get("/api/securitycenter/requete")
def api_sc_requete():
    """Corps JSON exact envoyé à POST /rest/analysis pour la première page, pour le vérifier ou le rejouer."""
    p = lire_profil(request.args.get("profil", ""))
    return jsonify(SC.Client.corps(p["source"], 0, 1000, p["perimetre"].get("severites")))


@app.post("/api/securitycenter/exporter")
def api_sc_exporter():
    d = corps_json()
    p = lire_profil(d.get("profil") or "")
    if d.get("selection") is not None:                          # périmètre choisi pour cette génération seulement : le profil n'est pas modifié
        try:
            p["source"] = {**p["source"], **PT.depuis_selection(d["selection"])}
        except ValueError:
            return erreur(tr("Sélection du périmètre invalide."))
    vm = p["source"].get("produit") == "vm"                     # le produit est un réglage du profil
    client = VMC.Client(CFG.lire()["vulnmanagement"]) if vm else SC.Client(CFG.lire()["securitycenter"])
    os.makedirs(EXPORTS_SC, exist_ok=True)
    nom = f"{slug(p['nom'])}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    chemin = os.path.join(EXPORTS_SC, nom)
    try:
        mod = MODELES.get(d.get("modele") or "", {})
        res = client.exporter_csv(p["source"], chemin, perimetre_pour(mod, p["perimetre"]).get("severites"))
        R.read_export(chemin)                                    # même contrôle que pour un fichier déposé
    except Exception:
        if os.path.exists(chemin):
            os.remove(chemin)
        raise
    eid = uuid.uuid4().hex[:12]
    EXPORTS[eid] = {"chemin": chemin, "nom": nom, "taille": os.path.getsize(chemin), "conserve": True, "portee": PT.portee(p["source"])}
    return jsonify({"id": eid, "nom": nom, "taille": EXPORTS[eid]["taille"], "dossier": EXPORTS_SC, "portee": EXPORTS[eid]["portee"], **res})


@app.post("/api/smtp/tester")
def api_smtp_tester():
    return jsonify(MAIL.tester(_cfg_section("smtp")))


def _gabarit(texte, valeurs):
    for k, v in valeurs.items():
        texte = texte.replace("{" + k + "}", v)
    return texte


def _envoyer_rapport(nom, p, d):
    avant = i18n.langue()
    i18n.set_langue(p["langue"])              # titre par défaut et format de date : langue du profil
    try:
        val = {"titre": p["habillage"].get("titre") or tr("Rapport de vulnérabilités"),
               "client": p["habillage"].get("client") or p["nom"],
               "date": datetime.date.today().strftime(tr("%d/%m/%Y")), "fichier": nom}
    finally:
        i18n.set_langue(avant)
    objet = _gabarit(d.get("objet") or p["mail"]["objet"], val).strip(" -")
    corps = _gabarit(d.get("message") or p["mail"]["message"], val)
    envoyes = MAIL.envoyer(CFG.lire()["smtp"], d.get("destinataires") or p["mail"]["destinataires"], objet, corps,
                           [os.path.join(RAPPORTS, nom)])
    return {"destinataires": envoyes, "objet": objet}


@app.post("/api/rapports/<path:nom>/envoyer")
def api_rapport_envoyer(nom):
    if "/" in nom or "\\" in nom or nom.startswith(".") or not os.path.isfile(os.path.join(RAPPORTS, nom)):
        abort(404)
    d = corps_json()
    return jsonify({"ok": True, **_envoyer_rapport(nom, lire_profil(d.get("profil") or ""), d)})


# ---------------------------------------------------------------------------- exemples de rapports (données fictives)
EXEMPLES = os.path.join(SESSION, "exemples")


@app.get("/api/modeles/<mid>/exemple")
def api_exemple(mid):
    """Rapport d'exemple (données fictives, habillage et langue du profil) : pages en images, ou feuilles pour Excel."""
    modele = MODELES.get(mid)
    if not modele:
        return erreur(tr("Modèle inconnu."))
    p = lire_profil(request.args.get("profil") or "")
    i18n.set_langue(p["langue"])
    hab = habillage_effectif(p)
    logo = hab.get("logo")
    cle = EX.cle_apercu(mid, {k: v for k, v in hab.items() if k != "logo"}, p["perimetre"], p["langue"],
                        os.path.getmtime(logo) if logo and os.path.exists(logo) else 0)
    dossier = os.path.join(EXEMPLES, cle)
    meta = os.path.join(dossier, "meta.json")
    with VERROU:                                           # reportlab / matplotlib : une génération à la fois
        if not os.path.exists(meta):
            os.makedirs(dossier, exist_ok=True)
            fichier, an = EX.produire(mid, modele, hab, dossier)
            info = {"format": modele["format"], "fichier": os.path.basename(fichier)}
            if modele["format"] == "xlsx":
                info["feuilles"] = EX.feuilles_excel(fichier, an, hab.get("couleur") or "#000091")
            else:
                try:
                    info["pages"] = EX.pages_pdf(fichier, dossier)
                except ImportError:
                    info["sans_images"] = True
            with open(meta, "w", encoding="utf-8") as f:
                json.dump(info, f, ensure_ascii=False)
    with open(meta, encoding="utf-8") as f:
        info = json.load(f)
    rep = {"cle": cle, "format": info["format"], "modele": tr(modele["nom"]), "profil": p["nom"], "langue": p["langue"],
           "fichier": f"/api/exemples/{cle}/{info['fichier']}"}
    if "feuilles" in info:
        rep["feuilles"] = info["feuilles"]
    elif info.get("sans_images"):
        rep["sans_images"] = tr("L'aperçu en images demande la bibliothèque « pypdfium2 » : exécutez « .venv/bin/python -m pip install -r requirements.txt » "
                                "(Windows : .venv\\Scripts\\python.exe), puis relancez. Le PDF d'exemple reste consultable.")
    else:
        rep["pages"] = [{**pg, "url": f"/api/exemples/{cle}/page-{pg['n']}.png"} for pg in info["pages"]]
    return jsonify(rep)


@app.get("/api/exemples/<cle>/<nom>")
def api_exemple_fichier(cle, nom):
    if not re.fullmatch(r"[0-9a-f]{16}", cle) or not re.fullmatch(r"(page-\d+\.png|exemple\.(pdf|xlsx))", nom):
        abort(404)
    chemin = os.path.join(EXEMPLES, cle, nom)
    if not os.path.isfile(chemin):
        abort(404)
    m = re.fullmatch(r"page-(\d+)\.png", nom)
    dpi = request.args.get("dpi", type=int)
    if m and dpi and dpi != 75:                            # version agrandie, produite à la demande
        dpi = max(50, min(dpi, 200))
        grand = os.path.join(EXEMPLES, cle, f"page-{m.group(1)}-{dpi}.png")
        if not os.path.exists(grand):
            EX.rendre_page(os.path.join(EXEMPLES, cle, "exemple.pdf"), int(m.group(1)), dpi).save(grand)
        chemin = grand
    rep = send_file(chemin, mimetype="image/png" if nom.endswith(".png") else None, as_attachment=False)
    rep.headers["Cache-Control"] = "max-age=600"
    return rep


# ---------------------------------------------------------------------------- règles
@app.get("/api/regles")
def api_regles():
    return jsonify(R.lire_regles_brutes())


@app.put("/api/regles")
def api_regles_maj():
    lignes = request.get_json(force=True)
    if not isinstance(lignes, list):
        return erreur(tr("Format invalide."))
    R.ecrire_regles(lignes)
    return jsonify({"ok": True, "nombre": len(lignes)})


@app.post("/api/regles/tester")
def api_regles_tester():
    d = corps_json()
    lignes = d.get("regles")
    if lignes is not None:                         # tester les règles en cours d'édition, non enregistrées
        tmp = os.path.join(SESSION, "regles_test.csv")
        R.ecrire_regles(lignes, tmp)
        regles = R.load_rules(tmp)
    else:
        regles = R.load_rules()
    res = []
    for nom in [x.strip() for x in (d.get("intitules") or "").splitlines() if x.strip()][:200]:
        r = R.tester(nom, d.get("famille", ""), regles)
        res.append({"intitule": nom, **(r or {"ligne": None})})
    return jsonify(res)


@app.get("/api/regles/fichier")
def api_regles_fichier():
    tmp = os.path.join(SESSION, f"regles_{i18n.langue()}.csv")          # fichier à 6 colonnes, dans la langue courante
    R.ecrire_regles(R.lire_regles_brutes(), tmp)
    return send_file(tmp, as_attachment=True, download_name=f"regles_{i18n.langue()}.csv")


@app.post("/api/regles/fichier")
def api_regles_importer():
    f = request.files.get("fichier")
    if not f:
        return erreur(tr("Aucun fichier reçu."))
    tmp = os.path.join(SESSION, "import_regles.csv")
    f.save(tmp)
    try:
        lignes = R.lire_regles_brutes(tmp)
    except Exception as e:
        return erreur(tr("Fichier de règles illisible ({err}).", err=e))
    if not lignes:
        return erreur(tr("Le fichier ne contient aucune règle (séparateur attendu : point-virgule)."))
    R.ecrire_regles(lignes)
    return jsonify({"ok": True, "nombre": len(lignes)})


# ---------------------------------------------------------------------------- interface
@app.get("/")
def index():
    return send_from_directory(WEB, "index.html", max_age=0)


@app.get("/web/langues/<code>.json")
def catalogue_interface(code):
    """Catalogue de l'interface : fusion de web/langues/parts/*_<code>.json (clé = texte français)."""
    if code not in i18n.CODES or code == i18n.DEFAUT:
        return jsonify({})
    cat = {}
    for chemin in sorted(glob.glob(os.path.join(WEB, "langues", "parts", f"*_{code}.json"))):
        with open(chemin, encoding="utf-8") as f:
            cat.update(json.load(f))
    rep = jsonify(cat)
    rep.headers["Cache-Control"] = "no-store"
    return rep


@app.get("/web/<path:f>")
def statiques(f):
    return send_from_directory(WEB, f, max_age=0)


@app.get("/polices/<path:f>")
def polices(f):
    return send_from_directory(os.path.join(RACINE, "polices"), f)


def port_libre(depart):
    for port in range(depart, depart + 50):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise SystemExit("Aucun port libre trouvé.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Atelier de rapports Tenable (application locale).")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--sans-navigateur", action="store_true")
    args = ap.parse_args()
    port = port_libre(args.port)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n  Atelier de rapports Tenable : {url}\n  Rapports enregistrés dans : {RAPPORTS}\n  Ctrl+C pour arrêter.\n")
    import logging
    import flask.cli
    logging.getLogger("werkzeug").setLevel(logging.ERROR)          # pas de journal de requêtes dans le terminal
    flask.cli.show_server_banner = lambda *a, **k: None
    if not args.sans_navigateur:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
