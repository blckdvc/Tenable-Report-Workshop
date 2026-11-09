"""Configuration locale (config.json) : connexion à Security Center et serveur SMTP.

Le fichier est créé avec des droits restreints (lecture/écriture pour l'utilisateur seul). Les secrets
(clé secrète de l'API, mot de passe SMTP) peuvent aussi venir de variables d'environnement, qui l'emportent :

    TENABLE_SC_URL  TENABLE_SC_ACCESS_KEY  TENABLE_SC_SECRET_KEY
    TENABLE_VM_URL  TENABLE_VM_ACCESS_KEY  TENABLE_VM_SECRET_KEY
    SMTP_HOST  SMTP_USER  SMTP_PASSWORD
"""
import json
import os

from .i18n import tr

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHEMIN = os.path.join(RACINE, "config.json")

DEFAUT = {
    "securitycenter": {
        "url": "",                  # https://securitycenter.exemple.fr
        "access_key": "",
        "secret_key": "",
        "verifier_tls": True,       # False : certificat auto-signé accepté (déconseillé)
        "ca_bundle": "",            # chemin d'un certificat d'autorité (PEM) pour une PKI interne
        "taille_page": 1000,
    },
    "vulnmanagement": {
        "url": "https://cloud.tenable.com",
        "access_key": "",
        "secret_key": "",
        "verifier_tls": True,
        "ca_bundle": "",            # chemin d'un certificat (PEM), par exemple pour un proxy d'inspection TLS
    },
    "endoflife": {                  # référentiel endoflife.date : réglage propre à ce service (le proxy peut différer de celui de Tenable)
        "ca_bundle": "",            # chemin d'un certificat (PEM) du proxy d'inspection TLS qui précède endoflife.date
        "verifier_tls": True,       # False : certificat non vérifié (à réserver à un test)
    },
    "interface": {
        "theme": "atelier",         # atelier | tenable : thème de l'interface et des rapports
    },
    "smtp": {
        "hote": "",
        "port": 587,
        "securite": "starttls",     # starttls | ssl | aucune
        "utilisateur": "",
        "mot_de_passe": "",
        "expediteur": "",           # adresse d'envoi (From)
        "nom_expediteur": "Atelier de rapports",
        "verifier_tls": True,
    },
}
SECRETS = {"securitycenter": ("secret_key",), "vulnmanagement": ("secret_key",), "smtp": ("mot_de_passe",), "endoflife": ()}
ENV = {
    ("securitycenter", "url"): "TENABLE_SC_URL",
    ("securitycenter", "access_key"): "TENABLE_SC_ACCESS_KEY",
    ("securitycenter", "secret_key"): "TENABLE_SC_SECRET_KEY",
    ("vulnmanagement", "url"): "TENABLE_VM_URL",
    ("vulnmanagement", "access_key"): "TENABLE_VM_ACCESS_KEY",
    ("vulnmanagement", "secret_key"): "TENABLE_VM_SECRET_KEY",
    ("smtp", "hote"): "SMTP_HOST",
    ("smtp", "utilisateur"): "SMTP_USER",
    ("smtp", "mot_de_passe"): "SMTP_PASSWORD",
}


def chemin_fichier(valeur):
    """Chemin d'un fichier de réglage (certificat PEM) : « ~ » et variables d'environnement développés ; un chemin relatif
    se lit depuis le dossier de l'application, ce qui permet de le copier avec elle d'un poste à l'autre. Vide -> None."""
    v = str(valeur or "").strip()
    if not v:
        return None
    v = os.path.expanduser(os.path.expandvars(v))
    return v if os.path.isabs(v) else os.path.join(RACINE, v)


def verifier(section, defaut=True):
    """Valeur `verify` de requests pour une section de config : certificat d'autorité si fourni, sinon `defaut`.
    Un fichier de certificat introuvable est signalé clairement (sur un autre poste, le chemin d'origine n'existe plus)."""
    chemin = chemin_fichier((section or {}).get("ca_bundle"))
    if chemin and not os.path.isfile(chemin):
        from .regles import ErreurDonnees
        raise ErreurDonnees(tr("Certificat introuvable : {chemin}. Corrigez le chemin dans l'onglet Configuration "
                                   "(il peut être relatif au dossier de l'application ou commencer par ~).", chemin=chemin))
    return chemin or defaut


SMTP_PROFIL_DEFAUT = {                  # serveur d'envoi propre à un profil client (sans mot de passe : il reste dans config.json)
    "hote": "", "port": 587, "securite": "starttls", "utilisateur": "", "expediteur": "", "nom_expediteur": "", "verifier_tls": True,
}


def _brut():
    try:
        with open(CHEMIN, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def mot_de_passe_smtp(pid):
    """Mot de passe SMTP propre à un profil (config.json, clé « mots_de_passe_smtp »), ou « »."""
    m = _brut().get("mots_de_passe_smtp")
    return str(m.get(pid) or "") if isinstance(m, dict) else ""


def definir_mot_de_passe_smtp(pid, valeur):
    """Enregistre (ou, si `valeur` est vide, supprime) le mot de passe SMTP d'un profil. Il ne quitte jamais config.json."""
    actuel = lire(avec_env=False, traduire=False)
    m = _brut().get("mots_de_passe_smtp")
    m = dict(m) if isinstance(m, dict) else {}
    if valeur:
        m[pid] = str(valeur)
    else:
        m.pop(pid, None)
    actuel["mots_de_passe_smtp"] = m
    _ecrire_fichier(actuel)


def smtp_effectif(smtp_profil, pid):
    """Réglages SMTP à utiliser pour un profil : les siens s'il a un serveur, sinon ceux, communs, de config.json.

    Le mot de passe d'un profil vient de SMTP_PASSWORD, sinon de config.json (propre au profil) ; à défaut, celui du serveur
    commun quand l'utilisateur est le même."""
    glob = lire()["smtp"]
    ps = {**SMTP_PROFIL_DEFAUT, **(smtp_profil or {})}
    if not ps["hote"]:
        return glob
    cfg = {**glob, **{k: ps[k] for k in SMTP_PROFIL_DEFAUT}}
    if not ps["nom_expediteur"]:
        cfg["nom_expediteur"] = glob["nom_expediteur"]
    mdp = os.environ.get("SMTP_PASSWORD") or mot_de_passe_smtp(pid)
    if not mdp and ps["utilisateur"] == glob["utilisateur"]:
        mdp = glob["mot_de_passe"]
    cfg["mot_de_passe"] = mdp
    return cfg


def _fusion(base, extra):
    out = {}
    for section, valeurs in base.items():
        out[section] = {**valeurs, **{k: v for k, v in (extra.get(section) or {}).items() if k in valeurs}}
    return out


def lire(avec_env=True, traduire=True):
    """Configuration complète (secrets inclus). À ne jamais renvoyer telle quelle à l'interface."""
    brut = {}
    if os.path.exists(CHEMIN):
        try:
            with open(CHEMIN, encoding="utf-8") as f:
                brut = json.load(f)
        except (OSError, ValueError):
            brut = {}
    cfg = _fusion(DEFAUT, brut)
    if avec_env:
        for (section, cle), var in ENV.items():
            if os.environ.get(var):
                cfg[section][cle] = os.environ[var]
    if traduire and cfg["smtp"]["nom_expediteur"] == DEFAUT["smtp"]["nom_expediteur"]:
        cfg["smtp"]["nom_expediteur"] = tr("Atelier de rapports")      # nom d'expéditeur par défaut, dans la langue courante
    return cfg


def vue_publique():
    """Configuration pour l'interface : les secrets sont remplacés par un indicateur « défini »."""
    cfg = lire()
    for section, cles in SECRETS.items():
        for c in cles:
            cfg[section][c + "_defini"] = bool(cfg[section][c])
            cfg[section][c] = ""
    cfg["depuis_env"] = sorted(f"{s}.{c}" for (s, c), v in ENV.items() if os.environ.get(v))
    return cfg


def ecrire(maj):
    """Fusionne `maj` dans config.json. Un secret vide ou absent conserve la valeur enregistrée."""
    actuel = lire(avec_env=False, traduire=False)
    for section, valeurs in (maj or {}).items():
        if section not in DEFAUT or not isinstance(valeurs, dict):
            continue
        for cle, val in valeurs.items():
            if cle not in DEFAUT[section]:
                continue
            if cle in SECRETS.get(section, ()) and not val:
                continue
            modele = DEFAUT[section][cle]
            if isinstance(modele, bool):
                val = bool(val)
            elif isinstance(modele, int):
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    val = modele
            else:
                val = str(val or "").strip()
            actuel[section][cle] = val
    actuel["securitycenter"]["url"] = actuel["securitycenter"]["url"].rstrip("/")
    if isinstance(_brut().get("mots_de_passe_smtp"), dict):
        actuel["mots_de_passe_smtp"] = _brut()["mots_de_passe_smtp"]          # mots de passe propres aux profils : conservés
    _ecrire_fichier(actuel)


def _ecrire_fichier(actuel):
    tmp = CHEMIN + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(actuel, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CHEMIN)
    try:
        os.chmod(CHEMIN, 0o600)
    except OSError:
        pass                                             # Windows : droits gérés par le système
