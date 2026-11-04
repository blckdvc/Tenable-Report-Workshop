"""Envoi d'un rapport par courriel via un serveur SMTP (bibliothèque standard, aucune dépendance)."""
import mimetypes
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from .i18n import tr
from .regles import ErreurDonnees

ADRESSE = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")
TAILLE_MAX = 25 * 1024 * 1024                    # limite courante des messageries ; au-delà, le message est refusé


def adresses(texte):
    """« a@x.fr, b@y.fr » ou une adresse par ligne → liste validée, sans doublon."""
    if isinstance(texte, (list, tuple)):
        texte = "\n".join(texte)
    out, mauvaises = [], []
    for a in re.split(r"[,;\n]+", texte or ""):
        a = a.strip()
        if not a:
            continue
        if ADRESSE.match(a):
            if a.lower() not in [x.lower() for x in out]:
                out.append(a)
        else:
            mauvaises.append(a)
    if mauvaises:
        raise ErreurDonnees(tr("Adresse(s) invalide(s) : {adresses}.", adresses=", ".join(mauvaises)))
    return out


def _connexion(cfg):
    if not cfg.get("hote"):
        raise ErreurDonnees(tr("Serveur SMTP non configuré : onglet Configuration > Courriel."))
    securite = cfg.get("securite") or "starttls"
    port = int(cfg.get("port") or {"ssl": 465, "starttls": 587}.get(securite, 25))
    ctx = ssl.create_default_context()
    if not cfg.get("verifier_tls", True):
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return _connecter_ou_erreur(cfg, port, securite, ctx)


def _ouvrir(cfg, port, securite, ctx):
    s = None
    try:
        if securite == "ssl":
            s = smtplib.SMTP_SSL(cfg["hote"], port, timeout=30, context=ctx)
        else:
            s = smtplib.SMTP(cfg["hote"], port, timeout=30)
            s.ehlo()
            if securite == "starttls":
                s.starttls(context=ctx)
                s.ehlo()
        if cfg.get("utilisateur"):
            s.login(cfg["utilisateur"], cfg.get("mot_de_passe") or "")
        return s
    except Exception:
        if s is not None:                                      # connexion ouverte puis échec (STARTTLS, identifiants) : fermée
            try:
                s.close()
            except Exception:
                pass
        raise


def _connecter_ou_erreur(cfg, port, securite, ctx):
    try:
        return _ouvrir(cfg, port, securite, ctx)
    except smtplib.SMTPAuthenticationError:
        raise ErreurDonnees(tr("Identifiants SMTP refusés par le serveur."))
    except ssl.SSLError as e:
        raise ErreurDonnees(tr("Échec de la connexion sécurisée au serveur SMTP ({err}). "
                               "Vérifiez le mode de chiffrement et le port, ou le certificat du serveur.", err=e.reason or e))
    except smtplib.SMTPNotSupportedError as e:
        raise ErreurDonnees(tr("Fonction non prise en charge par le serveur SMTP : {err}", err=e))
    except (smtplib.SMTPException, OSError) as e:
        raise ErreurDonnees(tr("Serveur SMTP injoignable ou erreur de dialogue ({hote}:{port}) : {err}", hote=cfg["hote"], port=port, err=e))


def tester(cfg):
    """Ouvre une session (chiffrement et authentification compris), sans envoyer de message."""
    s = _connexion(cfg)
    try:
        s.noop()
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
    return {"hote": cfg["hote"], "securite": cfg.get("securite")}


def envoyer(cfg, destinataires, objet, corps, pieces=()):
    """Envoie `corps` (texte) et les fichiers `pieces` à `destinataires`. Renvoie la liste des destinataires."""
    dest = adresses(destinataires)
    if not dest:
        raise ErreurDonnees(tr("Indiquez au moins un destinataire."))
    exp = (cfg.get("expediteur") or cfg.get("utilisateur") or "").strip()
    if not ADRESSE.match(exp):
        raise ErreurDonnees(tr("Adresse d'expédition absente ou invalide : onglet Configuration > Courriel."))
    msg = EmailMessage()
    msg["From"] = formataddr((" ".join((cfg.get("nom_expediteur") or "").split()), exp))
    msg["To"] = ", ".join(dest)
    msg["Subject"] = " ".join((objet or tr("Rapport Tenable")).split())          # une seule ligne : pas d'injection d'en-tête
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=exp.split("@")[1])
    msg.set_content(corps or tr("Veuillez trouver le rapport en pièce jointe."))
    total = 0
    for chemin in pieces:
        total += os.path.getsize(chemin)
        genre, _ = mimetypes.guess_type(chemin)
        principal, _, sous = (genre or "application/octet-stream").partition("/")
        with open(chemin, "rb") as f:
            msg.add_attachment(f.read(), maintype=principal, subtype=sous, filename=os.path.basename(chemin))
    if total > TAILLE_MAX:
        raise ErreurDonnees(tr("Pièce jointe trop volumineuse ({taille} Mo) : la plupart des messageries refusent plus de {max} Mo.",
                               taille=total // 1048576, max=TAILLE_MAX // 1048576))
    s = _connexion(cfg)
    try:
        refus = s.send_message(msg, from_addr=exp, to_addrs=dest)
    except smtplib.SMTPRecipientsRefused as e:
        raise ErreurDonnees(tr("Destinataire(s) refusé(s) par le serveur : {adresses}", adresses=", ".join(e.recipients)))
    except smtplib.SMTPSenderRefused:
        raise ErreurDonnees(tr("L'adresse d'expédition {adresse} est refusée par le serveur SMTP.", adresse=exp))
    except smtplib.SMTPException as e:
        raise ErreurDonnees(tr("Envoi refusé par le serveur SMTP : {err}", err=e))
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
    return [d for d in dest if d not in (refus or {})]
