#!/usr/bin/env python3
"""Génération en ligne de commande, sans interface (pour automatiser) :

    python generer.py export.csv                                  # rapport complet, profil par défaut
    python generer.py export.csv --modele synthese --profil client-a
    python generer.py ancien.csv recent.csv --modele comparaison
    python generer.py export.csv --modele plan_excel --sortie plan.xlsx

    python generer.py --securitycenter --profil client-a                     # export récupéré via l'API Security Center
    python generer.py ancien.csv --securitycenter --modele comparaison      # précédent = fichier, récent = API
    python generer.py --securitycenter --profil client-a --mail dsi@exemple.fr,rssi@exemple.fr
    python generer.py export.csv --langue en                      # rapport en anglais (fr, en, es, it)
"""
import argparse
import datetime
import json
import os
import re
import sys

from moteur import config as CFG
from moteur import courriel as MAIL
from moteur import portee as PT
from moteur import regles as R
from moteur import securitycenter as SC
from moteur import vulnmanagement as VMC
from moteur.analyse import Analyse
from moteur.commun import HABILLAGE_DEFAUT
from moteur import charte as CH
from moteur import i18n
from moteur.i18n import tr, plur
from moteur.modeles import MODELES, perimetre_pour

RACINE = os.path.dirname(os.path.abspath(__file__))

# la langue de l'aide : --langue si elle est donnée (lecture préalable), sinon le français
_pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
_pre.add_argument("--langue", choices=i18n.CODES)
i18n.set_langue(_pre.parse_known_args()[0].langue or i18n.DEFAUT)

ap = argparse.ArgumentParser(description=tr("Génère un rapport à partir d'un ou deux exports CSV Tenable Security Center."))
ap.add_argument("exports", nargs="*", help=tr("export CSV (deux exports pour la comparaison : le précédent puis le récent)"))
ap.add_argument("--modele", default="complet", choices=list(MODELES), help=tr("modèle de rapport"))
ap.add_argument("--profil", help=tr("identifiant du profil client (nom du fichier dans profils/, sans .json)"))
ap.add_argument("--sortie", help=tr("fichier à produire"))
ap.add_argument("--theme", choices=CH.THEMES, help=tr("thème visuel : atelier ou tenable (défaut : celui de l'application)"))
ap.add_argument("--langue", choices=i18n.CODES,
                help=tr("langue du rapport et des messages (défaut : langue du profil, sinon fr)"))
ap.add_argument("--securitycenter", "--api", dest="securitycenter", action="store_true",
                help=tr("récupère l'export (le plus récent, pour une comparaison) via l'API Security Center, selon la requête du profil"))
ap.add_argument("--mail", metavar=tr("ADRESSES"), help=tr("envoie le rapport par courriel (serveur SMTP de config.json) : adresses séparées "
                "par des virgules, ou « defaut » pour les destinataires du profil"))
args = ap.parse_args()

m = MODELES[args.modele]
habillage, perimetre, source, mail_profil = dict(HABILLAGE_DEFAUT), None, None, {}
if args.profil:
    chemin = os.path.join(RACINE, "profils", f"{args.profil}.json")
    if not os.path.exists(chemin):
        sys.exit(tr("Profil introuvable : {chemin}", chemin=chemin))
    with open(chemin, encoding="utf-8") as f:
        p = json.load(f)
    habillage.update(p.get("habillage", {}))
    if habillage.get("logo"):
        habillage["logo"] = os.path.join(RACINE, "profils", habillage["logo"])
    perimetre, source, mail_profil = p.get("perimetre"), p.get("source"), p.get("mail") or {}
    langue_profil = p.get("langue")
else:
    langue_profil = None
# langue : option --langue, sinon celle du profil, sinon le français ; à fixer avant de charger les règles et de générer
i18n.set_langue(args.langue or langue_profil or i18n.DEFAUT)
for _cle in ("titre", "pied"):                    # textes par défaut enregistrés en français : suivent la langue
    if habillage.get(_cle) == HABILLAGE_DEFAUT[_cle]:
        habillage[_cle] = tr(HABILLAGE_DEFAUT[_cle])
habillage = CH.appliquer(habillage, args.theme)         # thème : option --theme, sinon celui de l'application
attendus = m["exports"] - (1 if args.securitycenter else 0)
if len(args.exports) != attendus:
    sys.exit(tr("Le modèle « {modele} » demande {n} export(s)", modele=tr(m["nom"]), n=m["exports"])
             + (tr(" dont un récupéré via Security Center : indiquez {n} fichier(s) CSV.", n=attendus) if args.securitycenter else "."))
if args.securitycenter:
    try:
        vm = (source or {}).get("produit") == "vm"
        dossier = os.path.join(RACINE, "exports_vulnerability_management" if vm else "exports_security_center")
        nom = f"{args.profil or 'defaut'}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        client = VMC.Client(CFG.lire()["vulnmanagement"]) if vm else SC.Client(CFG.lire()["securitycenter"])
        res = client.exporter_csv(
            {**SC.SOURCE_DEFAUT, **VMC.SOURCE_DEFAUT, **(source or {})}, os.path.join(dossier, nom), perimetre_pour(MODELES[args.modele], perimetre).get("severites"))
    except R.ErreurDonnees as e:
        sys.exit(tr("Erreur : {err}", err=e))
    args.exports.append(os.path.join(dossier, nom))
    print(tr("Vulnerability Management : {lignes} lignes récupérées en {secondes} s, copie dans {chemin}" if vm else
             "Security Center : {lignes} lignes récupérées en {secondes} s, copie dans {chemin}",
             lignes=res["lignes"], secondes=res["secondes"], chemin=os.path.join(dossier, nom)))
    if res.get("avertissement"):
        print(res["avertissement"])
sortie = args.sortie or f"rapport_{args.modele}.{m['format']}"
try:
    portee_api = PT.portee({**SC.SOURCE_DEFAUT, **VMC.SOURCE_DEFAUT, **(source or {})}) if args.securitycenter else None
    analyses = [Analyse(e, perimetre_pour(m, perimetre), nom_fichier=os.path.basename(e),
                        portee=portee_api if e == args.exports[-1] and args.securitycenter else None) for e in args.exports]
    m["module"].generer(*analyses, habillage, sortie)
except R.ErreurDonnees as e:
    sys.exit(tr("Erreur : {err}", err=e))
an = analyses[-1]
print(tr("Rapport généré — {modele} : {fichier} ({machines}, {vulns}, {solutions})", modele=tr(m["nom"]), fichier=sortie,
         machines=plur(an.n_hosts, "machine"), vulns=plur(len(an.occ), "vulnérabilité"), solutions=plur(len(an.sols), "solution")))
if an.sans_regle:
    print(tr("{n} intitulé(s) sans règle dédiée ; à compléter dans l'onglet Règles de l'application.", n=len(an.sans_regle)))

if args.mail:
    cible = mail_profil.get("destinataires", "") if args.mail.lower() == "defaut" else args.mail
    valeurs = {"titre": habillage.get("titre") or tr("Rapport de vulnérabilités"), "client": habillage.get("client") or args.profil or "",
               "date": datetime.date.today().strftime(tr("%d/%m/%Y")), "fichier": os.path.basename(sortie)}
    def gabarit(t):
        for k, v in valeurs.items():
            t = t.replace("{" + k + "}", v)
        return t
    try:
        envoyes = MAIL.envoyer(CFG.lire()["smtp"], cible, gabarit(mail_profil.get("objet") or "{titre} - {client}").strip(" -"),
                               gabarit(mail_profil.get("message") or tr("Veuillez trouver le rapport en pièce jointe.")), [sortie])
    except R.ErreurDonnees as e:
        sys.exit(tr("Rapport généré mais non envoyé : {err}", err=e))
    print(tr("Rapport envoyé à {adresses}", adresses=", ".join(envoyes)))
