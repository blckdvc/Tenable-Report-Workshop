"""Exposition PHP2Shell (CVE-2026-109618 et CVE-2026-109619) : machines concernées, priorités, mesures provisoires,
vérification de compromission, fiabilité de la détection. Construit à partir de l'export Security Center."""
import re

from .. import graphiques as G
from .. import portee as P
from ..analyse import libelle_machine
from ..commun import (DocumentPDF, W, SEVC, esc, st, mm, Paragraph, Spacer, PageBreak, KeepTogether, pluriel, Table, TableStyle)
from ..i18n import tr
from ..scores import fmt, sev_acr, sev_aes, niveau_aes
from .complet import annexe_scores, pct
from reportlab.lib import colors
from reportlab.platypus import CondPageBreak

NOM = "Exposition PHP2Shell"          # constante française : à passer dans tr() à l'affichage
CVES = ("CVE-2026-109618", "CVE-2026-109619")
PUBLICATION_PLUGINS = "2026-10-21"    # premiers plugins Nessus publiés pour ces CVE
CORRIGEES = [("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35")]

# groupe -> (libellé français, type de preuve) ; type : paquet (avis de distribution), version, sans_correctif, direct
GROUPES = {
    "version": ("Contrôle de version PHP", "version"),
    "rhel": ("Red Hat Enterprise Linux", "paquet"), "rocky": ("Rocky Linux", "paquet"), "rocky_ciq": ("Rocky Linux (CIQ)", "paquet"),
    "oracle": ("Oracle Linux", "paquet"), "tuxcare": ("TuxCare", "paquet"), "amazon": ("Amazon Linux", "paquet"),
    "fedora": ("Fedora", "paquet"), "debian": ("Debian", "paquet"), "slackware": ("Slackware", "paquet"), "gentoo": ("Gentoo", "paquet"),
    "autre": ("Autre avis de distribution", "paquet"),
    "non_corrige": ("Correctif éditeur non publié", "sans_correctif"),
    "direct": ("Test direct du comportement", "direct"),
}
# identifiant de plugin Nessus -> groupe (43 plugins publiés le 22 octobre 2026)
PLUGINS = {}
for _g, _ids in {
    "version": [369483],
    "rhel": [370139, 370208, 370210, 370213, 370214, 370216, 370217],
    "rocky": [370173, 370176, 370181, 370186, 370191],
    "rocky_ciq": [370318, 370319, 370324, 370326, 370334, 370341, 370355, 370361],
    "oracle": [370155, 370307, 370308],
    "tuxcare": [369958, 369960, 369961, 369967, 369972, 370223, 370234],
    "amazon": [370301, 370303, 370304, 370305, 370306],
    "fedora": [369953], "debian": [370148, 370149], "slackware": [370158], "gentoo": [369521],
    "non_corrige": [370006, 370055],
}.items():
    for _i in _ids:
        PLUGINS[_i] = _g
_CVE_RX = re.compile("|".join(CVES))
_AVIS_RX = re.compile(r"\(([^()]+)\)\s*$|\b((?:crlsa|ciqsa)-\d{4}_\d+|dsa-\d+|dla-\d+)\b", re.I)
NIVEAUX = {"confirme": "Confirmée", "sans_correctif": "Sans correctif éditeur", "a_confirmer": "À confirmer"}
PRIORITES = {1: ("Immédiate", "Critical"), 2: ("À vérifier", "High")}


# ------------------------------------------------------------------ analyse
def _groupe(plugin, nom):
    try:
        pid = int(plugin)
    except (TypeError, ValueError):
        pid = None
    if pid in PLUGINS:
        return PLUGINS[pid]
    if pid == 900101 or "direct check" in nom.lower():
        return "direct"
    if re.match(r"^PHP\b", nom):
        return "version"
    return "autre"


def constats(an):
    """Constats PHP2Shell du périmètre : plugins connus, ou tout constat qui cite l'une des deux CVE."""
    occ = an.occ
    cve = occ["CVE"].fillna("").astype(str)
    plugin = occ["Plugin"].astype(str).str.extract(r"(\d+)")[0].astype(float)
    masque = cve.str.contains(_CVE_RX) | plugin.isin(list(PLUGINS))
    out = []
    for _, r in occ[masque].iterrows():
        nom = str(r["Plugin Name"])
        g = _groupe(r["Plugin"], nom)
        type_ = GROUPES[g][1]
        port = int(r["Port"]) if r["Port"] == r["Port"] else 0
        niveau = ("sans_correctif" if type_ == "sans_correctif" else
                  "a_confirmer" if (type_ == "version" and port > 0) else "confirme")
        m = _AVIS_RX.search(nom)
        out.append(dict(host=r["host"], dns=r["dns"], ip=r["IP Address"], plugin=str(r["Plugin"]), nom=nom, groupe=g, type=type_,
                        niveau=niveau, port=port, sev=r["Severity"], vpr=r["VPR"], acr=r["ACR"], aes=r["AES"],
                        avis=(m.group(1) or m.group(2)) if m and type_ == "paquet" else "", poids=r["weight"]))
    return out


def _niv_machine(cs):
    ns = {c["niveau"] for c in cs}
    return "confirme" if "confirme" in ns else "sans_correctif" if "sans_correctif" in ns else "a_confirmer"


def machines_exposees(an):
    """Une ligne par machine concernée, classée par priorité puis par AES décroissant."""
    par = {}
    for c in constats(an):
        par.setdefault(c["host"], []).append(c)
    lignes = []
    for host, cs in par.items():
        niveau = _niv_machine(cs)
        aes = max([c["aes"] for c in cs if c["aes"] == c["aes"]] or [float("nan")])
        acr = max([c["acr"] for c in cs if c["acr"] == c["acr"]] or [float("nan")])
        joignable = any(c["port"] > 0 for c in cs)
        # priorité fondée sur la preuve et l'accessibilité seulement : jamais sur l'AES ni l'ACR (affichés, sans aucun filtre)
        prio = 2 if niveau == "a_confirmer" else 1
        lignes.append(dict(host=host, dns=cs[0]["dns"], ip=cs[0]["ip"], cs=cs, niveau=niveau, prio=prio, aes=aes, acr=acr,
                           joignable=joignable, ports=sorted({c["port"] for c in cs if c["port"] > 0}),
                           plugins=sorted({c["plugin"] for c in cs}), avis=sorted({c["avis"] for c in cs if c["avis"]}),
                           groupes=sorted({c["groupe"] for c in cs}), poids=sum(c["poids"] for c in cs)))
    lignes.sort(key=lambda m: (m["prio"], -(m["aes"] if m["aes"] == m["aes"] else -1), -m["poids"], m["ip"]))
    return lignes


def action(m):
    """Action recommandée pour une machine, selon la nature des preuves."""
    if m["niveau"] == "sans_correctif":
        return tr("Aucun correctif publié par l'éditeur de la distribution : appliquer les mesures provisoires du chapitre 4, "
                  "limiter l'accès réseau et surveiller les avis de l'éditeur.")
    if m["niveau"] == "a_confirmer":
        return tr("Confirmer par un scan authentifié : la bannière du service peut refléter un paquet déjà corrigé par rétroportage.")
    if "paquet" in {GROUPES[g][1] for g in m["groupes"]}:
        av = ", ".join(m["avis"][:3]) if m["avis"] else tr("l'avis de la distribution")
        return tr("Appliquer {avis} (mise à jour du paquet PHP), puis redémarrer PHP-FPM ou Apache.", avis=esc(av))
    return tr("Mettre PHP à jour vers la version corrigée de sa branche ; s'il est embarqué dans une application, "
              "demander une version corrigée à l'éditeur ; redémarrer ensuite les services web.")


def _prio(d, n):
    nom, sev = PRIORITES[n]
    t = Table([[Paragraph(f"P{n}", st("pp", fontName="Inter-SemiBold", fontSize=7.6, leading=9, textColor=colors.white, alignment=1))]],
              colWidths=[9 * mm], rowHeights=[4.6 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEVC[sev]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]
                          + ([] if d.tenable else [("ROUNDEDCORNERS", [2, 2, 2, 2])])))
    return t


def meta(an, lignes):
    from .complet import meta as meta_base
    base = meta_base(an)
    volume = tr("{n} machines analysées · {e} concernées par PHP2Shell", n=an.n_hosts, e=len(lignes))
    cible = P.libelle(getattr(an, "portee", None))
    return [base[0], (tr("Sujet"), tr("PHP2Shell · {a} et {b}", a=CVES[0], b=CVES[1])),
            *([(tr("Périmètre"), cible), (tr("Volumétrie"), volume)] if cible else [(tr("Périmètre"), volume)])]


def _tab(d, rows, widths, entete=True):
    return d.tableau(rows, widths, entete)


def _cadre(d, texte, titre, couleur="#F59E0B", fond="#FFF4E5"):
    t = Table([[Paragraph(f'<font name="Inter-SemiBold">{esc(titre)}</font><br/>{texte}', d.ACT)]], colWidths=[W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(fond)), ("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(couleur)),
                           ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return t


# ------------------------------------------------------------------ chapitres
def guide(d, an, lignes):
    prio_rows = [d.entete_tableau(tr("Priorité"), tr("Critère"), tr("Délai conseillé"))]
    prio_rows += [[_prio(d, 1), Paragraph(tr("Faille confirmée, ou sans correctif éditeur : exécution de code à distance sans authentification, déjà exploitée."), d.CELL), Paragraph(tr("24 à 48 heures"), d.CELL)],
                  [_prio(d, 2), Paragraph(tr("Constat à confirmer : version déduite de la bannière distante d'un scan non authentifié."), d.CELL),
                   Paragraph(tr("Après vérification"), d.CELL)]]
    preuves = [d.entete_tableau(tr("Niveau de preuve"), tr("Ce que cela signifie"))]
    preuves += [[Paragraph(tr("Confirmée"), d.CELLB), Paragraph(tr("Un avis de distribution, un contrôle de version local ou un test direct établit que PHP est vulnérable : "
                                                                     "ce n'est pas une supposition."), d.CELL)],
                [Paragraph(tr("Sans correctif éditeur"), d.CELLB), Paragraph(tr("La distribution n'a pas encore publié de correctif : seules des mesures provisoires "
                                                                                   "sont possibles."), d.CELL)],
                [Paragraph(tr("À confirmer"), d.CELLB), Paragraph(tr("Version déduite de la bannière du service, sans authentification : à vérifier, car une distribution "
                                                                        "corrige souvent sans changer le numéro de version."), d.CELL)]]
    return [Paragraph(tr("Comment lire ce rapport"), d.H1),
            Paragraph(tr("Ce rapport isole, dans votre export Security Center, les machines concernées par PHP2Shell : deux failles critiques de PHP qui "
                         "permettent d'exécuter du code à distance sans authentification, exploitées depuis le 21 octobre 2026."), d.LEAD),
            Paragraph(tr("Périmètre de l'analyse"), d.H2),
            Paragraph(tr("Sont retenus les constats qui citent {a} ou {b}, ainsi que les 43 plugins Nessus publiés pour ces failles (contrôle de version PHP, avis "
                         "des distributions, correctif éditeur non publié). Les autres vulnérabilités de l'export ne sont pas traitées ici : utilisez le plan "
                         "de remédiation complet pour les voir. Le filtre de sévérité du profil est ignoré pour ce rapport, afin qu'aucun constat PHP2Shell ne manque.", a=CVES[0], b=CVES[1]), d.BODY),
            Paragraph(tr("Niveaux de preuve"), d.H2), d.tableau(preuves, [38 * mm, W - 38 * mm]), Spacer(1, 4),
            Paragraph(tr("Priorités"), d.H2), d.tableau(prio_rows, [18 * mm, W - 50 * mm, 32 * mm]), Spacer(1, 2),
            Paragraph(tr("Toutes les machines concernées sont listées, sans filtre sur l'AES ni sur l'ACR. La priorité repose sur le niveau de preuve ; "
                         "elle ne remplace pas votre connaissance de l'exposition réelle (machine publiée sur Internet, "
                         "segment isolé, répartiteur de charge)."), d.SMALL),
            Spacer(1, 4), *annexe_scores(d, an, jauge=False)[:-1]]


def chap_situation(d):
    frise = [d.entete_tableau(tr("Date"), tr("Événement"))]
    for date, txt in [
        (tr("19 août 2026"), tr("Première faille identifiée par les chercheurs de Calif ; signalée à l'équipe PHP le 24 août.")),
        (tr("17 octobre 2026"), tr("Premières tentatives d'exploitation observées, quatre jours avant les correctifs (selon Amazon, cité par SOCRadar).")),
        (tr("20 octobre 2026"), tr("Les détails fuitent avant la divulgation coordonnée ; PHP annonce une version de correction d'urgence.")),
        (tr("21 octobre 2026"), tr("PHP publie les correctifs (8.2.35, 8.3.36, 8.4.27, 8.5.12) ; Tenable publie les plugins Nessus ; des pots de miel observent "
                                   "l'exploitation des deux failles (watchTowr).")),
        (tr("23 octobre 2026"), tr("PHP divulgue une faille de session distincte et non corrigée (CVE-2026-115560), sans exploitation connue. Aucune des deux "
                                   "failles n'est encore au catalogue CISA KEV (SOCRadar).")),
    ]:
        frise.append([Paragraph(date, d.CELLB), Paragraph(txt, d.CELL)])
    branches = [d.entete_tableau(tr("Branche PHP"), tr("Situation"), tr("Version corrigée"), tr("Que faire"))]
    for br, v in CORRIGEES:
        branches.append([Paragraph(f"PHP {br}", d.CELLB), Paragraph(tr("Branche maintenue"), d.CELL), Paragraph(v, d.CELLB),
                         Paragraph(tr("Passer à la version corrigée."), d.CELL)])
    branches.append([Paragraph("PHP 8.1, 8.0, 7.4", d.CELLB), Paragraph(tr("Fin de support"), d.CELL), Paragraph(tr("Aucune version officielle"), d.CELL),
                     Paragraph(tr("Paquet de la distribution ou d'un fournisseur LTS ; sinon migrer."), d.CELL)])
    branches.append([Paragraph(tr("PHP 7.3 et antérieur (dont PHP 5)"), d.CELLB), Paragraph(tr("Fin de support"), d.CELL), Paragraph(tr("Aucune correction"), d.CELL),
                     Paragraph(tr("Migrer vers une branche supportée."), d.CELL)])
    return [Paragraph(tr("1. Situation : la menace PHP2Shell"), d.H1),
            Paragraph(tr("Point de situation au {date}. Il repose sur les avis de PHP et sur les analyses publiées (références en annexe) ; vérifiez les mises "
                         "à jour avant de diffuser ce rapport.", date=tr("25 octobre 2026")), d.LEAD),
            d.indicateurs([("9,2", tr("score CVSS 4.0 de chacune des deux failles"), SEVC["Critical"]),
                           (tr("Aucune"), tr("authentification nécessaire pour les exploiter"), SEVC["High"]),
                           (tr("Oui"), tr("exploitation observée dans la nature depuis le 21 octobre"), SEVC["Critical"])]),
            Spacer(1, 6),
            Paragraph(tr("Ce que sont ces failles"), d.H2),
            Paragraph(tr("<b>{a}</b> : corruption mémoire quand PHP manque de mémoire en pleine initialisation d'une requête ; le code de nettoyage fait confiance à "
                         "des données à moitié construites.", a=CVES[0]), d.BODY),
            Paragraph(tr("<b>{b}</b> : un état interne survit à la mémoire de la requête qui l'a créé, et la requête suivante traitée par le même processus PHP "
                         "agit sur des données périmées.", b=CVES[1]), d.BODY),
            Paragraph(tr("Toute installation PHP qui répond à des requêtes web est concernée (PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed) ; Apache avec "
                         "mod_php est le plus exposé. Le suivi de téléversement des sessions, activé par défaut, est un chemin d'exploitation confirmé."), d.BODY),
            Paragraph(tr("Chronologie"), d.H2), KeepTogether([d.tableau(frise, [32 * mm, W - 32 * mm])]), Spacer(1, 4),
            Paragraph(tr("Versions corrigées"), d.H2), KeepTogether([d.tableau(branches, [34 * mm, 28 * mm, 34 * mm, W - 96 * mm])]), Spacer(1, 2),
            Paragraph(tr("Le numéro de version ne suffit pas : les distributions corrigent souvent sans le changer. Pour un paquet de distribution, "
                         "c'est l'avis de la distribution qui fait foi."), d.SMALL),
            Spacer(1, 4),
            _cadre(d, tr("Des équipements embarquent PHP : Palo Alto PAN-OS et Panorama sont signalés sans correctif à la date de rédaction, Cisco Expressway "
                         "est corrigé en 15.5.21 (SOCRadar). Vérifiez les avis de vos éditeurs."),
                   tr("Au-delà des serveurs web"))]


def _graphes(d, lignes, cs):
    par_g = {}
    for c in cs:
        par_g[c["groupe"]] = par_g.get(c["groupe"], 0) + 1
    coul = {"paquet": "#A4161A", "version": "#E8590C", "sans_correctif": "#F2A007", "direct": "#2F6FCB"}
    rows = [(tr(GROUPES[g][0]), n, coul[GROUPES[g][1]]) for g, n in sorted(par_g.items(), key=lambda x: -x[1])[:7]]
    G.barres_h(rows, d.chemin_tmp("p2s_groupes.png"), size=(3.3, max(1.4, 0.3 * len(rows) + 0.5)), xlabel=tr("Constats"))
    prio = [(tr(PRIORITES[n][0]), sum(1 for m in lignes if m["prio"] == n), {"Critical": "#A4161A", "High": "#E8590C"}[PRIORITES[n][1]])
            for n in (1, 2)]
    G.barres_h(prio, d.chemin_tmp("p2s_prio.png"), size=(3.3, 1.4 + 0.0), xlabel=tr("Machines"))


def _gauges(d, an, lignes):
    vals = [m["aes"] for m in lignes if m["aes"] == m["aes"]]
    if not vals or not an.a_aes or an.aes_moy is None:
        return []
    moy = sum(vals) / len(vals)
    G.jauge_aes(d.chemin_tmp("p2s_g1.png"), moy, tr("CES des machines concernées"), size=(6.6, 0.95))
    G.jauge_aes(d.chemin_tmp("p2s_g2.png"), an.aes_moy, tr("CES du périmètre"), size=(6.6, 0.95))
    return [Paragraph(tr("Posture d'exposition des machines concernées"), d.H2), d.image(d.chemin_tmp("p2s_g1.png"), W * 0.92),
            d.image(d.chemin_tmp("p2s_g2.png"), W * 0.92),
            Paragraph(tr("Le Cyber Exposure Score (CES) est estimé ici par la moyenne des AES des machines. Comparé à celui du périmètre, il indique si PHP2Shell "
                         "touche des machines plus ou moins exposées que la moyenne."), d.SMALL)]


def chap_exposition(d, an, lignes, cs):
    n_conf = sum(1 for m in lignes if m["niveau"] == "confirme")
    n_snc = sum(1 for m in lignes if m["niveau"] == "sans_correctif")
    n_p1 = sum(1 for m in lignes if m["prio"] == 1)
    part = 100 * len(lignes) / an.n_hosts if an.n_hosts else 0
    _graphes(d, lignes, cs)
    rows = [d.entete_tableau(tr("Prio."), tr("Machine"), tr("Preuve"), tr("Plugins"), "ACR", "AES", droite=(4, 5))]
    for m in lignes:
        rows.append([_prio(d, m["prio"]),
                     Paragraph(f'<font name="Inter-Medium">{esc(libelle_machine(m["dns"], m["ip"]))}</font><br/>'
                               f'<font size="7" color="#5A5A5A">{m["ip"]}</font>', d.CELL),
                     Paragraph(tr(NIVEAUX[m["niveau"]]) + (f'<br/><font size="7" color="#5A5A5A">{tr("service joignable")} : '
                                                           f'{", ".join(str(p) for p in m["ports"])}</font>' if m["ports"] else ""), d.CELL),
                     Paragraph(", ".join(m["plugins"]), d.CELL),
                     d.pastille_score(m["acr"], sev_acr(m["acr"])) if an.a_acr else Paragraph("—", d.CELLR),
                     d.pastille_score(m["aes"], sev_aes(m["aes"])) if an.a_aes else Paragraph("—", d.CELLR)])
    return [Paragraph(tr("2. Exposition de votre périmètre"), d.H1),
            Paragraph(tr("{e} sur {n} machines de l'export sont concernées par PHP2Shell, soit {p} du périmètre.", e=len(lignes), n=an.n_hosts, p=pct(part, 0)), d.LEAD),
            d.indicateurs([(len(lignes), tr("machines concernées"), SEVC["Critical"]), (n_p1, tr("à traiter en priorité 1"), SEVC["High"]),
                           (n_conf, tr("failles confirmées"), None), (n_snc, tr("sans correctif éditeur"), SEVC["Medium"])]),
            Spacer(1, 8),
            d.deux_graphiques((tr("Constats par source de détection"), d.chemin_tmp("p2s_groupes.png")),
                              (tr("Machines par priorité"), d.chemin_tmp("p2s_prio.png"))),
            *_gauges(d, an, lignes),
            Paragraph(tr("Machines concernées"), d.H2),
            Paragraph(tr("Toutes les machines concernées, classées par priorité, puis par AES décroissant. Le détail de chaque constat figure à l'annexe A."), d.SMALL), Spacer(1, 3),
            d.tableau(rows, [12 * mm, 54 * mm, 42 * mm, 38 * mm, 14 * mm, 14 * mm])]


def chap_plan(d, an, lignes):
    out = [Paragraph(tr("3. Plan d'action"), d.H1),
           Paragraph(tr("Machine par machine, dans l'ordre de priorité. Dans tous les cas : redémarrer les processus PHP (PHP-FPM, Apache) après la mise à jour, "
                         "et vérifier la version qui sert réellement les requêtes web (l'interface en ligne de commande peut en utiliser une autre)."), d.LEAD)]
    for n in (1, 2):
        sel = [m for m in lignes if m["prio"] == n]
        if not sel:
            continue
        nom, _ = PRIORITES[n]
        bloc = [Paragraph(tr("Priorité {n} : {nom}", n=n, nom=tr(nom)), d.H2)]
        rows = [d.entete_tableau(tr("Machine"), tr("Preuve"), tr("Action recommandée"))]
        for m in sel:
            rows.append([Paragraph(f'<font name="Inter-Medium">{esc(libelle_machine(m["dns"], m["ip"]))}</font><br/>'
                                   f'<font size="7" color="#5A5A5A">{m["ip"]}</font>', d.CELL),
                         Paragraph(tr(NIVEAUX[m["niveau"]]), d.CELL), Paragraph(action(m), d.CELL)])
        out += [bloc[0], d.tableau(rows, [44 * mm, 30 * mm, W - 74 * mm]), Spacer(1, 6)]
    out += [Paragraph(tr("Après les correctifs"), d.H2),
            Paragraph(tr("Relancer un scan authentifié avec des plugins à jour, puis générer ce rapport à nouveau et le comparer à l'export précédent avec le modèle "
                         "« Comparaison de deux exports » : les machines corrigées doivent disparaître de la liste."), d.BODY)]
    return out


def chap_mesures(d):
    rows = [d.entete_tableau(tr("Mesure"), tr("Faille visée"), tr("Remarque"))]
    for a, b, c in [
        (tr("Mettre PHP à jour"), tr("Les deux"), tr("Seule solution durable : PHP indique qu'aucun réglage de configuration ne ferme complètement les failles.")),
        (tr("Redémarrer tous les processus PHP après la mise à jour"), tr("Les deux"), tr("Sans redémarrage, les anciens processus restent vulnérables.")),
        (tr("Désactiver le suivi de téléversement des sessions (session.upload_progress.enabled=0), puis redémarrer"), CVES[1],
         tr("Ferme un chemin d'exploitation confirmé, pas tous.")),
        (tr("Limiter la taille, le nombre et l'imbrication des requêtes (post_max_size, limites du serveur web ou du proxy)"), CVES[0],
         tr("Réduit la capacité à provoquer un manque de mémoire.")),
        (tr("Imposer des limites de mémoire non modifiables par les applications (PHP et conteneur)"), CVES[0], tr("À valider avec l'éditeur de l'application.")),
        (tr("PHP 8.5 : désactiver les traces d'erreur fatale (fatal_error_backtraces=0)"), tr("PHP 8.5"), tr("Recommandation de PHP pour cette branche.")),
        (tr("Isoler les applications exposées à Internet, restreindre l'accès aux systèmes qui ne peuvent pas être corrigés"), tr("Les deux"),
         tr("Un pare-feu applicatif aide, mais reste temporaire.")),
    ]:
        rows.append([Paragraph(a, d.CELL), Paragraph(b, d.CELLB), Paragraph(c, d.CELL)])
    return [Paragraph(tr("4. Mesures provisoires"), d.H1),
            Paragraph(tr("Pour les machines que vous ne pouvez pas corriger tout de suite, ou pour lesquelles aucun correctif n'existe. Ces mesures réduisent "
                         "l'exposition, elles ne remplacent pas la mise à jour."), d.LEAD),
            d.tableau(rows, [W - 80 * mm, 26 * mm, 54 * mm]), Spacer(1, 4),
            Paragraph(tr("Sources : avis de PHP et SOCRadar, octobre 2026. Validez ces réglages avec vos équipes avant déploiement."), d.SMALL)]


def chap_compromission(d):
    def ligne(a, b):
        return [Paragraph("☐", st("box", fontName="DejaVu", fontSize=10, leading=11)), Paragraph(f'<font name="Inter-Medium">{a}</font>', d.CELL), Paragraph(b, d.CELL)]
    rows = [[Paragraph("", d.CELLH), d.entete_tableau(tr("Vérification"))[0], d.entete_tableau(tr("Quoi chercher"))[0]]]
    for a, b in [
        (tr("Préserver les preuves"), tr("Avant toute correction : journaux PHP et du serveur web, instantané de la configuration, fichiers suspects.")),
        (tr("Requêtes inhabituelles"), tr("Requêtes multipart très volumineuses ou très imbriquées dans les journaux d'accès.")),
        (tr("Processus PHP instables"), tr("Processus arrêtés brutalement ou ayant atteint leur limite de mémoire.")),
        (tr("Fichiers dans la racine web"), tr("Fichiers récemment écrits dans les répertoires servis par le serveur web (portes dérobées, web shells).")),
        (tr("Connexions sortantes"), tr("Connexions sortantes de processus PHP que rien ne justifie.")),
        (tr("Persistance"), tr("Nouvelles tâches planifiées, comptes récemment créés et rattachés aux processus PHP.")),
        (tr("Version réellement servie"), tr("Version indiquée par phpinfo() ou le gestionnaire de paquets ; la ligne de commande peut utiliser un autre PHP.")),
    ]:
        rows.append(ligne(a, b))
    return [Paragraph(tr("5. Vérifier une éventuelle compromission"), d.H1),
            Paragraph(tr("L'exploitation a commencé avant la publication des correctifs. Une machine exposée à Internet et corrigée tardivement doit être examinée "
                         "avant d'être considérée comme saine : le NCSC britannique recommande de rechercher des portes dérobées avant la mise à jour si le "
                         "système ne peut pas être corrigé immédiatement."), d.LEAD),
            d.tableau(rows, [8 * mm, 46 * mm, W - 54 * mm]), Spacer(1, 4),
            Paragraph(tr("Sources : watchTowr, NCSC (Royaume-Uni), octobre 2026."), d.SMALL)]


def chap_fiabilite(d, an, lignes):
    presents = {p for p in (str(x) for x in an.occ["Plugin"].astype(str).str.extract(r"(\d+)")[0].dropna().astype(int)) if int(p) in PLUGINS}
    derniere = ""
    try:
        derniere = str(an.occ["Last Observed"].dropna().astype(str).max())[:10]
    except Exception:
        pass
    avert = []
    if derniere and derniere < PUBLICATION_PLUGINS:
        avert = [_cadre(d, tr("La dernière observation de l'export date du {date}, avant la publication des plugins ({pub}). Relancez un scan avec des plugins "
                              "à jour : une absence de constat ne prouve rien.", date=derniere, pub=PUBLICATION_PLUGINS), tr("Export antérieur aux plugins"),
                        "#A4161A", "#FDECEC"), Spacer(1, 8)]
    rows = [d.entete_tableau(tr("Situation"), tr("Explication"), tr("Que faire"))]
    for a, b, c in [
        (tr("PHP est installé, mais le contrôle de version 369483 ne remonte rien"),
         tr("Ce contrôle ignore volontairement les paquets gérés par la distribution : c'est l'avis de la distribution qui les couvre."),
         tr("Vérifier la famille de plugins de votre distribution (annexe B) et scanner avec des identifiants.")),
        (tr("Le contrôle 369483 signale un paquet de distribution déjà corrigé"),
         tr("Le scan est en mode « paranoïaque » : il signale des versions qui paraissent rétroportées."),
         tr("Repasser le scan en mode normal ; se fier à l'avis de la distribution.")),
        (tr("PHP embarqué dans une application"), tr("La copie embarquée est réellement vulnérable, mais le gestionnaire de paquets ne peut pas la corriger."),
         tr("Demander à l'éditeur de l'application une version qui embarque PHP 8.2.35, 8.3.36, 8.4.27 ou 8.5.12 minimum.")),
        (tr("Constat issu d'une bannière distante"), tr("Scan non authentifié : la version annoncée peut ne pas refléter le correctif."),
         tr("Confirmer par un scan authentifié.")),
        (tr("Aucun constat « correctif non publié »"), tr("Les plugins 370006 et 370055 ne s'exécutent que si l'option d'affichage des vulnérabilités sans "
                                                           "correctif de l'éditeur est activée dans le scan."), tr("Activer l'option si vous voulez ces constats.")),
        (tr("Scan par agent"), tr("Les contrôles distants (bannière, test direct) ne s'exécutent pas avec un agent."), tr("S'appuyer sur la détection locale.")),
    ]:
        rows.append([Paragraph(a, d.CELLB), Paragraph(b, d.CELL), Paragraph(c, d.CELL)])
    return [Paragraph(tr("6. Fiabilité de la détection"), d.H1),
            Paragraph(tr("{p} des 43 plugins Nessus publiés pour PHP2Shell apparaissent dans votre export. Ce chapitre explique les écarts les plus courants "
                         "entre ce que le scan voit et ce qui est réellement exposé.", p=len(presents)), d.LEAD), *avert,
            d.tableau(rows, [50 * mm, W - 100 * mm, 50 * mm])]


def annexe_constats(d, lignes):
    rows = [d.entete_tableau(tr("Machine"), "Plugin", tr("Intitulé Tenable"), "Port", tr("Sévérité"), "VPR", droite=(3, 5))]
    for m in lignes:
        for c in m["cs"]:
            rows.append([Paragraph(f'<font name="Inter-Medium">{esc(libelle_machine(m["dns"], m["ip"]))}</font><br/><font size="7" color="#5A5A5A">{m["ip"]}</font>', d.CELL),
                         Paragraph(c["plugin"], d.CELL), Paragraph(esc(c["nom"][:90]), d.CELL), Paragraph(str(c["port"] or "—"), d.CELLR),
                         d.pastille(c["sev"]) if c["sev"] in SEVC else Paragraph(esc(str(c["sev"])), d.CELL), Paragraph(fmt(c["vpr"]) if c["vpr"] == c["vpr"] else "—", d.CELLR)])
    return [Paragraph(tr("Annexe A : tous les constats"), d.H1),
            Paragraph(tr("{n} constats sur {m} machines, classés comme au chapitre 2.", n=len(rows) - 1, m=len(lignes)), d.LEAD),
            d.tableau(rows, [38 * mm, 15 * mm, W - 38 * mm - 15 * mm - 12 * mm - 20 * mm - 12 * mm, 12 * mm, 20 * mm, 12 * mm])]


def annexe_plugins(d, an):
    presents = {int(x) for x in an.occ["Plugin"].astype(str).str.extract(r"(\d+)")[0].dropna().astype(int)}
    rows = [d.entete_tableau(tr("Famille"), tr("Identifiants des plugins"), tr("Dans l'export"))]
    for g, (lib, _) in GROUPES.items():
        ids = sorted(i for i, gg in PLUGINS.items() if gg == g)
        if not ids:
            continue
        vus = [i for i in ids if i in presents]
        rows.append([Paragraph(tr(lib), d.CELLB), Paragraph(", ".join(str(i) for i in ids), d.CELL),
                     Paragraph(f'{len(vus)} / {len(ids)}' + (f' ({", ".join(str(i) for i in vus)})' if vus else ""), d.CELL)])
    return [Paragraph(tr("Annexe B : plugins Nessus couverts"), d.H1),
            Paragraph(tr("Les 43 plugins publiés pour {a} et {b} au 22 octobre 2026 ; de nouveaux avis de distribution sont publiés régulièrement.", a=CVES[0], b=CVES[1]), d.LEAD),
            d.tableau(rows, [46 * mm, W - 46 * mm - 52 * mm, 52 * mm])]


def annexe_sources(d):
    liens = [("watchTowr", "watchtowr.com/intelligence/php-remote-code-execution-php2shell"),
             ("SOCRadar", "socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619"),
             ("Help Net Security", "helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619"),
             ("Recorded Future", "recordedfuture.com/blog/php2shell-vulnerability-exploitation"),
             ("CrowdStrike", "crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation"),
             ("Advisories php-src", "GHSA-w8hw-w9fx-j79w (CVE-2026-109618) · GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)"),
             ("Calif", "calif.io/php2shell")]
    return [Paragraph(tr("Annexe C : sources"), d.H1),
            Paragraph(tr("Le point de situation du chapitre 1 et les mesures des chapitres 4 et 5 s'appuient sur ces publications, consultées en octobre 2026."), d.LEAD),
            *d.puces([f"<b>{a}</b> : {b}" for a, b in liens])]


def sans_exposition(d, an):
    return [Paragraph(tr("2. Exposition de votre périmètre"), d.H1),
            Paragraph(tr("Aucune des {n} machines de l'export n'est signalée comme concernée par PHP2Shell.", n=an.n_hosts), d.LEAD),
            _cadre(d, tr("Ce résultat n'est rassurant que si votre scan pouvait voir ces failles. Lisez le chapitre 3 avant de conclure."),
                   tr("Absence de constat ne veut pas dire absence de PHP vulnérable"))]


def generer(an, habillage, sortie):
    lignes = machines_exposees(an)
    cs = [c for m in lignes for c in m["cs"]]
    d = DocumentPDF(sortie, habillage, tr(NOM), meta(an, lignes))
    story = guide(d, an, lignes) + [PageBreak()] + chap_situation(d) + [PageBreak()]
    if lignes:
        story += chap_exposition(d, an, lignes, cs) + [PageBreak()] + chap_plan(d, an, lignes) + [PageBreak()] + chap_mesures(d) + [PageBreak()] + \
                 chap_compromission(d) + [PageBreak()] + chap_fiabilite(d, an, lignes) + [PageBreak()] + annexe_constats(d, lignes) + [PageBreak()]
    else:
        fiab = chap_fiabilite(d, an, lignes)
        fiab[0] = Paragraph(tr("3. Fiabilité de la détection"), d.H1)
        story += sans_exposition(d, an) + [PageBreak()] + fiab + [PageBreak()] + chap_mesures(d) + [PageBreak()]
    story += annexe_plugins(d, an) + [Spacer(1, 10)] + annexe_sources(d)
    return d.construire(story)
