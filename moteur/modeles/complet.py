"""Rapport complet : synthèse, plan d'action, détail par solution, guide par machine.

Seules les solutions du plan d'action (réglage « nombre de solutions » du périmètre) sont présentées."""
from .. import graphiques as G
from .. import portee as P
from ..analyse import libelle_machine
from ..commun import (DocumentPDF, W, SEVC, FR, esc, st, mm, Paragraph, Spacer, PageBreak, KeepTogether,
                      pluriel, Table, TableStyle)
from ..i18n import tr
from reportlab.lib import colors
from ..scores import SCORES, source, fmt, sev_acr, sev_aes, niveau_aes
from reportlab.platypus import CondPageBreak, HRFlowable

NOM = "Plan de remédiation"          # constante française : à passer dans tr() à l'affichage


def pct(v, dec=1):
    """Pourcentage dans la langue courante (« 12.3 % » en français, « 12.3% » en anglais)."""
    return tr("{v} %", v=f"{v:.{dec}f}")


def meta(an):
    volume = tr("{n} machines · {v} vulnérabilités ({c} critiques, {e} élevées)",
                n=an.n_hosts, v=len(an.occ), c=an.sev_occ.get("Critical", 0), e=an.sev_occ.get("High", 0))
    cible = P.libelle(getattr(an, "portee", None))
    return [(tr("Source des données"), tr("Export Tenable Vulnerability Management") if getattr(an, "produit", "sc") == "vm"
             else tr("Export Tenable Security Center")),
            *([(tr("Périmètre"), cible), (tr("Volumétrie"), volume)] if cible else [(tr("Périmètre"), volume)])]


def bloc_aes(d, an):
    """Posture d'exposition du périmètre : AES moyen, jauge de risque faible à élevé, répartition des machines."""
    if not an.a_aes or an.aes_moy is None:
        return []
    G.jauge_aes(d.chemin_tmp("jauge_aes.png"), an.aes_moy, tr("CES"))
    niveau = niveau_aes(an.aes_moy)
    sev = sev_aes(an.aes_moy)
    tuile = Table([[Paragraph(f'<font name="Inter-SemiBold" size="24" color="#{SEVC[sev].hexval()[2:]}">{an.aes_moy:.0f}</font>',
                              st("k", leading=28)),
                    Paragraph(f'<font size="8" color="#5A5A5A">{tr("Cyber Exposure Score du périmètre")}<br/>{tr("sur 1 000")} · '
                              f'<b>{niveau}</b></font>', st("kl", leading=10.5))]],
                  colWidths=[22 * mm, 28 * mm])
    tuile.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    haut = Table([[tuile, d.image(d.chemin_tmp("jauge_aes.png"), W - 56 * mm)]], colWidths=[56 * mm, W - 56 * mm])
    haut.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    rep = an.aes_rep
    return [Spacer(1, 10), Paragraph(tr("Posture d'exposition (Cyber Exposure Score)"), d.H2), haut,
            Paragraph(tr("Répartition des {n} : <b>{h}</b> à risque élevé, <b>{m}</b> à risque moyen, <b>{b}</b> à risque faible. "
                         "AES maximum : <b>{mx}</b>.", n=pluriel(an.aes_n, "machine"), h=rep["High"], m=rep["Medium"], b=rep["Low"],
                         mx=fmt(an.aes_max)), d.BODY),
            Paragraph(tr("Le Cyber Exposure Score (CES) est la note d'exposition globale de Tenable, de 0 à 1 000, déduite des AES des machines. "
                         "Ici, il est estimé par la moyenne des AES du périmètre analysé."), d.SMALL)]


def chapitre_synthese(d, an, numero="1."):
    """Synthèse graphique, réutilisée par la synthèse exécutive."""
    G.severity_bars(an.sev_occ, d.chemin_tmp("sev.png"))
    G.pareto([s["pct"] for s in an.sols], d.chemin_tmp("pareto.png"), n=max(an.top, 1), accent=d.accent_hex)
    G.top_hosts([(f"{libelle_machine(h['dns'], h['ip'])}  ({h['ip']})" + (f" · {tr('AES {v}', v=fmt(h['aes']))}" if an.a_aes else ""),
                  h["sevscore"]) for h in an.machines[:10]], d.chemin_tmp("hosts.png"))
    top3 = sorted(an.machines, key=lambda h: (-h["score"], h["ip"]))[:3]
    top3pct = 100 * sum(h["score"] for h in top3) / an.total
    crit_hosts = an.occ[an.occ.Severity == "Critical"].host.nunique()
    plus_large = max(an.TOP, key=lambda s: len(s["hosts"]))
    points = [
        (tr("<b>{machines} concentrent {pct} du risque</b> : {liste}.", machines=pluriel(len(top3), 'machine'), pct=pct(top3pct, 0),
            liste=", ".join(f"{esc(libelle_machine(h['dns'], h['ip']))} ({h['ip']})" for h in top3))
         if len(top3) > 1 else
         tr("<b>{machines} concentre {pct} du risque</b> : {liste}.", machines=pluriel(len(top3), 'machine'), pct=pct(top3pct, 0),
            liste=", ".join(f"{esc(libelle_machine(h['dns'], h['ip']))} ({h['ip']})" for h in top3))),
        tr("<b>Appliquer les 5 premières solutions élimine {p5} du risque</b>, les 10 premières {p10} et les {top} du plan d'action {ptop}.",
           p5=pct(an.cum_at(5), 0), p10=pct(an.cum_at(10), 0), top=an.top, ptop=pct(an.cum_at(an.top), 0)),
        tr("La solution qui touche le plus de machines est « {titre} » ({machines}).", titre=esc(plus_large['title']),
           machines=pluriel(len(plus_large['hosts']), 'machine')),
    ]
    if crit_hosts:
        points.insert(2, tr("Des vulnérabilités critiques sont présentes sur <b>{machines}</b> ; "
                            "elles sont corrigées par {solutions} du plan d'action.",
                            machines=pluriel(crit_hosts, 'machine'),
                            solutions=pluriel(sum(1 for s in an.TOP if 'Critical' in s['sev_counts']), 'solution')))
    story = [Paragraph(f"{numero} {tr('Synthèse')}", d.H1),
             Paragraph(tr("L'analyse porte sur {machines} et {vulns}. "
                          "Les vulnérabilités sont regroupées en {solutions} : une solution est une action "
                          "concrète (mise à jour, changement de configuration) qui corrige d'un coup toutes les vulnérabilités qu'elle couvre.",
                          machines=pluriel(an.n_hosts, 'machine'), vulns=pluriel(len(an.occ), 'vulnérabilité'),
                          solutions=pluriel(len(an.sols), 'solution')),
                       d.LEAD),
             d.indicateurs([(an.n_hosts, tr("machines analysées"), None), (len(an.occ), tr("vulnérabilités"), None),
                            (an.sev_occ.get("Critical", 0), tr("vulnérabilités critiques"), SEVC["Critical"]),
                            (an.sev_occ.get("High", 0), tr("vulnérabilités élevées"), SEVC["High"])]),
             *bloc_aes(d, an),
             Spacer(1, 10), Paragraph(tr("Points clés"), d.H2), *d.puces(points), Spacer(1, 8),
             d.deux_graphiques((tr("Vulnérabilités par sévérité"), d.chemin_tmp("sev.png")),
                               (tr("Risque éliminé selon le nombre de solutions appliquées"), d.chemin_tmp("pareto.png"))),
             Spacer(1, 8),
             KeepTogether([Paragraph(tr("Les {n} machines les plus exposées (classées par AES)", n=min(10, an.n_hosts)) if an.a_aes
                                     else tr("Les {n} machines les plus exposées", n=min(10, an.n_hosts)), d.CAP),
                           d.image(d.chemin_tmp("hosts.png"), W)])]
    return story


def tableau_plan(d, sols, liens=True):
    data = [d.entete_tableau(tr("N°"), tr("Solution"), tr("Sévérité max."), tr("Vuln."), tr("Machines"), tr("Risque éliminé"))]
    for s in sols:
        titre = (f'<a href="#sol{s["rank"]}" color="#161616">{esc(s["title"])}</a>' if liens else esc(s["title"]))
        data.append([Paragraph(str(s["rank"]), d.CELLC), Paragraph(titre, d.CELLB), d.pastille(s["maxsev"]),
                     Paragraph(str(s["n_vulns"]), d.CELLR), Paragraph(str(len(s["hosts"])), d.CELLR),
                     Paragraph(pct(s['pct']), d.CELLR)])
    return d.tableau(data, [9 * mm, W - 84 * mm, 22 * mm, 14 * mm, 17 * mm, 22 * mm])


def bloc_solution(d, s, an):
    meta_txt = tr("{vulns} ({sev}) · {machines} · <b>{pct} du risque total</b>",
                  vulns=pluriel(s["n_vulns"], "vulnérabilité corrigée", "vulnérabilités corrigées"), sev=d.compte_sev(s["sev_counts"]),
                  machines=pluriel(len(s["hosts"]), "machine"), pct=pct(s["pct"]))
    noms = s["names"][:6]
    vl = tr("Vulnérabilités corrigées (intitulés Tenable) : ") + "; ".join(esc(n) for n in noms)
    if len(s["names"]) > len(noms):
        vl += tr(" ; et {n} autres.", n=len(s["names"]) - len(noms))
    sc = an.a_acr or an.a_aes
    rows = [d.entete_tableau(tr("Machine"), tr("Adresse IP"), *(("ACR", "AES") if sc else ()), tr("Vuln. corrigées"), tr("Sévérité max."),
                              droite=(2, 3, 4) if sc else (2,))]
    for _, r in s["hosts"].iterrows():
        rows.append([Paragraph(esc(r["dns"] or "—"), d.CELL), Paragraph(r["host"], d.CELL),
                     *((d.pastille_score(r["acr"], sev_acr(r["acr"])), d.pastille_score(r["aes"], sev_aes(r["aes"], ))) if sc else ()),
                     Paragraph(str(r["vulns"]), d.CELLR), d.pastille(r["maxsev"])])
    tab = d.tableau(rows, [W - 114 * mm, 30 * mm, 16 * mm, 16 * mm, 24 * mm, 24 * mm] if sc else [W - 82 * mm, 34 * mm, 24 * mm, 24 * mm])
    bloc = [d.bandeau(s["rank"], s["title"], s["maxsev"], ancre=f"sol{s['rank']}"), Spacer(1, 3),
            Paragraph(meta_txt, d.SMALL), Spacer(1, 5), d.encadre_action(s["action"]), Spacer(1, 4),
            Paragraph(vl, d.SMALL), Spacer(1, 4)]
    if len(rows) <= 12:
        return [CondPageBreak(80 * mm), KeepTogether(bloc + [tab]), Spacer(1, 4)]
    return [CondPageBreak(80 * mm), KeepTogether(bloc), tab, Spacer(1, 4)]


def bloc_machine(d, an, h, sols):
    """Liste à cocher des solutions d'une machine (sols : solutions du plan d'action qui la concernent)."""
    titre = Paragraph(f'{esc(h["dns"] or h["ip"])} <font name="Inter-Regular" color="#5A5A5A" size="9">  {h["ip"]}</font>',
                      st("hh", fontName="Inter-SemiBold", fontSize=10.5, leading=14))
    sous = Paragraph(tr("{vulns} ({sev}) · score de risque {score} · {scores}{actions} à mener",
                        vulns=pluriel(h['n'], 'vulnérabilité'), sev=d.compte_sev(h['counts']), score=h['score'],
                        scores="".join(f"{n} {fmt(h[k])} · " for n, k, a in (("ACR", "acr", an.a_acr), ("AES", "aes", an.a_aes)) if a),
                        actions=pluriel(len(sols), 'action')), d.SMALL)
    rows = [d.entete_tableau(tr("Fait"), tr("N°"), tr("Action"), tr("Vuln. corrigées"), tr("Sévérité max."))]
    for s in sols:
        hr = s["par_hote"][h["ip"]]
        rows.append([Paragraph('<font name="DejaVu" size="11">☐</font>', d.CELLC), Paragraph(str(s["rank"]), d.CELLC),
                     Paragraph(f'<font name="Inter-Medium">{esc(s["title"])}</font><br/>'
                               f'<font size="7.6" color="#5A5A5A">{esc(s["action"])}</font>', d.CELL),
                     Paragraph(str(hr["vulns"]), d.CELLR), d.pastille(hr["maxsev"])])
    t = d.tableau(rows, [10 * mm, 9 * mm, W - 63 * mm, 22 * mm, 22 * mm])
    bloc = [Spacer(1, 2), titre, sous, Spacer(1, 4), t]
    if len(rows) <= 9:
        return [CondPageBreak(55 * mm), KeepTogether(bloc), Spacer(1, 12)]
    return [CondPageBreak(55 * mm), KeepTogether(bloc[:4]), *bloc[4:], Spacer(1, 12)]


def annexe_scores(d, an, titre=True, jauge=True):
    """Définitions de VPR, ACR, AES et CES ; seuls les scores présents dans l'export sont détaillés, VPR toujours."""
    out = [Paragraph(tr("Définition des scores Tenable"), d.H2)]
    for sc in SCORES:
        if sc["sigle"] == "ACR" and not an.a_acr or sc["sigle"] in ("AES", "CES") and not an.a_aes:
            continue
        niv = " · ".join(tr("{n} : {v}", n=n, v=v) for n, v in sc["niveaux"])
        out.append(Paragraph(tr("<b>{sigle} — {nom}</b> ({cible}, échelle {echelle}). {definition} <i>Niveaux : {niv}.</i>",
                                sigle=sc["sigle"], nom=sc["nom"], cible=sc["cible"], echelle=sc["echelle"],
                                definition=sc["definition"], niv=niv), d.BODY))
    if jauge and an.a_aes and an.aes_moy is not None:       # jauge de lecture de l'AES, avec le repère du périmètre
        G.jauge_aes(d.chemin_tmp("jauge_guide.png"), an.aes_moy, tr("Votre périmètre"))
        out += [Spacer(1, 4), Paragraph(tr("Lire l'AES et le CES"), d.CAP), d.image(d.chemin_tmp("jauge_guide.png"), W * 0.92),
                Paragraph(tr("Plus le score est élevé, plus l'exposition est forte (AES pour une machine, CES pour le périmètre) : en dessous de 350 "
                             "elle est faible, de 350 à 649 elle est moyenne, à partir de 650 elle est élevée."), d.SMALL), Spacer(1, 4)]
    out.append(Paragraph(source(), d.SMALL))
    return out


def _texte_score_risque(an):
    mode = an.ponderation if an else "severite"
    if mode == "severite":
        return tr("<b>Score de risque.</b> Chaque vulnérabilité est pondérée selon sa sévérité, avec le barème de sévérité de Tenable "
                  "(celui du score de vulnérabilité de Security Center), quel que soit le produit d'où viennent les données : "
                  "Critique 40, Élevée 10, Moyenne 3, Faible 1. L'impact d'une solution sur la réduction du risque est la somme des "
                  "poids des vulnérabilités qu'elle corrige, rapportée au score total ; il sert à classer les solutions.")
    if mode == "vpr":
        return tr("<b>Score de risque.</b> Chaque vulnérabilité est pondérée par son VPR (Vulnerability Priority Rating, de 0,1 à 10), qui reflète "
                  "la probabilité d'exploitation. Lorsqu'un constat n'a pas de VPR, la valeur médiane de sa sévérité est retenue "
                  "(Critique 9,5 · Élevée 8,0 · Moyenne 5,5 · Faible 2,0). L'impact d'une solution sur la réduction du risque est la somme des "
                  "poids des vulnérabilités qu'elle corrige, rapportée au score total ; il sert à classer les solutions. "
                  "Le score de risque par machine reste calculé par sévérité.")
    return tr("<b>Score de risque.</b> Chaque vulnérabilité est pondérée par son VPR (Vulnerability Priority Rating, de 0,1 à 10), multiplié par la "
              "criticité de la machine : son ACR (Asset Criticality Rating, de 1 à 10) divisé par 10. Lorsqu'un constat n'a pas de VPR, la valeur "
              "médiane de sa sévérité est retenue (Critique 9,5 · Élevée 8,0 · Moyenne 5,5 · Faible 2,0) ; lorsqu'une machine n'a pas d'ACR, "
              "la valeur par défaut de Tenable (5) est utilisée. L'impact d'une solution sur la réduction du risque est la somme des "
              "poids des vulnérabilités qu'elle corrige, rapportée au score total ; il sert à classer les solutions. "
              "Le score de risque par machine reste calculé par sévérité.")


def annexe_methode(d, an=None, titre=True):
    return [Paragraph(tr("Méthode"), d.H2),
            Paragraph(tr("<b>Comptage.</b> Une vulnérabilité est comptée une fois par machine, même si elle est détectée sur plusieurs ports. "
                         "Les constats de sévérité Info sont exclus."), d.BODY),
            Paragraph(_texte_score_risque(an), d.BODY),
            Paragraph(tr("<b>Regroupement en solutions.</b> Les vulnérabilités d'un même produit sont corrigées par une seule action : "
                         "la dernière mise à jour remplace les précédentes. Les textes d'action sont produits à partir des intitulés "
                         "Tenable par un fichier de règles ; les versions cibles sont à confirmer avec les bulletins de l'éditeur avant "
                         "déploiement."), d.BODY),
            Paragraph(tr("<b>Sévérité.</b> Critique : CVSS 9,0 à 10 · Élevée : 7,0 à 8,9 · Moyenne : 4,0 à 6,9 · Faible : 0,1 à 3,9."), d.BODY)]


def guide_lecture(d, an):
    """Page « Comment lire ce rapport » : méthode et définitions des scores, placée juste après la page de titre."""
    return [Paragraph(tr("Comment lire ce rapport"), d.H1),
            Paragraph(tr("Cette page explique comment sont calculés les scores et regroupées les vulnérabilités, "
                         "et ce que signifient les notes Tenable (VPR, ACR, AES, CES) utilisées dans la suite du document."), d.LEAD),
            *annexe_methode(d, an, titre=False), *annexe_scores(d, an, titre=False)]


def generer(an, habillage, sortie):
    d = DocumentPDF(sortie, habillage, tr(NOM), meta(an), produit=an.produit, portee=P.libelle(an.portee))
    story = guide_lecture(d, an)
    story += [PageBreak(), *chapitre_synthese(d, an)]
    story += [PageBreak(), Paragraph(tr("2. Plan d'action : les {n} solutions prioritaires", n=an.top), d.H1),
              Paragraph(tr("Les solutions sont classées par impact sur la réduction du risque : plus une solution fait baisser le score de risque, plus elle "
                           "figure haut dans la liste. Cet impact représente la part du risque total que la solution supprime. Le chapitre 3 détaille chaque "
                           "solution avec la liste des machines sur lesquelles l'appliquer ; le chapitre 4 reprend les mêmes actions "
                           "machine par machine."), d.LEAD),
              tableau_plan(d, an.TOP), Spacer(1, 4),
              Paragraph(tr("Ces {n} solutions réduisent le risque mesuré de {pct}.", n=an.top, pct=pct(an.cum_at(an.top))), d.SMALL)]
    story += [PageBreak(), Paragraph(tr("3. Détail par solution : machines concernées"), d.H1),
              Paragraph(tr("Pour chaque solution : l'action à mener, les vulnérabilités qu'elle corrige et les machines sur lesquelles "
                           "l'appliquer, de la plus exposée à la moins exposée") + (tr(" (AES décroissant).") if an.a_aes else "."), d.LEAD)]
    for i, s in enumerate(an.TOP):
        if i:                                         # filet de séparation entre deux solutions
            story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#BFC5CC"), spaceBefore=2, spaceAfter=12))
        story += bloc_solution(d, s, an)
    story += [PageBreak(), Paragraph(tr("4. Guide de remédiation par machine"), d.H1),
              Paragraph(tr("Pour chaque machine concernée par le plan d'action, la liste des solutions à appliquer, dans l'ordre de "
                           "priorité. La case de gauche permet de suivre l'avancement. Les numéros renvoient au chapitre 3."), d.LEAD)]
    for h in an.machines:
        mine = [s for s in h["sols"] if s["key"] in an.cles_top]
        if mine:
            story += bloc_machine(d, an, h, mine)
    return d.construire(story)
