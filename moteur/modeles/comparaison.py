"""Comparaison de deux exports : vulnérabilités corrigées, nouvelles et persistantes, évolution du risque."""
from .. import graphiques as G
from collections import Counter

from .. import portee as P
from ..analyse import libelle_machine
from ..commun import (DocumentPDF, W, SEVC, BON, MAUVAIS, FR, esc, mm, Paragraph, Spacer, PageBreak, KeepTogether,
                      pluriel)
from ..regles import SEV_ORDER
from ..i18n import tr
from .complet import guide_lecture

NOM = "Évolution entre deux analyses"          # constante française : à passer dans tr() à l'affichage


def pct(v, dec=1, signe=False):
    """Pourcentage dans la langue courante (« 12 % » en français, « 12% » en anglais)."""
    return tr("{v} %", v=f"{v:+.{dec}f}" if signe else f"{v:.{dec}f}")


def calculer(avant, apres):
    a = avant.occ.set_index(["host", "Plugin"])
    b = apres.occ.set_index(["host", "Plugin"])
    hotes_b = set(apres.occ["host"])
    hotes_a = set(avant.occ["host"])
    # machine réanalysée : présente dans l'export récent, quelle que soit la sévérité (une machine entièrement corrigée
    # n'y garde parfois que des constats Info, retirés de l'analyse)
    revues = getattr(apres, "hotes_scannes", None) or hotes_b
    ka, kb = set(a.index), set(b.index)
    corrigees = {k for k in ka - kb if k[0] in revues}       # machine réanalysée, vulnérabilité disparue
    non_revues = {k for k in ka - kb if k[0] not in revues}
    nouvelles = kb - ka
    persistantes = ka & kb
    poids_a, poids_b = a["weight"].groupby(level=[0, 1]).first(), b["weight"].groupby(level=[0, 1]).first()

    def poids(df, keys):
        if not keys:
            return 0
        serie = poids_a if df is a else poids_b
        return int(serie.reindex(list(keys)).fillna(0).sum())
    score_a, score_b = avant.occ.groupby("host")["weight"].sum(), apres.occ.groupby("host")["weight"].sum()
    dns_a, dns_b = avant.occ.groupby("host")["dns"].first(), apres.occ.groupby("host")["dns"].first()
    n_corr, n_nouv = Counter(k[0] for k in corrigees), Counter(k[0] for k in nouvelles)
    machines = []
    for h in sorted(hotes_a | hotes_b):
        sa, sb = int(score_a.get(h, 0)), int(score_b.get(h, 0))
        dns = dns_b.get(h) if h in dns_b.index else dns_a.get(h, "")
        machines.append(dict(ip=h, dns=dns or "", avant=sa, apres=sb, delta=sb - sa, corr=n_corr[h], nouv=n_nouv[h],
                             statut="non réanalysée" if h not in revues else ("nouvelle" if h not in hotes_a else "")))
    sol_a = {s["key"]: s for s in avant.sols}
    sol_b = {s["key"]: s for s in apres.sols}
    solutions = []
    for k in set(sol_a) | set(sol_b):
        sa, sb = sol_a.get(k), sol_b.get(k)
        wa, wb = (sa or {}).get("weight", 0), (sb or {}).get("weight", 0)
        if sb is None:
            statut = "Terminée"
        elif sa is None:
            statut = "Nouvelle"
        elif wb < wa:
            statut = "En cours"
        elif wb > wa:
            statut = "Aggravée"
        else:
            statut = "Inchangée"
        ref = sb or sa
        solutions.append(dict(titre=ref["title"], sev=ref["maxsev"], avant=wa, apres=wb, statut=statut,
                              m_avant=len(sa["hosts"]) if sa else 0, m_apres=len(sb["hosts"]) if sb else 0))
    ordre = {"Aggravée": 0, "Nouvelle": 1, "Inchangée": 2, "En cours": 3, "Terminée": 4}
    solutions.sort(key=lambda s: (ordre[s["statut"]], -max(s["avant"], s["apres"])))
    return dict(corrigees=corrigees, nouvelles=nouvelles, persistantes=persistantes, non_revues=non_revues,
                score_avant=avant.total, score_apres=apres.total,
                score_corrige=poids(a, corrigees), score_nouveau=poids(b, nouvelles),
                machines=machines, solutions=solutions, sev_avant=avant.sev_occ, sev_apres=apres.sev_occ)


def generer(avant, apres, habillage, sortie):
    c = calculer(avant, apres)
    var = 100 * (c["score_apres"] - c["score_avant"]) / c["score_avant"] if c["score_avant"] else 0
    meta = [(tr("Export précédent"), tr("{fichier} ({n} machines, {v} vulnérabilités)",
                                        fichier=avant.nom_fichier, n=avant.n_hosts, v=len(avant.occ))),
            (tr("Export récent"), tr("{fichier} ({n} machines, {v} vulnérabilités)",
                                     fichier=apres.nom_fichier, n=apres.n_hosts, v=len(apres.occ)))]
    cp, ca = P.libelle(getattr(avant, "portee", None)), P.libelle(getattr(apres, "portee", None))
    if cp or ca:                                          # même sélection : une seule ligne ; sinon les deux, pour que l'écart soit visible
        if P.identique(getattr(avant, "portee", None), getattr(apres, "portee", None)):
            meta.append((tr("Périmètre"), cp))
        else:
            meta += [(tr("Périmètre précédent"), cp or tr("non précisé")), (tr("Périmètre récent"), ca or tr("non précisé"))]
    d = DocumentPDF(sortie, habillage, tr(NOM), meta, produit=apres.produit,
                    portee=ca if P.identique(getattr(avant, "portee", None), getattr(apres, "portee", None)) else "")
    G.compare_severity(c["sev_avant"], c["sev_apres"], d.chemin_tmp("cmp_sev.png"), accent=d.accent_hex)
    lignes = sorted([m for m in c["machines"] if m["delta"] and m["statut"] != "non réanalysée"], key=lambda m: -abs(m["delta"]))[:12]
    if lignes:
        G.host_delta([(f"{libelle_machine(m['dns'], m['ip'])}  ({m['ip']})", m["delta"]) for m in lignes], d.chemin_tmp("cmp_hosts.png"))

    points = [(tr("<b>Le score de risque est en baisse de {v}</b> : {a} → {b}.", v=pct(abs(var), 0), a=c['score_avant'], b=c['score_apres'])
               if var < 0 else
               tr("<b>Le score de risque est en hausse de {v}</b> : {a} → {b}.", v=pct(abs(var), 0), a=c['score_avant'], b=c['score_apres'])),
              tr("<b>{vulns}</b> sur les machines analysées dans les deux exports, soit {pts} points de risque en moins.",
                 vulns=pluriel(len(c['corrigees']), 'vulnérabilité corrigée', 'vulnérabilités corrigées'), pts=c['score_corrige']),
              tr("<b>{vulns}</b> ({pts} points de risque), dues à de nouvelles publications ou à de nouvelles machines.",
                 vulns=pluriel(len(c['nouvelles']), 'nouvelle vulnérabilité', 'nouvelles vulnérabilités'), pts=c['score_nouveau']),
              tr("{vulns} d'un export à l'autre.",
                 vulns=pluriel(len(c['persistantes']), 'vulnérabilité persistante', 'vulnérabilités persistantes'))]
    if c["non_revues"]:
        n = len({k[0] for k in c["non_revues"]})
        points.append(tr("{machines} du premier export n'apparaît pas dans le second : ses {v} vulnérabilités ne sont pas comptées comme corrigées.",
                         machines=pluriel(n, 'machine'), v=len(c['non_revues'])) if n == 1 else
                      tr("{machines} du premier export n'apparaissent pas dans le second : leurs {v} vulnérabilités ne sont pas comptées comme corrigées.",
                         machines=pluriel(n, 'machine'), v=len(c['non_revues'])))
    story = [*guide_lecture(d, apres), PageBreak(), Paragraph(tr("1. Synthèse de l'évolution"), d.H1),
             Paragraph(tr("Ce rapport compare deux exports Tenable analysés avec le même périmètre et les mêmes "
                          "règles. Une vulnérabilité est considérée comme corrigée si elle a disparu d'une machine réanalysée, "
                          "c'est-à-dire présente dans l'export récent."), d.LEAD),
             d.indicateurs([(pct(var, 0, signe=True), tr("évolution du score de risque"), BON if var < 0 else MAUVAIS),
                            (len(c["corrigees"]), tr("vulnérabilités corrigées"), BON),
                            (len(c["nouvelles"]), tr("nouvelles vulnérabilités"), MAUVAIS),
                            (len(c["persistantes"]), tr("vulnérabilités persistantes"), None)]),
             Spacer(1, 10), Paragraph(tr("Points clés"), d.H2), *d.puces(points), Spacer(1, 8),
             KeepTogether([Paragraph(tr("Vulnérabilités par sévérité"), d.CAP), d.image(d.chemin_tmp("cmp_sev.png"), W * 0.62)])]
    if lignes:
        story += [Spacer(1, 6), KeepTogether([Paragraph(tr("Machines dont le risque a le plus évolué"), d.CAP),
                                               d.image(d.chemin_tmp("cmp_hosts.png"), W)])]

    # solutions
    sym = {"Terminée": BON, "En cours": BON, "Nouvelle": MAUVAIS, "Aggravée": MAUVAIS, "Inchangée": None}
    rows = [d.entete_tableau(tr("Solution"), tr("Sévérité"), tr("Machines"), tr("Score avant"), tr("Score après"), tr("Statut"))]
    for s in c["solutions"]:
        col = sym[s["statut"]]
        lib_statut = tr(s["statut"])
        statut = (f'<font name="Inter-SemiBold" color="#{col.hexval()[2:]}">{lib_statut}</font>' if col else lib_statut)
        rows.append([Paragraph(esc(s["titre"]), d.CELLB), d.pastille(s["sev"]),
                     Paragraph(f"{s['m_avant']} → {s['m_apres']}", d.CELLR), Paragraph(str(s["avant"]), d.CELLR),
                     Paragraph(str(s["apres"]), d.CELLR), Paragraph(statut, d.CELL)])
    story += [PageBreak(), Paragraph(tr("2. Avancement par solution"), d.H1),
              Paragraph(tr("Statuts : <b>Terminée</b>, plus aucune vulnérabilité ; <b>En cours</b>, score en baisse ; "
                           "<b>Inchangée</b> ; <b>Aggravée</b>, score en hausse ; <b>Nouvelle</b>, absente du premier export."), d.LEAD),
              d.tableau(rows, [W - 108 * mm, 22 * mm, 20 * mm, 20 * mm, 20 * mm, 26 * mm])]

    # machines
    rows = [d.entete_tableau(tr("Machine"), tr("Adresse IP"), tr("Score avant"), tr("Score après"), tr("Corrigées"), tr("Nouvelles"))]
    for m in sorted(c["machines"], key=lambda m: (m["statut"] == "non réanalysée", -m["apres"], -m["avant"])):
        nom = esc(m["dns"] or m["ip"]) + (f' <font size="7" color="#5A5A5A">({tr(m["statut"])})</font>' if m["statut"] else "")
        rows.append([Paragraph(nom, d.CELL), Paragraph(m["ip"], d.CELL), Paragraph(str(m["avant"]), d.CELLR),
                     Paragraph(str(m["apres"]), d.CELLR), Paragraph(str(m["corr"]), d.CELLR), Paragraph(str(m["nouv"]), d.CELLR)])
    story += [PageBreak(), Paragraph(tr("3. Évolution par machine"), d.H1),
              d.tableau(rows, [W - 120 * mm, 32 * mm, 22 * mm, 22 * mm, 22 * mm, 22 * mm])]

    # nouvelles critiques / élevées et critiques persistantes
    def liste(an, cles, titre, vide):
        occ = an.occ[an.occ["Severity"].isin(("Critical", "High"))].drop_duplicates(["host", "Plugin"]).set_index(["host", "Plugin"])
        garde = [k for k in cles if k in occ.index]
        sel = list(zip(garde, (r for _, r in occ.loc[garde].iterrows()))) if garde else []
        sel.sort(key=lambda kv: (-SEV_ORDER[kv[1]["Severity"]], kv[0][0]))
        out = [Paragraph(titre, d.H2)]
        if not sel:
            return out + [Paragraph(vide, d.BODY)]
        rows = [d.entete_tableau(tr("Machine"), tr("Vulnérabilité (intitulé Tenable)"), tr("Sévérité"))]
        for (h, _), r in sel[:60]:
            rows.append([Paragraph(esc(r["dns"] or h), d.CELL), Paragraph(esc(str(r["Plugin Name"])), d.CELL), d.pastille(r["Severity"])])
        out.append(d.tableau(rows, [50 * mm, W - 72 * mm, 22 * mm]))
        if len(sel) > 60:
            out.append(Paragraph(tr("… et {n} autres.", n=len(sel) - 60), d.SMALL))
        return out
    story += [PageBreak(), Paragraph(tr("4. Points d'attention"), d.H1),
              *liste(apres, c["nouvelles"], tr("Nouvelles vulnérabilités critiques et élevées"), tr("Aucune nouvelle vulnérabilité critique ou élevée.")),
              Spacer(1, 10),
              *liste(apres, c["persistantes"], tr("Vulnérabilités critiques et élevées persistantes"), tr("Aucune vulnérabilité critique ou élevée persistante."))]
    return d.construire(story)
