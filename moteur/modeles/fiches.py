"""Fiches par machine : une fiche autonome par serveur, à remettre aux équipes d'exploitation."""
from reportlab.platypus import CondPageBreak

from .. import portee as P
from ..i18n import tr
from ..commun import (DocumentPDF, W, SEVC, esc, st, mm, Paragraph, Spacer, PageBreak, Table, TableStyle,
                      RULE, MUTED, pluriel)
from .complet import meta, guide_lecture
from ..scores import fmt, sev_acr, sev_aes

NOM = "Fiches de remédiation par machine"


def _fiche(d, an, h, i):
    titre = Paragraph(f'<a name="m{i}"/>{esc(h["dns"] or h["ip"])}', st("ft", fontName="Inter-SemiBold", fontSize=16,
                                                                          leading=20, textColor=d.accent))
    sous = Paragraph(tr("Adresse IP {ip} · score de risque {score} ({pct:.1f} % du risque du périmètre)",
                        ip=h['ip'], score=h['score'], pct=100 * h['score'] / an.total)
                     + "".join(f" · {n} {fmt(h[k])}" for n, k, a in (("ACR", "acr", an.a_acr), ("AES", "aes", an.a_aes)) if a), d.SMALL)
    c = h["counts"]
    tuiles = d.indicateurs([(c.get("Critical", 0), tr("critiques"), SEVC["Critical"]), (c.get("High", 0), tr("élevées"), SEVC["High"]),
                            (c.get("Medium", 0), tr("moyennes"), None), (c.get("Low", 0), tr("faibles"), None),
                            (len(h["sols"]), tr("actions à mener"), None)])
    rows = [d.entete_tableau(tr("Fait"), tr("Ordre"), tr("Action à mener"), tr("Vulnérabilités corrigées"), tr("Sévérité"))]
    for k, s in enumerate(h["sols"], 1):
        hr = s["hosts"][s["hosts"]["host"] == h["ip"]].iloc[0]
        noms = sorted(an.occ[(an.occ.host == h["ip"]) & (an.occ.sol == s["key"])]["Plugin Name"].astype(str).unique())
        liste = "<br/>".join(esc(n[:70]) for n in noms[:3]) + (("<br/>" + tr("et {n} autres", n=len(noms) - 3)) if len(noms) > 3 else "")
        rows.append([Paragraph('<font name="DejaVu" size="11">☐</font>', d.CELLC), Paragraph(str(k), d.CELLC),
                     Paragraph(f'<font name="Inter-Medium">{esc(s["title"])}</font><br/>'
                               f'<font size="7.6" color="#5A5A5A">{esc(s["action"])}</font>', d.CELL),
                     Paragraph(f'<font size="7.2" color="#5A5A5A">{liste}</font>', d.CELL), d.pastille(hr["maxsev"])])
    tab = d.tableau(rows, [10 * mm, 12 * mm, W - 103 * mm, 59 * mm, 22 * mm])
    visa = Table([[Paragraph(tr("Intervenant"), d.CELLH), Paragraph(tr("Date d'intervention"), d.CELLH), Paragraph(tr("Commentaires"), d.CELLH)],
                  ["", "", ""]], colWidths=[W * 0.3, W * 0.25, W * 0.45], rowHeights=[None, 14 * mm])
    visa.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.6, RULE),
                              ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
    return [titre, sous, Spacer(1, 8), tuiles, Spacer(1, 10),
            Paragraph(tr("Actions à mener, par ordre de priorité"), d.H2), tab, Spacer(1, 12),
            CondPageBreak(30 * mm), Paragraph(tr("Suivi de l'intervention"), d.H2), visa]


def generer(an, habillage, sortie):
    d = DocumentPDF(sortie, habillage, tr(NOM), meta(an), produit=an.produit, portee=P.libelle(an.portee))
    sc = [(n, k) for n, k, a in (("ACR", "acr", an.a_acr), ("AES", "aes", an.a_aes)) if a]
    rows = [d.entete_tableau(tr("Machine"), tr("Adresse IP"), tr("Vuln."), tr("Critiques"), tr("Actions"), tr("Score"), *[n for n, _ in sc], droite=tuple(range(2, 6 + len(sc))))]
    for i, h in enumerate(an.machines):
        rows.append([Paragraph(f'<a href="#m{i}" color="#161616">{esc(h["dns"] or h["ip"])}</a>', d.CELLB),
                     Paragraph(h["ip"], d.CELL), Paragraph(str(h["n"]), d.CELLR),
                     Paragraph(str(h["counts"].get("Critical", 0)), d.CELLR), Paragraph(str(len(h["sols"])), d.CELLR),
                     Paragraph(str(h["score"]), d.CELLR), *[d.pastille_score(h[k], (sev_acr if k == 'acr' else sev_aes)(h[k])) for _, k in sc]])
    story = [*guide_lecture(d, an), PageBreak(), Paragraph(tr("Sommaire des fiches"), d.H1),
             Paragraph(tr("{machines}, de la plus exposée à la moins exposée. Chaque fiche est autonome : "
                          "elle liste les actions à mener sur la machine, dans l'ordre de priorité, et peut être remise telle quelle "
                          "à l'équipe qui l'administre. Les intitulés de vulnérabilités sont ceux de Tenable.",
                          machines=pluriel(an.n_hosts, 'machine')), d.LEAD),
             d.tableau(rows, [W - 108 * mm - 14 * mm * len(sc), 34 * mm, 16 * mm, 20 * mm, 18 * mm, 20 * mm] + [12 * mm] * len(sc))]
    for i, h in enumerate(an.machines):
        story += [PageBreak(), *_fiche(d, an, h, i)]
    return d.construire(story)
