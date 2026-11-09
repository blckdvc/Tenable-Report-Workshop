"""Logiciels en fin de vie : produits hors support ou dont le support se termine sous 12 mois, calendrier, plan de migration.

Construit à partir d'une AnalyseEol (moteur/eol.py) : les CPE détectés par Tenable, rapprochés d'endoflife.date."""
import datetime as dt

from .. import graphiques as G
from .. import portee as P
from ..commun import (DocumentPDF, W, HABILLAGE_DEFAUT, esc, st, mm, Paragraph, Spacer, PageBreak, KeepTogether,
                      Table, TableStyle, colors, TA_CENTER)
from ..i18n import tr, plur, date_longue, traductions

NOM = "Logiciels en fin de vie"          # constante française : à passer dans tr() à l'affichage
ROUGE, ORANGE = G.COL["Critical"], G.COL["High"]       # couleurs de données : hors support / échéance sous 12 mois


# ---------------------------------------------------------------------------- petits outils
def date_txt(iso):
    return date_longue(dt.date.fromisoformat(iso)) if iso else tr("date inconnue")


def _depuis(a, b):
    """Durée entre les dates a < b, en années et mois, ou en jours quand elle est courte."""
    m = (b.year - a.year) * 12 + b.month - a.month - (1 if b.day < a.day else 0)
    if m >= 12:
        an, reste = divmod(m, 12)
        return plur(an, "an") + (f" {tr('et')} {plur(reste, 'mois', 'mois')}" if reste else "")
    if m >= 1:
        return plur(m, "mois", "mois")
    return plur((b - a).days, "jour")


def ecart(e, auj):
    if not e["eol_date"]:
        return tr("date inconnue")
    d = dt.date.fromisoformat(e["eol_date"])
    return tr("depuis {duree}", duree=_depuis(d, auj)) if d <= auj else tr("dans {duree}", duree=plur((d - auj).days, "jour"))


def nom_produit(e):
    return f"{e['libelle']} {e['cycle']}"


def versions(e, n=3):
    vus = sorted({v for m in e["machines"] for v in m["versions"] if v})
    return ", ".join(vus[:n]) + (" …" if len(vus) > n else "") if vus else "—"


def pastille(d, statut):
    dep = statut == "depassee"
    t = Table([[Paragraph(tr("Dépassée") if dep else tr("Sous 12 mois"),
                          st("pe", fontName="Inter-SemiBold", fontSize=7, leading=9, textColor=colors.white, alignment=TA_CENTER))]],
              colWidths=[21 * mm], rowHeights=[4.6 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(ROUGE if dep else ORANGE)),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]
                          + ([] if d.tenable else [("ROUNDEDCORNERS", [2, 2, 2, 2])])))
    return t


def encadre(d, titre, paragraphes):
    """Encadré de lecture : titre et paragraphes (balises <b> admises, texte déjà échappé)."""
    corps = "<br/><br/>".join(paragraphes)
    t = Table([[Paragraph(f'<font name="Inter-SemiBold" color="{d.accent_hex}">{esc(titre)}</font><br/>{corps}', d.ACT)]], colWidths=[W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), d.pale), ("LINEBEFORE", (0, 0), (0, -1), 2.2, d.accent),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return t


def avertissement(d):
    return encadre(d, tr("À lire avant d'exploiter ce rapport"), [
        tr("<b>Scan authentifié obligatoire.</b> Un logiciel n'est inventorié que si la machine a été analysée avec des identifiants "
           "(scan authentifié) ou par un agent Nessus. Un scan sans authentification ne voit que les services exposés sur le réseau : "
           "les logiciels installés en fin de vie n'y apparaissent pas."),
        tr("<b>Complétude limitée aux logiciels qui déclarent un CPE.</b> Le rapport est exhaustif pour les applications qui enregistrent "
           "un identifiant CPE (cpe:/), ce qui est en principe le cas des logiciels installés de façon standard et reconnus par Tenable. "
           "Un logiciel copié à la main, portable ou inconnu de Tenable peut ne pas être listé."),
    ])


def meta(an):
    produit = tr("Tenable Vulnerability Management") if an.produit == "vm" else tr("Tenable Security Center")
    cible = P.libelle(an.portee)
    volume = tr("{machines} machines inventoriées · {produits} produits en fin de vie ou proches de l'être",
                machines=an.n_hosts, produits=len(an.produits))
    return [(tr("Source des données"), tr("{produit} (plugin CPE) et endoflife.date", produit=produit)),
            *([(tr("Périmètre"), cible)] if cible else []),
            (tr("Volumétrie"), volume),
            (tr("Référentiel consulté le"), date_longue(an.consulte))]


# ---------------------------------------------------------------------------- graphiques
def _x(d):
    return d.year + (d.timetuple().tm_yday - 1) / 365.25


def graphique_calendrier(chemin, produits, auj):
    import matplotlib.pyplot as plt
    lignes = sorted((e for e in produits if e["eol_date"]), key=lambda e: e["eol_date"])
    if not lignes:
        return None
    eols = [dt.date.fromisoformat(e["eol_date"]) for e in lignes]
    debut, fin = min(min(eols).year, auj.year - 3), max(max(eols).year, auj.year) + 1
    fig, ax = plt.subplots(figsize=(6.9, max(1.8, 0.27 * len(lignes) + 0.9)), dpi=300)
    n = len(lignes)
    for i, (e, eol) in enumerate(zip(lignes, eols)):
        y = n - 1 - i
        sortie = dt.date.fromisoformat(e["sortie"]) if e["sortie"] else dt.date(debut, 1, 1)
        x0, xe, xa = max(_x(sortie), debut), _x(eol), _x(auj)
        if eol <= auj:
            ax.barh(y, max(xe - x0, 0), left=x0, color="#CCCCCC", height=0.5)
            ax.barh(y, xa - xe, left=xe, color=ROUGE, height=0.5)
        else:
            ax.barh(y, max(xa - x0, 0), left=x0, color="#CCCCCC", height=0.5)
            ax.barh(y, xe - xa, left=xa, color=ORANGE, height=0.5)
        ax.plot([xe, xe], [y - 0.34, y + 0.34], color="#1E2426", lw=1.4)
    ax.axvline(_x(auj), color="#1E2426", lw=1.2)
    ax.text(_x(auj) + 0.06, n - 0.35, tr("Aujourd'hui"), fontsize=7, fontweight="semibold", va="bottom", color="#1E2426")
    ax.set_xlim(debut, fin)
    ax.set_ylim(-0.6, n + 0.2)
    ax.set_xticks(range(debut, fin + 1), [str(a) for a in range(debut, fin + 1)], fontsize=7.5)
    ax.set_yticks(range(n), [nom_produit(e) for e in lignes[::-1]], fontsize=7.6)
    ax.xaxis.grid(True, color="#E6E6E6", lw=0.6)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    ax.spines["left"].set_visible(False)
    ax2 = ax.twinx()
    ax2.set_ylim(ax.get_ylim())
    ax2.set_yticks(range(n), [e.strftime("%d/%m/%Y") for e in eols[::-1]], fontsize=7.4)
    ax2.tick_params(length=0)
    for s in ("top", "right", "left", "bottom"):
        ax2.spines[s].set_visible(False)
    return G._finish(fig, chemin)


# ---------------------------------------------------------------------------- chapitres
def chapitre_synthese(d, an):
    dep = [e for e in an.produits if e["statut"] == "depassee"]
    av = [e for e in an.produits if e["statut"] == "a_venir"]
    auj = an.aujourdhui
    story = [Paragraph(tr("1. Synthèse"), d.H1)]
    if not an.produits:
        story += [Paragraph(tr("L'analyse porte sur {machines}. Aucun produit détecté n'est hors support ni ne le sera dans les 12 mois, "
                               "parmi ceux que le référentiel endoflife.date couvre.", machines=plur(an.n_hosts, "machine")), d.LEAD),
                  Spacer(1, 6), avertissement(d)]
        return story
    story.append(Paragraph(tr("L'analyse porte sur {machines}. {produits} ont déjà atteint ou atteindront dans les 12 mois la fin de leur support.",
                              machines=plur(an.n_hosts, "machine"), produits=plur(len(an.produits), "produit"))
                           + (" " + tr("Pour {n} d'entre eux, l'éditeur ne publie plus de correctif de sécurité : toute nouvelle vulnérabilité y restera ouverte.",
                                       n=len(dep)) if dep else ""), d.LEAD))
    story.append(d.indicateurs([
        (len(an.produits), tr("produits en fin de vie ou proches de l'être"), None),
        (len(dep), tr("produits déjà hors support"), colors.HexColor(ROUGE) if dep else None),
        (len(av), tr("produits dont le support se termine sous 12 mois"), None),
        (len(an.concernees), tr("machines concernées, sur {n}", n=an.n_hosts), None)]
        + ([(an.vulns_hors_support, tr("vulnérabilités ouvertes sur les produits hors support"), colors.HexColor(ROUGE) if an.vulns_hors_support else None)]
           if an.vulns_hors_support is not None else [])))
    story += [Spacer(1, 12), Paragraph(tr("Situation des produits"), d.H2)]
    blanc = st("bs", fontName="Inter-SemiBold", fontSize=8, leading=10, textColor=colors.white)
    cases = [(len(dep), tr("{n} hors support", n=len(dep)), ROUGE), (len(av), tr("{n} sous 12 mois", n=len(av)), ORANGE)]
    cases = [c for c in cases if c[0]]
    barre = Table([[Paragraph(c[1], blanc) for c in cases]], colWidths=[W * c[0] / len(an.produits) for c in cases], rowHeights=[8 * mm])
    barre.setStyle(TableStyle([*[("BACKGROUND", (i, 0), (i, 0), colors.HexColor(c[2])) for i, c in enumerate(cases)],
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
    story += [barre, Spacer(1, 12)]
    haut = sorted(an.produits, key=lambda e: -len(e["machines"]))[:8]
    G.barres_h([(nom_produit(e), len(e["machines"]), ROUGE if e["statut"] == "depassee" else ORANGE) for e in haut],
               d.chemin_tmp("machines_produit.png"), size=(6.6, 0.3 * len(haut) + 0.55), xlabel=tr("Machines concernées"))
    story += [Paragraph(tr("Produits les plus répandus"), d.H2), d.image(d.chemin_tmp("machines_produit.png"), W * 0.92), Spacer(1, 8)]

    points = []
    if dep:
        top = sorted(dep, key=lambda e: -len(e["machines"]))[:3]
        points.append(tr("<b>Les produits hors support les plus répandus</b> : {liste}.",
                         liste=" ; ".join(f"{esc(nom_produit(e))} ({plur(len(e['machines']), 'machine')})" for e in top)))
        vieux = min((e for e in dep if e["eol_date"]), key=lambda e: e["eol_date"], default=None)
        if vieux:
            points.append(tr("<b>La fin de support la plus ancienne</b> est celle de {produit}, dépassée {ecart}.",
                             produit=esc(nom_produit(vieux)), ecart=ecart(vieux, auj)))
        points.append(tr("<b>{n} machines sur {total}</b> portent au moins un produit hors support.",
                         n=len({m["cle"] for e in dep for m in e["machines"]}), total=an.n_hosts))
    if dep and an.vulns_hors_support:
        gros = sorted((e for e in dep if e.get("vulns")), key=lambda e: -e["vulns"])[:3]
        part = sum(e["vulns"] for e in gros) / max(1, sum(e["vulns"] for e in dep))
        if gros:
            points.insert(0, tr("<b>{n} produits portent {pct} % des vulnérabilités</b> des logiciels hors support : {liste}.", n=len(gros), pct=round(part * 100),
                                liste=", ".join(f"{esc(nom_produit(e))} ({e['vulns']})" for e in gros)))
    proches = sorted((e for e in av if e["eol_date"] and (dt.date.fromisoformat(e["eol_date"]) - auj).days <= 90), key=lambda e: e["eol_date"])
    if proches:
        points.append(tr("<b>Échéances sous 90 jours</b> : {liste}.",
                         liste=" ; ".join(tr("{produit} le {date} ({ecart})", produit=esc(nom_produit(e)), date=date_txt(e["eol_date"]), ecart=ecart(e, auj))
                                          for e in proches[:4])))
    story += [Paragraph(tr("Points clés"), d.H2), *d.puces(points), Spacer(1, 8),
              encadre(d, tr("À lire avant d'exploiter ces chiffres"), [
                  tr("Ils ne couvrent que les machines analysées par scan authentifié ou par agent, et les logiciels qui déclarent un CPE. "
                     "Détails au chapitre 5.")])]
    return story


def chapitre_calendrier(d, an):
    story = [Paragraph(tr("2. Calendrier de fin de support"), d.H1),
             Paragraph(tr("Chaque barre va de la sortie du produit à sa fin de support. En rouge, le temps écoulé depuis cette date ; "
                          "en orange, le support qu'il reste."), d.LEAD)]
    chemin = graphique_calendrier(d.chemin_tmp("calendrier.png"), an.produits, an.aujourdhui)
    if chemin:
        story += [d.image(chemin, W), Spacer(1, 4),
                  Paragraph(tr("Gris : support en cours · rouge : depuis la fin de support · orange : support restant · trait noir : date de fin de support."), d.SMALL)]
    sans = [e for e in an.produits if not e["eol_date"]]
    if sans:
        story.append(Paragraph(tr("Sans date publiée par le référentiel : {liste}.", liste=", ".join(esc(nom_produit(e)) for e in sans)), d.SMALL))
    proches = sorted((e for e in an.produits if e["statut"] == "a_venir" and e["eol_date"]), key=lambda e: e["eol_date"])[:3]
    if proches:
        auj = an.aujourdhui
        story += [Spacer(1, 14), Paragraph(tr("Prochaines échéances"), d.H2),
                  d.indicateurs([(plur((dt.date.fromisoformat(e["eol_date"]) - auj).days, "jour"),
                                  f"<b>{esc(nom_produit(e))}</b><br/>{date_txt(e['eol_date'])} · {plur(len(e['machines']), 'machine')}", None)
                                 for e in proches])]
    return story


def chapitre_inventaire(d, an):
    cell, cellr = d.CELL, d.CELLR
    vu = an.vulns_hors_support is not None
    lignes = [d.entete_tableau(tr("N°"), tr("Produit"), tr("Version détectée"), tr("Fin de support"), tr("Statut"), tr("Machines"),
                               *((tr("Vuln."), tr("AES")) if vu else ()), tr("Version cible"), droite=(5, 6, 7) if vu else (5,))]
    for i, e in enumerate(an.produits, 1):
        lignes.append([Paragraph(str(i), cell), Paragraph(esc(nom_produit(e)), d.CELLB), Paragraph(esc(versions(e)), cell),
                       Paragraph(f"{date_txt(e['eol_date'])}<br/><font size=7 color='#5B6062'>{ecart(e, an.aujourdhui)}</font>", cell),
                       pastille(d, e["statut"]), Paragraph(str(len(e["machines"])), cellr),
                       *((Paragraph(str(e["vulns"]), cellr), Paragraph(str(int(e["aes"])) if e["aes"] else "—", cellr)) if vu else ()),
                       Paragraph(esc(e["cible"] or "—"), cell)])
    occ = sum(len(e["machines"]) for e in an.produits)
    return [Paragraph(tr("3. Inventaire et plan de migration"), d.H1),
            Paragraph(tr("Les produits sont classés par urgence : d'abord ceux qui sont déjà hors support, du plus répandu au moins répandu, "
                         "puis ceux dont l'échéance approche. La version cible est une version encore supportée selon endoflife.date (voir la note de méthode)."), d.LEAD),
            d.tableau(lignes, [7 * mm, 31 * mm, 21 * mm, 28 * mm, 21 * mm, 16 * mm, 13 * mm, 12 * mm, W - 149 * mm] if vu
                       else [8 * mm, 36 * mm, 24 * mm, 32 * mm, 22 * mm, 18 * mm, W - 140 * mm]), Spacer(1, 6),
            Paragraph(tr("{produits} · {occ} occurrences sur {machines} (une machine peut porter plusieurs produits).",
                         produits=plur(len(an.produits), "produit"), occ=occ, machines=plur(len(an.concernees), "machine")), d.SMALL)]


def fiche(d, an, i, e):
    cible = e["cible"]
    if cible and e.get("cible_ancienne"):
        avis = tr("Cette version est plus ancienne que celle installée, mais c'est la seule encore supportée selon endoflife.date.")
    else:
        avis = None
    if e["statut"] == "depassee":
        if not cible:
            action = tr("Migrer vers une version encore supportée par l'éditeur.")
        elif avis:
            action = tr("Migrer vers {cible}.", cible=cible) + " " + avis
        elif e.get("cible_lts"):
            action = tr("Migrer vers {cible}, version à support long encore supportée selon endoflife.date.", cible=cible)
        else:
            action = tr("Migrer vers {cible}, la version la plus récente encore supportée selon endoflife.date.", cible=cible)
        action += " " + tr("Tant que la migration n'est pas faite, isoler les machines concernées et limiter leurs flux entrants.")
    else:
        action = (tr("Planifier la migration vers {cible} avant le {date}.", cible=cible, date=date_txt(e["eol_date"])) if cible
                  else tr("Planifier la migration vers une version supportée avant le {date}.", date=date_txt(e["eol_date"])))
        if avis:
            action += " " + avis
    statut = tr("fin de support dépassée") if e["statut"] == "depassee" else tr("fin de support sous 12 mois")
    cycle = tr("Fin de support : {date} ({ecart}).", date=date_txt(e["eol_date"]), ecart=ecart(e, an.aujourdhui))
    if e["deduit"]:
        cycle += " " + tr("Version plus ancienne que tous les cycles connus d'endoflife.date : date de fin de support du plus ancien cycle.")
    tete = KeepTogether([d.bandeau(i, tr("Migrer {produit}", produit=nom_produit(e))), Spacer(1, 3),
                         Paragraph(f"{plur(len(e['machines']), 'machine')} · {statut}", d.SMALL), Spacer(1, 3),
                         d.encadre_action(action), Spacer(1, 3), Paragraph(esc(cycle), d.SMALL), Spacer(1, 4)])
    lignes = [d.entete_tableau(tr("Machine"), tr("Adresse IP"), tr("Version détectée"))]
    for m in e["machines"][:40]:
        lignes.append([Paragraph(esc(m["nom"] or m["ip"]), d.CELL), Paragraph(esc(m["ip"] or "—"), d.CELL),
                       Paragraph(esc(", ".join(v for v in m["versions"] if v) or "—"), d.CELL)])
    out = [tete, d.tableau(lignes, [W * 0.45, W * 0.2, W * 0.35])]
    if len(e["machines"]) > 40:
        out.append(Paragraph(tr("… et {n} autres machines.", n=len(e["machines"]) - 40), d.SMALL))
    return out + [Spacer(1, 12)]


def chapitre_fiches(d, an):
    story = [Paragraph(tr("4. Fiches par produit"), d.H1),
             Paragraph(tr("Pour chaque produit : l'action à mener, les étapes de son cycle de vie et les machines concernées."), d.LEAD)]
    for i, e in enumerate(an.produits, 1):
        story += fiche(d, an, i, e)
    return story


def chapitre_methode(d, an):
    cause = {"absent": tr("Inconnu d'endoflife.date"), "sans_version": tr("Version non renseignée"),
             "sans_cycle": tr("Version absente des cycles connus")}
    notions = [
        (tr("Détection"), tr("Les logiciels sont repérés par le plugin Tenable {plugin} (Common Platform Enumeration), qui liste les identifiants CPE "
                             "des logiciels installés sur chaque machine. Le nom et la version de chaque CPE sont rapprochés d'endoflife.date.", plugin=45590)),
        (tr("Date de fin de support"), tr("Date de fin de vie publiée par endoflife.date pour le cycle de la version détectée. "
                                          "Les supports payants (Ubuntu Pro, mises à jour de sécurité étendues de Microsoft) ne sont pas pris en compte.")),
        (tr("Statut"), tr("Dépassée : la date est passée. Sous 12 mois : la date tombe dans l'année qui vient. "
                          "Les produits dont le support dépasse 12 mois ne sont pas listés.")),
        (tr("Version cible"), tr("Une version encore supportée selon le référentiel, plus récente que celle détectée, en version à support long (LTS) quand il en existe une. "
                                 "Si seule une version plus ancienne reste supportée, c'est elle qui est indiquée et la fiche le précise. "
                                 "Elle est à valider avec les contraintes de chaque application.")),
        (tr("Ce qui n'est pas couvert"), tr("Un logiciel qui ne déclare pas de CPE, ou que le référentiel ne connaît pas, n'apparaît pas dans les chiffres. "
                                            "Il figure alors dans la liste ci-dessous, quand sa présence est connue.")),
    ]
    tab = d.tableau([d.entete_tableau(tr("Notion"), tr("En clair"))] + [[Paragraph(esc(a), d.CELLB), Paragraph(esc(b), d.CELL)] for a, b in notions],
                    [34 * mm, W - 34 * mm])
    story = [Paragraph(tr("5. Méthode et sources"), d.H1),
             Paragraph(tr("Cette page explique comment les produits sont repérés, comment leur date de fin de support est établie "
                          "et ce que ce rapport ne couvre pas."), d.LEAD),
             avertissement(d), Spacer(1, 10), tab]
    n = len(an.non_rapproches)
    if n:
        lignes = [d.entete_tableau(tr("Logiciel détecté (CPE)"), tr("Machines"), tr("Cause"), droite=(1,))]
        for o in an.non_rapproches[:15]:
            lignes.append([Paragraph(esc(o["cpe"]), d.CELL), Paragraph(str(len(o["machines"])), d.CELLR), Paragraph(cause[o["cause"]], d.CELL)])
        story += [Spacer(1, 10), Paragraph(tr("Logiciels détectés sans date de fin de support ({n})", n=n), d.H2),
                  Paragraph(tr("Ces logiciels n'ont pas pu être situés dans le référentiel. Ils ne sont pas comptés dans les chiffres du rapport.")
                            + (" " + tr("Les {k} plus répandus sont listés.", k=15) if n > 15 else ""), d.SMALL),
                  Spacer(1, 3), d.tableau(lignes, [W * 0.6, W * 0.12, W * 0.28])]
    story += [Spacer(1, 10), Paragraph(tr("Sources"), d.H2),
              *d.puces([tr("Tenable {produit} : constats du plugin {plugin} (CPE des logiciels installés).",
                           produit="Vulnerability Management" if an.produit == "vm" else "Security Center", plugin=45590),
                        tr("endoflife.date, interrogé le {date} : dates de fin de support, dernière version supportée de chaque produit.",
                           date=date_longue(an.consulte))])]
    return story


def generer(an, habillage, sortie):
    habillage = dict(habillage or {})
    if not habillage.get("titre") or habillage["titre"] in traductions(HABILLAGE_DEFAUT["titre"]):
        habillage["titre"] = tr("Rapport de logiciels en fin de vie")        # le titre par défaut parle de vulnérabilités
    d = DocumentPDF(sortie, habillage, tr(NOM), meta(an), produit=an.produit, portee=P.libelle(an.portee))
    story = chapitre_synthese(d, an)
    if an.produits:
        story += [PageBreak(), *chapitre_calendrier(d, an), PageBreak(), *chapitre_inventaire(d, an),
                  PageBreak(), *chapitre_fiches(d, an)]
    story += [PageBreak(), *chapitre_methode(d, an)]
    return d.construire(story)
