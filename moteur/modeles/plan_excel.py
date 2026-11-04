"""Plan d'action Excel : tableau de suivi des solutions (responsable, échéance, statut) et détail par machine."""
from openpyxl import Workbook
from openpyxl.comments import Comment
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

from .. import portee as P
from ..commun import HABILLAGE_DEFAUT, date_fr
from ..i18n import tr, langue
from ..regles import SEV_FR
from ..scores import SCORES, source, fmt

NOM = "Plan d'action (Excel)"          # constantes françaises : à passer dans tr() à l'affichage
STATUTS = ["À faire", "En cours", "Fait", "Risque accepté"]
SEV_FILL = {"Critical": "A4161A", "High": "E8590C", "Medium": "F2A007", "Low": "2F6FCB"}   # clés techniques de sévérité
SEV_TXT = {"Critical": "FFFFFF", "High": "FFFFFF", "Medium": "161616", "Low": "FFFFFF"}

POLICE, POLICE_GRAS, POLICE_TITRE, GRAS = "Arial", "Arial", "Arial", True
F_BASE = Font(name=POLICE, size=10)
F_GRAS = Font(name=POLICE_GRAS, size=10, bold=GRAS)
F_TITRE = Font(name=POLICE_GRAS, size=16, bold=GRAS)
F_GRIS = Font(name=POLICE, size=9, color="5A5A5A")
SAISIE = PatternFill("solid", fgColor="FFF4C2")          # cellules à renseigner


def _theme(theme):
    """Polices et aplats du classeur : Arial par défaut ; en thème Tenable, Aeonik (Light, Regular, Medium : jamais de gras)."""
    global POLICE, POLICE_GRAS, POLICE_TITRE, GRAS, F_BASE, F_GRAS, F_TITRE, F_GRIS, SAISIE
    if theme == "tenable":
        from ..charte import aeonik_disponible
        if aeonik_disponible():
            POLICE, POLICE_GRAS, POLICE_TITRE, GRAS = "Aeonik", "Aeonik Medium", "Aeonik Light", False
        else:
            POLICE, POLICE_GRAS, POLICE_TITRE, GRAS = "Inter", "Inter Medium", "Inter", False
        SAISIE = PatternFill("solid", fgColor="F2F2F2")
        F_GRIS = Font(name=POLICE, size=9, color="5B6062")
    else:
        POLICE, POLICE_GRAS, POLICE_TITRE, GRAS = "Arial", "Arial", "Arial", True
        SAISIE = PatternFill("solid", fgColor="FFF4C2")
        F_GRIS = Font(name=POLICE, size=9, color="5A5A5A")
    F_BASE = Font(name=POLICE, size=10)
    F_GRAS = Font(name=POLICE_GRAS, size=10, bold=GRAS)
    F_TITRE = Font(name=POLICE_TITRE if theme == "tenable" else POLICE_GRAS, size=16, bold=GRAS)
FIN = Side(style="thin", color="D9D9D9")
BORD = Border(bottom=FIN)
WRAP = Alignment(wrap_text=True, vertical="top")


def _note_impact(an):
    base = tr("Impact sur la réduction du risque : part du score de risque total supprimée en appliquant la solution, qui sert à classer les solutions")
    return base + " " + {"severite": tr("(pondération Tenable SC : Critique 40, Élevée 10, Moyenne 3, Faible 1)."),
                   "vpr": tr("(pondération par VPR)."),
                   "vpr_acr": tr("(pondération par VPR et criticité de la machine, ACR).")}[an.ponderation]


def _libelle_ponderation(an):
    return {"severite": tr("Critique 40 · Élevée 10 · Moyenne 3 · Faible 1 (Tenable Security Center)"),
            "vpr": tr("VPR de chaque vulnérabilité (0,1 à 10) ; à défaut, médiane de la sévérité"),
            "vpr_acr": tr("VPR × ACR/10 ; à défaut, médiane de la sévérité et ACR par défaut de 5")}[an.ponderation]


def statuts():
    """Statuts de la liste de validation, dans la langue courante."""
    # clé propre au tableur (« statut:Fait ») : le mot « Fait » peut être traduit autrement ailleurs (cases à cocher)
    return [x if langue() == "fr" else tr("statut:" + x) for x in STATUTS]


def _nom_feuille(nom):
    """Nom de feuille Excel valide (31 caractères au plus, sans caractère interdit)."""
    for c in '[]:*?/\\':
        nom = nom.replace(c, "-")
    return nom[:31]


def _q(nom):
    """Nom de feuille entre apostrophes pour une formule (apostrophe interne doublée)."""
    return "'" + nom.replace("'", "''") + "'"


def _txt(v):
    """Texte entre guillemets dans une formule (guillemets internes doublés)."""
    return '"' + v.replace('"', '""') + '"'


def _entete(ws, ligne, titres, couleur):
    fill = PatternFill("solid", fgColor=couleur)
    for j, t in enumerate(titres, 1):
        c = ws.cell(row=ligne, column=j, value=t)
        c.font = Font(name=POLICE_GRAS, size=10, bold=GRAS, color="FFFFFF")
        c.fill = fill
        c.alignment = Alignment(wrap_text=True, vertical="center")
    ws.row_dimensions[ligne].height = 30


def _largeurs(ws, largeurs):
    for j, w in enumerate(largeurs, 1):
        ws.column_dimensions[get_column_letter(j)].width = w


def _couleurs_severite(ws, plage):
    for sev, fond in SEV_FILL.items():
        ws.conditional_formatting.add(plage, CellIsRule(operator="equal", formula=[_txt(SEV_FR[sev])],
                                                        fill=PatternFill("solid", fgColor=fond),
                                                        font=Font(name=POLICE_GRAS, color=SEV_TXT[sev], bold=GRAS)))


def _couleurs_scores(ws, plage_acr, plage_aes):
    """Mise en forme conditionnelle d'ACR (1-10) et d'AES (0-1000) selon les niveaux Tenable."""
    for plage, bornes in ((plage_acr, [(9, 10, "Critical"), (7, 8.99, "High"), (4, 6.99, "Medium"), (1, 3.99, "Low")]),
                          (plage_aes, [(650, 1000, "High"), (350, 649.99, "Medium"), (0, 349.99, "Low")])):
        for bas, haut, lib in bornes:
            ws.conditional_formatting.add(plage, CellIsRule(operator="between", formula=[str(bas), str(haut)],
                                                            fill=PatternFill("solid", fgColor=SEV_FILL[lib]),
                                                            font=Font(name=POLICE_GRAS, color=SEV_TXT[lib], bold=GRAS)))


def generer(an, habillage, sortie):
    h = {**HABILLAGE_DEFAUT, **(habillage or {})}
    _theme(h.get("theme"))
    accent = (h.get("couleur") or "#000091").lstrip("#").upper()
    wb = Workbook()
    N_PARAM, N_PLAN, N_MACH = _nom_feuille(tr("Paramètres")), _nom_feuille(tr("Plan d'action")), _nom_feuille(tr("Par machine"))
    N_VULN, N_SYNTH, N_DEF = _nom_feuille(tr("Vulnérabilités")), _nom_feuille(tr("Synthèse")), _nom_feuille(tr("Définitions"))
    ST_TODO, ST_DOING, ST_DONE, ST_ACCEPTED = statuts()
    PRIORITAIRE = tr("Plan d'action")                     # valeur de la colonne Priorité pour le plan prioritaire
    LISTE_STATUTS = f"={_q(N_PARAM)}!$A$2:$A${len(STATUTS) + 1}"

    # ------------------------------------------------------------ Paramètres (listes de validation)
    wp = wb.active
    wp.title = N_PARAM

    # ------------------------------------------------------------ Plan d'action
    ws = wb.create_sheet(N_PLAN, 0)
    n = len(an.sols)
    titres = [tr("N°"), tr("Priorité"), tr("Solution"), tr("Action à mener"), tr("Sévérité max."), tr("Vulnérabilités"),
              tr("Machines"), tr("Part du risque"), tr("Machines concernées"), tr("Responsable"), tr("Échéance"),
              tr("Statut"), tr("Commentaire")]
    ws["A1"] = h.get("titre") or tr("Plan d'action")
    ws["A1"].font = F_TITRE
    ws["A2"] = " · ".join(x for x in (h.get("client"), tr("Plan d'action généré le {date}", date=date_fr()), an.nom_fichier) if x)
    ws["A2"].font = F_GRIS
    ws["A3"] = tr("À renseigner : les cellules jaunes (Responsable, Échéance, Statut, Commentaire). "
                  "Le statut se choisit dans la liste ; la feuille Synthèse se met à jour automatiquement.")
    ws["A3"].font = F_GRIS
    L0 = 5
    _entete(ws, L0, titres, accent)
    for i, s in enumerate(an.sols):
        r = L0 + 1 + i
        machines = ", ".join((x.dns or x.host) for x in s["hosts"].itertuples())
        vals = [s["rank"], PRIORITAIRE if s["key"] in an.cles_top else tr("Secondaire"), s["title"], s["action"],
                SEV_FR[s["maxsev"]], s["n_vulns"], len(s["hosts"]), s["pct"] / 100, machines, None, None, ST_TODO, None]
        for j, v in enumerate(vals, 1):
            c = ws.cell(row=r, column=j, value=v)
            c.font = F_BASE
            c.alignment = WRAP
            c.border = BORD
        ws.cell(row=r, column=3).font = F_GRAS
        ws.cell(row=r, column=8).number_format = "0.0%"
        ws.cell(row=r, column=11).number_format = "DD/MM/YYYY"
        for j in (10, 11, 12, 13):
            ws.cell(row=r, column=j).fill = SAISIE
    der = L0 + n
    _largeurs(ws, [6, 13, 38, 70, 12, 13, 10, 11, 40, 18, 13, 15, 30])
    ws.freeze_panes = ws.cell(row=L0 + 1, column=4)
    ws.auto_filter.ref = f"A{L0}:M{der}"
    _couleurs_severite(ws, f"E{L0 + 1}:E{der}")
    ws.conditional_formatting.add(f"A{L0 + 1}:M{der}", FormulaRule(formula=[f'$L{L0 + 1}={_txt(ST_DONE)}'],
                                                                   font=Font(name=POLICE, color="7A7A7A", strike=True)))
    dv = DataValidation(type="list", formula1=LISTE_STATUTS, allow_blank=True,
                        error=tr("Choisissez un statut dans la liste."), errorTitle=tr("Statut"))
    ws.add_data_validation(dv)
    dv.add(f"L{L0 + 1}:L{der}")
    dvd = DataValidation(type="date", operator="greaterThan", formula1="1", allow_blank=True,
                         error=tr("Saisissez une date (JJ/MM/AAAA)."), errorTitle=tr("Échéance"))
    ws.add_data_validation(dvd)
    dvd.add(f"K{L0 + 1}:K{der}")
    ws.cell(row=L0, column=8).comment = Comment(_note_impact(an), tr("Rapport"))

    # ------------------------------------------------------------ Par machine
    wm = wb.create_sheet(N_MACH, 1)
    wm["A1"] = tr("Actions par machine")
    wm["A1"].font = F_TITRE
    wm["A2"] = tr("Le statut global reprend celui de la feuille Plan d'action ; le statut machine permet de suivre "
                  "chaque machine séparément (cellules jaunes).")
    wm["A2"].font = F_GRIS
    L1 = 4
    _entete(wm, L1, [tr("Machine"), tr("Adresse IP"), tr("N°"), tr("Solution"), tr("Vuln. corrigées"), tr("Sévérité max."),
                     tr("Statut global"), tr("Statut machine"), tr("Commentaire")]
            + (["ACR", "AES"] if an.a_acr or an.a_aes else []), accent)
    r = L1
    for hm in an.machines:
        for s in hm["sols"]:
            r += 1
            hr = s["hosts"][s["hosts"]["host"] == hm["ip"]].iloc[0]
            vals = [hm["dns"] or hm["ip"], hm["ip"], s["rank"], s["title"], int(hr["vulns"]), SEV_FR[hr["maxsev"]],
                    f"=IFERROR(INDEX({_q(N_PLAN)}!$L${L0 + 1}:$L${der},MATCH(C{r},{_q(N_PLAN)}!$A${L0 + 1}:$A${der},0)),\"\")",
                    ST_TODO, None]
            if an.a_acr or an.a_aes:
                vals += [None if hm["acr"] != hm["acr"] else float(hm["acr"]), None if hm["aes"] != hm["aes"] else float(hm["aes"])]
            for j, v in enumerate(vals, 1):
                c = wm.cell(row=r, column=j, value=v)
                c.font = F_BASE
                c.alignment = WRAP
                c.border = BORD
            for j in (8, 9):
                wm.cell(row=r, column=j).fill = SAISIE
    _largeurs(wm, [34, 15, 6, 52, 12, 12, 15, 15, 30, 7, 7])
    wm.freeze_panes = "C5"
    if an.a_acr or an.a_aes:
        _couleurs_scores(wm, f"J{L1 + 1}:J{r}", f"K{L1 + 1}:K{r}")
    wm.auto_filter.ref = f"A{L1}:{'K' if an.a_acr or an.a_aes else 'I'}{r}"
    _couleurs_severite(wm, f"F{L1 + 1}:F{r}")
    dvm = DataValidation(type="list", formula1=LISTE_STATUTS, allow_blank=True)
    wm.add_data_validation(dvm)
    dvm.add(f"H{L1 + 1}:H{r}")

    # ------------------------------------------------------------ Vulnérabilités
    wv = wb.create_sheet(N_VULN, 2)
    cols = [tr("Machine"), tr("Adresse IP"), "Plugin", tr("Intitulé Tenable"), tr("Famille"), tr("Sévérité"), "VPR", tr("N° solution"), tr("Solution")] + (["ACR", "AES"] if an.a_acr or an.a_aes else [])
    _entete(wv, 1, cols, accent)
    rang = {s["key"]: s for s in an.sols}
    occ = (an.occ.sort_values(["AES", "weight", "host"], ascending=[False, False, True], na_position="last") if an.a_aes
           else an.occ.sort_values(["weight", "host"], ascending=[False, True]))
    for i, rr in enumerate(occ.to_dict("records"), 2):
        s = rang[rr["sol"]]
        try:
            vpr = float(rr.get("VPR"))
            vpr = None if vpr != vpr else vpr
        except (TypeError, ValueError):
            vpr = None
        vals = [rr["dns"] or rr["host"], rr["host"], int(rr["Plugin"]), rr["Plugin Name"],
                rr["Family"] if isinstance(rr["Family"], str) else "", SEV_FR[rr["Severity"]],
                vpr, s["rank"], s["title"]]
        if an.a_acr or an.a_aes:
            vals += [None if rr["ACR"] != rr["ACR"] else float(rr["ACR"]), None if rr["AES"] != rr["AES"] else float(rr["AES"])]
        for j, v in enumerate(vals, 1):
            c = wv.cell(row=i, column=j, value=v)
            c.font = F_BASE
    _largeurs(wv, [34, 15, 9, 70, 22, 11, 7, 11, 45, 7, 7])
    if an.a_acr or an.a_aes:
        _couleurs_scores(wv, f"J2:J{len(occ) + 1}", f"K2:K{len(occ) + 1}")
    wv.freeze_panes = "A2"
    wv.auto_filter.ref = f"A1:{'K' if an.a_acr or an.a_aes else 'I'}{len(occ) + 1}"
    _couleurs_severite(wv, f"F2:F{len(occ) + 1}")

    # ------------------------------------------------------------ Synthèse (formules)
    sy = wb.create_sheet(N_SYNTH, 0)
    sy["A1"] = h.get("titre") or tr("Plan d'action")
    sy["A1"].font = F_TITRE
    sy["A2"] = " · ".join(x for x in (h.get("client"), tr("Édité le {date}", date=date_fr())) if x)
    sy["A2"].font = F_GRIS
    plan = _q(N_PLAN)
    stat = f"{plan}!$L${L0 + 1}:$L${der}"
    part = f"{plan}!$H${L0 + 1}:$H${der}"
    prio = f"{plan}!$B${L0 + 1}:$B${der}"
    lignes = [
        (tr("Machines analysées"), an.n_hosts, "0", tr("Valeur issue de l'export")),
        (tr("Vulnérabilités"), len(an.occ), "0", tr("Valeur issue de l'export (couples machine / vulnérabilité)")),
        (tr("Solutions"), f"=COUNTA({plan}!$A${L0 + 1}:$A${der})", "0", ""),
        (tr("dont plan d'action prioritaire"), f'=COUNTIF({prio},{_txt(PRIORITAIRE)})', "0", ""),
        (tr("Solutions terminées (Fait)"), f'=COUNTIF({stat},{_txt(ST_DONE)})', "0", ""),
        (tr("Solutions en cours"), f'=COUNTIF({stat},{_txt(ST_DOING)})', "0", ""),
        (tr("Risques acceptés"), f'=COUNTIF({stat},{_txt(ST_ACCEPTED)})', "0", ""),
        (tr("Avancement (solutions terminées)"), "=IFERROR(B8/B6,0)", "0.0%", ""),
        (tr("Part du risque traitée"), f'=SUMIF({stat},{_txt(ST_DONE)},{part})', "0.0%",
         tr("Somme de la part du risque des solutions au statut Fait")),
        (tr("Part du risque restante"), f'=1-B12-SUMIF({stat},{_txt(ST_ACCEPTED)},{part})', "0.0%", tr("Hors risques acceptés")),
    ]
    _entete(sy, 3, [tr("Indicateur"), tr("Valeur"), tr("Note")], accent)
    for i, (lib, val, fmt, note) in enumerate(lignes, 4):
        sy.cell(row=i, column=1, value=lib).font = F_BASE
        c = sy.cell(row=i, column=2, value=val)
        c.font = F_GRAS
        c.number_format = fmt
        sy.cell(row=i, column=3, value=note).font = F_GRIS
        for j in (1, 2, 3):
            sy.cell(row=i, column=j).border = BORD
    _entete(sy, 15, [tr("Sévérité max."), tr("Solutions"), tr("Terminées")], accent)
    for i, lib in enumerate([SEV_FR[x] for x in ("Critical", "High", "Medium", "Low")], 16):
        sy.cell(row=i, column=1, value=lib).font = F_BASE
        sy.cell(row=i, column=2, value=f'=COUNTIF({plan}!$E${L0 + 1}:$E${der},A{i})').font = F_BASE
        sy.cell(row=i, column=3, value=f'=COUNTIFS({plan}!$E${L0 + 1}:$E${der},A{i},{stat},{_txt(ST_DONE)})').font = F_BASE
    _couleurs_severite(sy, "A16:A19")
    sy["A21"] = tr("Mode d'emploi : renseignez Responsable, Échéance et Statut dans la feuille Plan d'action (cellules jaunes). "
                   "Les indicateurs ci-dessus se recalculent automatiquement.")
    sy["A21"].font = F_GRIS
    _largeurs(sy, [36, 14, 60])

    # ------------------------------------------------------------ Paramètres
    wp["A1"] = tr("Statuts")
    wp["A1"].font = F_GRAS
    for i, s in enumerate(statuts(), 2):
        wp.cell(row=i, column=1, value=s).font = F_BASE
    p = an.perimetre
    infos = [(tr("Export analysé"), an.nom_fichier), *([(tr("Périmètre"), P.libelle(an.portee))] if P.libelle(getattr(an, "portee", None)) else []),
             (tr("Sévérités retenues"), ", ".join(SEV_FR[x] for x in p["severites"])),
             (tr("Machines incluses"), p.get("inclure") or tr("toutes")), (tr("Machines exclues"), p.get("exclure") or tr("aucune")),
             (tr("Solutions du plan prioritaire"), an.top),
             (tr("Pondération"), _libelle_ponderation(an))]
    wp["C1"] = tr("Périmètre du rapport")
    wp["C1"].font = F_GRAS
    for i, (k, v) in enumerate(infos, 2):
        wp.cell(row=i, column=3, value=k).font = F_BASE
        wp.cell(row=i, column=4, value=str(v)).font = F_BASE
    _largeurs(wp, [18, 3, 30, 70])

    wd = wb.create_sheet(N_DEF)
    wd["A1"] = tr("Définitions des scores")
    wd["A1"].font = F_TITRE
    _entete(wd, 3, [tr("Score"), tr("Nom"), tr("S'applique à"), tr("Échelle"), tr("Niveaux"), tr("Définition")], accent)
    for i, sc in enumerate(SCORES, 4):
        vals = [sc["sigle"], sc["nom"], sc["cible"], sc["echelle"],
                " · ".join(tr("{n} : {v}", n=n, v=v) for n, v in sc["niveaux"]), sc["definition"]]
        for j, v in enumerate(vals, 1):
            c = wd.cell(row=i, column=j, value=v)
            c.font = F_GRAS if j == 1 else F_BASE
            c.alignment = WRAP
            c.border = BORD
    wd["A8"] = source()
    wd["A8"].font = F_GRIS
    _largeurs(wd, [8, 30, 14, 12, 42, 90])
    wb.save(sortie)
    return sortie
