"""Exemples de rapports avec des données fictives : montrent, page par page, ce que produit chaque modèle.

Le jeu de données est inventé (machines en « exemple.local », plugins Tenable réalistes). Le rapport est produit avec le
vrai moteur, l'habillage du profil et la langue courante ; les pages PDF sont converties en images (pypdfium2), les
classeurs Excel en tableaux HTML feuille par feuille.
"""
import csv
import hashlib
import html
import json
import os
import threading

from .i18n import tr, langue

# (nom court, adresse IP, ACR, AES, système) — les noms de machines sont fictifs
MACHINES = [
    ("db-prod-01", "10.20.2.21", 10, 905, "lin"), ("ad-dc-01", "10.20.5.51", 10, 880, "win"),
    ("db-prod-02", "10.20.2.22", 10, 860, "lin"), ("web-prod-01", "10.20.1.11", 9, 812, "lin"),
    ("web-prod-02", "10.20.1.12", 9, 790, "lin"), ("esx-01", "10.20.6.61", 9, 770, "esx"),
    ("vcenter-01", "10.20.6.60", 9, 745, "vc"), ("app-erp-01", "10.20.3.32", 8, 702, "win"),
    ("ad-dc-02", "10.20.5.52", 10, 700, "win"), ("vpn-gw-01", "10.20.8.81", 8, 690, "net"),
    ("app-crm-01", "10.20.3.31", 7, 640, "win"), ("fs-paris-01", "10.20.4.41", 6, 515, "win"),
    ("backup-nas-01", "10.20.9.91", 6, 480, "lin"), ("mail-relay-01", "10.20.7.71", 5, 430, "lin"),
    ("srv-test-07", "10.40.1.7", 2, 305, "old"), ("pc-compta-12", "10.30.1.12", 3, 210, "win"),
    ("pc-rh-04", "10.30.1.34", 3, 180, "win"),
]
# plugin, nom, famille, sévérité, VPR, CVE, port, machines (noms courts) ou catégorie
PLUGINS = [
    (151890, "Oracle Java SE 8 < 8u401 Multiple Vulnerabilities (January 2024 CPU)", "Windows", "Critical", 9.4, "CVE-2024-20918", 445,
     ["app-erp-01", "app-crm-01", "pc-compta-12", "pc-rh-04", "fs-paris-01"]),
    (192010, "KB5040442: Windows Server 2022 Security Update (July 2024)", "Windows : Microsoft Bulletins", "High", 8.1, "CVE-2024-38112", 445,
     ["ad-dc-01", "ad-dc-02", "app-erp-01", "app-crm-01", "fs-paris-01"]),
    (192011, "KB5040434: Windows 10 Version 22H2 Security Update (July 2024)", "Windows : Microsoft Bulletins", "High", 7.4, "CVE-2024-38080", 445,
     ["pc-compta-12", "pc-rh-04"]),
    (190512, "VMware ESXi 7.0 < ESXi70U3p-23307199 Multiple Vulnerabilities (VMSA-2024-0006)", "Misc.", "Critical", 9.0, "CVE-2024-22252", 443,
     ["esx-01"]),
    (190830, "VMware vCenter Server 7.0 < 7.0 U3q Multiple Vulnerabilities (VMSA-2024-0012)", "Misc.", "High", 8.4, "CVE-2024-22274", 443,
     ["vcenter-01"]),
    (200311, "RHEL 8 : kernel (RHSA-2024:3306)", "Red Hat Local Security Checks", "High", 7.8, "CVE-2024-1086", 0,
     ["web-prod-01", "web-prod-02", "db-prod-01", "db-prod-02", "backup-nas-01", "mail-relay-01"]),
    (200312, "RHEL 8 : openssh (RHSA-2024:4312)", "Red Hat Local Security Checks", "Critical", 9.8, "CVE-2024-6387", 0,
     ["web-prod-01", "web-prod-02", "db-prod-01", "mail-relay-01"]),
    (57608, "SMB Signing not required", "Misc.", "Medium", 4.0, "", 445,
     ["ad-dc-01", "ad-dc-02", "app-erp-01", "app-crm-01", "fs-paris-01", "pc-compta-12", "pc-rh-04"]),
    (26928, "SSL Weak Cipher Suites Supported", "Service detection", "Medium", 5.1, "CVE-2016-2183", 443,
     ["web-prod-01", "web-prod-02", "vpn-gw-01", "mail-relay-01"]),
    (104743, "TLS Version 1.0 Protocol Detection", "Service detection", "Medium", 4.4, "", 443,
     ["web-prod-01", "web-prod-02", "vpn-gw-01", "mail-relay-01", "app-crm-01"]),
    (108797, "Unsupported Windows OS (remote)", "Windows", "Critical", 7.7, "", 445, ["srv-test-07"]),
    (177850, "Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-iosxe-webui-privesc-j22SaA4z)", "CISCO", "Critical", 9.9,
     "CVE-2023-20198", 443, ["vpn-gw-01"]),
    (194100, "Apache Log4j 1.x End of Life (CVE-2021-44228)", "Misc.", "Critical", 9.6, "CVE-2021-44228", 8080, ["app-crm-01", "app-erp-01"]),
    (370210, "RHEL 9 : php (RHSA-2026:87151)", "Red Hat Local Security Checks", "Critical", 9.6, "CVE-2026-109618, CVE-2026-109619", 0,
     ["web-prod-01", "web-prod-02"]),
    (369483, "PHP < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 Multiple Vulnerabilities", "CGI abuses", "Critical", 9.6,
     "CVE-2026-109618, CVE-2026-109619", 0, ["app-crm-01"]),
    (369483, "PHP < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 Multiple Vulnerabilities", "CGI abuses", "Critical", 9.6,
     "CVE-2026-109618, CVE-2026-109619", 8080, ["app-erp-01", "vpn-gw-01"]),
    (370006, "Linux Distros Unpatched Vulnerability : CVE-2026-109618", "Misc.", "Critical", 9.2, "CVE-2026-109618", 0, ["mail-relay-01"]),
    (153953, "SSH Weak Key Exchange Algorithms Enabled", "Misc.", "Low", 2.4, "", 22, ["db-prod-01", "db-prod-02", "backup-nas-01"]),
]
# précédent export : une campagne plus tôt (ce qui a été corrigé depuis, et ce qui est apparu depuis)
ANCIEN_EXTRA = [
    (192012, "KB5039212: Windows Server 2022 Security Update (June 2024)", "Windows : Microsoft Bulletins", "High", 7.2, "CVE-2024-30080", 445,
     ["ad-dc-01", "ad-dc-02", "app-erp-01", "app-crm-01", "fs-paris-01"]),
]
ANCIEN_SANS = {"Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-iosxe-webui-privesc-j22SaA4z)",
               "Unsupported Windows OS (remote)", "SMB Signing not required"}
COLONNES = ["Plugin", "Plugin Name", "Family", "Severity", "IP Address", "DNS Name", "NetBIOS Name", "Protocol", "Port", "VPR", "ACR", "AES",
            "CVE", "Repository", "Last Observed", "Solution", "Synopsis"]


def ecrire_jeu(chemin, ancien=False, nb_machines=None):
    """Écrit un export fictif au format CSV de Security Center. `nb_machines` limite aux machines les plus exposées."""
    machines = {m[0]: m for m in MACHINES[:nb_machines] if True}
    plugins = [p for p in PLUGINS if not (ancien and p[1] in ANCIEN_SANS)] + (ANCIEN_EXTRA if ancien else [])
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(COLONNES)
        for pid, nom, fam, sev, vpr, cve, port, noms in plugins:
            for n in noms:
                if n not in machines:
                    continue
                _, ip, acr, aes, _ = machines[n]
                w.writerow([pid, nom, fam, sev, ip, f"{n}.exemple.local", n.upper(), "TCP", port, vpr, acr, aes, cve,
                            "Production", "2026-10-24 02:14:07", "", ""])
    return chemin


def _analyse(chemin, perimetre, nom):
    from .analyse import Analyse
    return Analyse(chemin, perimetre, nom_fichier=nom)


def cle_apercu(modele, habillage, perimetre, code, mtime_logo=0):
    brut = json.dumps([modele, habillage, perimetre, code, mtime_logo, "v2"], sort_keys=True, default=str)
    return hashlib.sha1(brut.encode()).hexdigest()[:16]


def produire(modele_id, modele, habillage, dossier):
    """Génère le rapport d'exemple dans `dossier` ; renvoie le chemin du fichier produit."""
    os.makedirs(dossier, exist_ok=True)
    nb = 5 if modele_id == "fiches" else None            # fiches : une page par machine, 5 suffisent à montrer le principe
    perimetre = {"top": 6, "severites": ["Critical", "High", "Medium", "Low"]}
    hab = dict(habillage)
    hab["client"] = hab.get("client") or tr("Client exemple")
    recent = ecrire_jeu(os.path.join(dossier, "export-exemple.csv"), nb_machines=nb)
    a1 = _analyse(recent, perimetre, "export-exemple.csv")
    sortie = os.path.join(dossier, f"exemple.{modele['format']}")
    if modele["exports"] == 2:
        prec = ecrire_jeu(os.path.join(dossier, "export-precedent.csv"), ancien=True, nb_machines=nb)
        modele["module"].generer(_analyse(prec, perimetre, "export-precedent.csv"), a1, hab, sortie)
    else:
        modele["module"].generer(a1, hab, sortie)
    return sortie, a1


# ------------------------------------------------------------------ pages PDF
PDFIUM = threading.Lock()          # PDFium n'est pas utilisable par deux fils à la fois


def pages_pdf(pdf_chemin, dossier, dpi=75):
    """Convertit le PDF en images page-N.png ; renvoie [{n, titre}] (titre = texte le plus gros de la page)."""
    with PDFIUM:
        return _pages_pdf(pdf_chemin, dossier, dpi)


def _pages_pdf(pdf_chemin, dossier, dpi):
    import pypdfium2 as pdfium
    doc = pdfium.PdfDocument(pdf_chemin)
    pages = []
    for i in range(len(doc)):
        page = doc[i]
        page.render(scale=dpi / 72).to_pil().save(os.path.join(dossier, f"page-{i + 1}.png"))
        pages.append({"n": i + 1, "titre": tr("Page de couverture") if i == 0 else _titre(page)})
        page.close()
    doc.close()
    return pages


def _titre(page):
    """Ligne dont la police est la plus grande (titre de chapitre, de solution ou de machine) ; « Suite » si la page n'en a pas."""
    import re
    import pypdfium2.raw as raw
    from .regles import SEV_FR
    tp = page.get_textpage()
    texte = tp.get_text_range()
    meilleur, taille_max, debut = "", 0.0, 0
    for ligne in re.split(r"\r?\n", texte):
        fin = debut + len(ligne)
        if sum(c.isalpha() for c in ligne) >= 4:
            t = max((raw.FPDFText_GetFontSize(tp, k) for k in range(debut, fin)), default=0)
            if t > 20:                       # chiffres clés des tuiles d'indicateurs : pas des titres
                t = 0
            if t > taille_max + 0.01:
                meilleur, taille_max = ligne.strip(), t
        debut = fin + (2 if texte[fin:fin + 2] == "\r\n" else 1)
    if taille_max < 10.2 or not meilleur:
        return tr("Suite de la page précédente")
    noms = "|".join(re.escape(SEV_FR[k]) for k in ("Critical", "High", "Medium", "Low"))
    return re.sub(rf"^\d+\s+(?:{noms})\s+", "", meilleur)[:80]


def rendre_page(pdf_chemin, n, dpi, sortie):
    """Page n en PNG dans `sortie`, écrite sous un nom provisoire puis renommée : jamais de fichier à moitié écrit."""
    import pypdfium2 as pdfium
    with PDFIUM:
        doc = pdfium.PdfDocument(pdf_chemin)
        img = doc[n - 1].render(scale=dpi / 72).to_pil()
        doc.close()
    provisoire = f"{sortie}.{threading.get_ident()}.tmp"
    img.save(provisoire, format="PNG")
    os.replace(provisoire, sortie)


# ------------------------------------------------------------------ feuilles Excel
def feuilles_excel(xlsx_chemin, an, accent):
    """Tableaux HTML (un par feuille) : valeurs, couleurs d'en-tête et de sévérité. Les formules sont évaluées pour l'exemple."""
    import openpyxl
    from .modeles import plan_excel as PE
    from .regles import SEV_FR
    wb = openpyxl.load_workbook(xlsx_chemin)
    statut0 = PE.statuts()[0]
    nb = len(an.sols)
    for idx, ws in enumerate(wb.worksheets):
        for row in ws.iter_rows():
            for c in row:
                if isinstance(c.value, str) and c.value.startswith("="):
                    c.value = _valeur_formule(idx, c, ws, an, statut0, nb)
    out = []
    couleurs = {SEV_FR[k]: (PE.SEV_FILL[k], PE.SEV_TXT[k]) for k in PE.SEV_FILL}
    for ws in wb.worksheets:
        out.append({"nom": ws.title, "html": _table_html(ws, accent, couleurs)})
    return out


def _valeur_formule(idx, c, ws, an, statut0, nb):
    f = c.value
    if f.startswith("=IFERROR(INDEX"):
        return statut0                                   # « Par machine » : statut global = statut de la solution (À faire)
    if idx == 0:                                         # feuille Synthèse
        if f.startswith("=COUNTA"):
            return nb
        if "COUNTIF(" in f and c.column == 2 and c.row == 7:
            return min(an.top, nb)                       # solutions du plan d'action prioritaire
        if f.startswith("=1-"):
            return 1.0
        if f.startswith("=COUNTIFS"):
            return 0
        if f.startswith("=COUNTIF") and c.row >= 16:
            from .regles import SEV_FR
            lib = ws.cell(row=c.row, column=1).value
            return sum(1 for s in an.sols if SEV_FR[s["maxsev"]] == lib)
    return 0                                             # solutions terminées / en cours / acceptées, avancement, part traitée


def _table_html(ws, accent, couleurs, max_lignes=34, max_cols=13):
    lignes, cols = min(ws.max_row, max_lignes), min(ws.max_column, max_cols)
    larg = {}
    for k, d in ws.column_dimensions.items():
        if d.width:
            larg[d.min or 1] = d.width
    h = ['<table class="xl"><colgroup><col class="rn">']
    for j in range(1, cols + 1):
        h.append(f'<col style="width:{int(min(max(larg.get(j, 12), 6), 60) * 7)}px">')
    h.append("</colgroup><thead><tr><th></th>" + "".join(f"<th>{_lettre(j)}</th>" for j in range(1, cols + 1)) + "</tr></thead><tbody>")
    for i in range(1, lignes + 1):
        h.append(f'<tr><th>{i}</th>')
        for j in range(1, cols + 1):
            c = ws.cell(row=i, column=j)
            v = c.value
            if v is None:
                txt = ""
            elif isinstance(v, (int, float)) and not isinstance(v, bool) and "%" in (c.number_format or ""):
                txt = f"{v * 100:.1f} %"
            elif hasattr(v, "strftime"):
                txt = v.strftime("%d/%m/%Y")
            else:
                txt = str(v)
            st = []
            fill = c.fill.fgColor.rgb if c.fill and c.fill.fill_type == "solid" and isinstance(c.fill.fgColor.rgb, str) else None
            if fill and fill not in ("00000000",):
                st.append(f"background:#{fill[-6:]}")
            if c.font and c.font.bold:
                st.append("font-weight:600")
            if c.font and isinstance(c.font.color and c.font.color.rgb, str) and c.font.color.rgb[-6:] != "000000":
                st.append(f"color:#{c.font.color.rgb[-6:]}")
            if txt in couleurs:
                st = [f"background:#{couleurs[txt][0]}", f"color:#{couleurs[txt][1]}", "font-weight:600"]
            h.append(f'<td style="{";".join(st)}">{html.escape(txt)}</td>')
        h.append("</tr>")
    h.append("</tbody></table>")
    if ws.max_row > lignes:
        h.append(f'<p class="xl-suite">… {ws.max_row - lignes}</p>')
    return "".join(h)


def _lettre(j):
    from openpyxl.utils import get_column_letter
    return get_column_letter(j)
