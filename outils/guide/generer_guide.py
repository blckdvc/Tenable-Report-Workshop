#!/usr/bin/env python3
"""Produit le guide utilisateur (anglais) : Report_Workshop_User_Guide.pdf, à la racine du projet.

    .venv/bin/python outils/guide/generer_guide.py [--date "November 2026"] [--sortie chemin.pdf]

Le texte est dans ce fichier ; les captures d'écran sont dans outils/guide/images/. Pour mettre le guide à jour après
une évolution de l'application : modifier le texte ci-dessous (et remplacer une capture si l'écran a changé), puis relancer.
"""
import argparse
import os
import re

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, Image, KeepTogether, ListFlowable, ListItem,
                                NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(os.path.dirname(ICI))
IMAGES = os.path.join(ICI, "images")
POLICES = os.path.join(RACINE, "polices")

ACCENT = colors.HexColor("#1F4E9D")
TEXTE = colors.HexColor("#161616")
GRIS = colors.HexColor("#5A5A5A")
FILET = colors.HexColor("#D9DDE3")
PALE = colors.HexColor("#F3F5F8")
MARGE = 20 * mm
LARGEUR = A4[0] - 2 * MARGE

for nom in ("Regular", "Medium", "SemiBold", "Bold"):
    pdfmetrics.registerFont(TTFont(f"Inter-{nom}", os.path.join(POLICES, f"Inter-{nom}.ttf")))
pdfmetrics.registerFontFamily("Inter", normal="Inter-Regular", bold="Inter-SemiBold", italic="Inter-Regular", boldItalic="Inter-SemiBold")

BODY = ParagraphStyle("body", fontName="Inter-Regular", fontSize=9.6, leading=14, textColor=TEXTE, spaceAfter=6, alignment=TA_LEFT)
LEAD = ParagraphStyle("lead", parent=BODY, fontSize=10.6, leading=15.5, textColor=GRIS, spaceAfter=10)
H1 = ParagraphStyle("h1", fontName="Inter-Bold", fontSize=22, leading=27, textColor=ACCENT, spaceBefore=4, spaceAfter=10, keepWithNext=1)
H2 = ParagraphStyle("h2", fontName="Inter-SemiBold", fontSize=13, leading=17, textColor=TEXTE, spaceBefore=10, spaceAfter=5, keepWithNext=1)
CAPTION = ParagraphStyle("cap", parent=BODY, fontSize=8, leading=10.5, textColor=GRIS, spaceBefore=3, spaceAfter=8)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.6, leading=11.6, spaceAfter=0)
CELLB = ParagraphStyle("cellb", parent=CELL, fontName="Inter-SemiBold")
CELLH = ParagraphStyle("cellh", parent=CELL, fontName="Inter-SemiBold", textColor=colors.white)
CODE = ParagraphStyle("code", parent=BODY, fontName="Courier", fontSize=8.4, leading=11.5, textColor=TEXTE,
                      backColor=PALE, borderPadding=(5, 6, 5, 6), spaceBefore=4, spaceAfter=10)
NOTE = ParagraphStyle("note", parent=BODY, backColor=PALE, borderPadding=(6, 8, 6, 8), spaceBefore=6, spaceAfter=12)


def md(t):
    """Petite syntaxe : **gras**, `code`."""
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    return re.sub(r"`(.+?)`", r'<font name="Courier" size="8.8">\1</font>', t)


def p(t, style=BODY):
    return Paragraph(md(t), style)


def note(t):
    return Paragraph(md(t), NOTE)


def code(*lignes):
    return Paragraph("<br/>".join(md(x).replace(" ", "&nbsp;") for x in lignes), CODE)


def liste(items, numerotee=True):
    if numerotee:
        return ListFlowable([ListItem(p(x), leftIndent=14) for x in items], bulletType="1", start=1, leftIndent=14,
                            bulletFontName="Inter-SemiBold", bulletFontSize=9, bulletFormat="%s.", bulletColor=TEXTE, spaceAfter=6)
    return ListFlowable([ListItem(p(x), leftIndent=14) for x in items], bulletType="bullet", start="•", leftIndent=14,
                        bulletFontName="Inter-Regular", bulletFontSize=9, bulletColor=TEXTE, spaceAfter=6)


def tableau(entete, lignes, largeurs):
    data = [[Paragraph(md(x), CELLH) for x in entete]] + [[Paragraph(md(x), CELLB if j == 0 else CELL) for j, x in enumerate(l)] for l in lignes]
    t = Table(data, colWidths=[w * LARGEUR for w in largeurs], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), ACCENT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEBELOW", (0, 1), (-1, -1), 0.5, FILET), ("TOPPADDING", (0, 0), (-1, -1), 4),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
    return [t, Spacer(1, 8)]


class Figures:
    n = 0

    @classmethod
    def une(cls, fichier, legende, largeur=0.62):
        cls.n += 1
        return KeepTogether([_image(fichier, largeur * LARGEUR), p(f"**Figure {cls.n}.** {legende}", CAPTION)])

    @classmethod
    def deux(cls, a, la, b, lb):
        cls.n += 2
        w = (LARGEUR - 8 * mm) / 2
        t = Table([[_image(a, w), _image(b, w)], [p(f"**Figure {cls.n - 1}.** {la}", CAPTION), p(f"**Figure {cls.n}.** {lb}", CAPTION)]],
                  colWidths=[w + 4 * mm, w + 4 * mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        return KeepTogether([t, Spacer(1, 4)])


def _image(fichier, largeur):
    chemin = os.path.join(IMAGES, fichier)
    w, h = PILImage.open(chemin).size
    img = Image(chemin, width=largeur, height=largeur * h / w)
    img.hAlign = "LEFT"
    return img


class Titre(Paragraph):
    """Titre repris dans le sommaire (niveau 0 : chapitre, 1 : section)."""
    def __init__(self, texte, niveau):
        super().__init__(md(texte), H1 if niveau == 0 else H2)
        self.niveau, self.brut = niveau, texte


def h1(t):
    return Titre(t, 0)


def h2(t):
    return [CondPageBreak(30 * mm), Titre(t, 1)]


class Document(BaseDocTemplate):
    def __init__(self, sortie, date):
        super().__init__(sortie, pagesize=A4, leftMargin=MARGE, rightMargin=MARGE, topMargin=24 * mm, bottomMargin=20 * mm,
                         title="Report Workshop: User Guide", author="Report Workshop", subject="User guide")
        self.date = date
        cadre = Frame(MARGE, 20 * mm, LARGEUR, A4[1] - 44 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([PageTemplate("couverture", [cadre], onPage=self.couverture),
                               PageTemplate("corps", [cadre], onPage=self.page)])

    def afterFlowable(self, f):
        if isinstance(f, Titre):
            self.notify("TOCEntry", (f.niveau, f.brut.replace("**", ""), self.page))

    def couverture(self, c, doc):
        c.saveState()
        x, y = MARGE, A4[1] * 0.53
        c.setFillColor(ACCENT)
        c.rect(x, y + 14 * mm, 24 * mm, 2.2 * mm, stroke=0, fill=1)
        c.setFillColor(TEXTE)
        c.setFont("Inter-Bold", 36)
        c.drawString(x, y, "Report Workshop")
        c.setFillColor(GRIS)
        c.setFont("Inter-Regular", 18)
        c.drawString(x, y - 11 * mm, "User guide")
        c.setFont("Inter-Regular", 10.5)
        c.drawString(x, y - 26 * mm, "Turn Tenable Security Center or Vulnerability Management data into remediation reports,")
        c.drawString(x, y - 32 * mm, "in your client's colours and in four languages.")
        c.setStrokeColor(FILET)
        c.line(MARGE, 40 * mm, A4[0] - MARGE, 40 * mm)
        c.setFont("Inter-Regular", 8)
        c.drawString(MARGE, 33 * mm, self.date)
        c.drawString(MARGE, 28 * mm, "Local application: Flask, ReportLab, openpyxl. Runs on your computer; data stays on it.")
        c.restoreState()

    def page(self, c, doc):
        c.saveState()
        c.setFont("Inter-Regular", 8)
        c.setFillColor(GRIS)
        c.drawString(MARGE, A4[1] - 13 * mm, "Report Workshop · User guide")
        c.setStrokeColor(FILET)
        c.setLineWidth(0.5)
        c.line(MARGE, A4[1] - 15.5 * mm, A4[0] - MARGE, A4[1] - 15.5 * mm)
        c.line(MARGE, 13.5 * mm, A4[0] - MARGE, 13.5 * mm)
        c.drawString(MARGE, 9 * mm, "Tenable report generator")
        c.drawRightString(A4[0] - MARGE, 9 * mm, f"Page {doc.page}")
        c.restoreState()


def contenu():
    F = Figures
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("t0", fontName="Inter-SemiBold", fontSize=10, leading=15, leftIndent=0, textColor=TEXTE),
                       ParagraphStyle("t1", fontName="Inter-Regular", fontSize=9, leading=13, leftIndent=12, textColor=GRIS)]
    s = [NextPageTemplate("corps"), PageBreak(), Paragraph("Contents", H1), toc, PageBreak()]

    # 1 ------------------------------------------------------------------
    s += [h1("1. What Report Workshop does"),
          p("Report Workshop is a small application that runs on your own computer. It takes vulnerability data from Tenable "
            "Security Center or Tenable Vulnerability Management (a CSV export, or a direct query of their API), groups the "
            "findings into a short list of concrete actions, and produces a finished report: a PDF for management, a PDF for "
            "the teams who will do the work, or an Excel tracking workbook.", LEAD),
          p("Every client can have their own profile (logo, colours, confidentiality mention, watermark, scope, language). "
            "The interface and the reports are available in French, English, Spanish and Italian."),
          *h2("How it works, in four steps"),
          liste(["**Load the data.** Drop a CSV export, or let the application query Security Center or Vulnerability "
                 "Management through its API. A live log shows each step of an API retrieval.",
                 "**Group findings into solutions.** A set of rules turns Tenable plugin names into actions. All the Oracle Java "
                 "findings become one action, “Update Oracle Java SE”, because the latest update replaces the earlier ones.",
                 "**Rank the solutions.** Each finding is weighted with Tenable's scoring, whichever product the data comes "
                 "from: by severity (Critical 40, High 10, Medium 3, Low 1, the scale behind the Security Center vulnerability "
                 "score), by VPR, or by VPR and ACR. The solutions that remove the most risk come first.",
                 "**Produce the report.** Pick a template; the file is saved in the `rapports/` folder and can optionally be "
                 "sent by email."]),
          note("**Privacy.** The application only listens on 127.0.0.1 (your own machine). Client data leaves your computer in "
               "two cases only, both initiated by you: a query to Security Center or Vulnerability Management (the data then "
               "comes from it), and sending a report through the SMTP server you configured. There is no telemetry."),

          h1("2. Installation and first launch"),
          *h2("What you need"),
          p("Python 3.9 or newer (python.org). On Windows, tick “Add Python to PATH” during installation. An Internet "
            "connection is needed once, at the first launch, to download the libraries."),
          *tableau(["System", "How to launch"], [["Windows", "Double-click `lancer.bat`"],
                                                  ["macOS", "Double-click `lancer.command` (first time only: right-click, then Open)"],
                                                  ["Linux", "`./lancer.sh`"]], [0.25, 0.75]),
          p("At the first launch the script creates a `.venv` folder and installs the libraries; this takes one or two minutes. "
            "Later launches are immediate, and the script reinstalls automatically if `requirements.txt` changes. The "
            "application then opens in your browser at http://127.0.0.1:8765 (the next free port is used if 8765 is taken). "
            "To stop it, close the terminal window."),
          *h2("Updating"),
          p("With git, run `git pull` in the application folder. Otherwise copy the new files over the application folder (your "
            "`profils/`, `config.json`, `regles/` and `rapports/` are yours: do not overwrite them). Then quit the application "
            "completely and launch it again: it does not reload its code while running, so a report generated before the "
            "restart still follows the old behaviour."),
          note("**Offline install.** To install on a computer without Internet access, run `pip download -r requirements.txt "
               "-d packages` on a connected machine with the same system and Python version, copy the `packages` folder "
               "across, then run `python -m venv .venv` and `.venv/bin/python -m pip install --no-index --find-links packages "
               "-r requirements.txt` (Windows: `.venv\\Scripts\\python.exe`)."),

          # 3 --------------------------------------------------------------
          h1("3. Quick start"),
          p("Your first report in five minutes.", LEAD),
          liste(["Launch the application and, at the top right, open **Manage** to create a client profile (or keep the default one).",
                 "Choose the language with the flag next to **Manage**. It applies to the interface and to the reports, and is saved in the profile.",
                 "On the **Branding** tab, set the title, client name, colour and logo. The cover on the left updates as you type.",
                 "On the **Generate** tab, drop your CSV export, or fetch it through the API. A summary appears: machines, "
                 "vulnerabilities, severity split and the main solutions.",
                 "Choose a template (use **View an example** first if you want to see what it looks like) and click **Generate "
                 "the report**. PDF reports open in a new tab."]),
          F.une("generer_apercu.png", "The Generate tab once an export is loaded: live cover preview on the left, export summary on the right.", 0.8),
          PageBreak(),

          # 4 --------------------------------------------------------------
          h1("4. Tour of the interface"),
          *h2("Profiles and language"),
          p("A profile holds everything that is specific to a client: branding, scope, Tenable product and export query, email "
            "message and language. Use **Manage** to create, duplicate, rename or delete profiles. The last profile cannot be deleted."),
          F.deux("menu_profils.png", "The profile menu.", "menu_langues.png", "The language menu."),
          *h2("Theme"),
          p("The **Theme** button, at the top right, switches the look of the application and of the reports it produces. "
            "**Atelier** is the default: the client's main colour and logo drive the reports. **Tenable** applies the Tenable "
            "brand guidelines: Aeonik typeface (Light for large titles, Regular for text, Medium for headings), Soft Black and "
            "neutral greys, sharp corners, no shadows, no gradients. The setting belongs to the application, not to a profile, "
            "and applies to the PDF reports and to the Excel action plan."),
          p("With the Tenable theme, the client's main colour is replaced by the brand palette. The profile logo is kept; without "
            "a logo, the Tenable logo is used. The cover is white by default; a dark (Soft Black) cover can be chosen in the "
            "Branding tab. Severity colours in charts and badges are data colours and are kept. The command-line option "
            "`--theme atelier|tenable` overrides the setting for one report."),
          F.deux("theme_atelier.png", "The Atelier theme.", "theme_tenable.png", "The Tenable theme."),
          *h2("Generate"),
          p("The tab has three numbered steps. **1. Load the export**: from a CSV file or through the API of the profile's "
            "Tenable product. **2. Choose the template.** **3. Generate the report**, with an optional email send. Below, the "
            "list of generated reports lets you open, download or send each file."),
          p("During an API retrieval, a **Retrieval log** box opens under the fetch button and fills in live: export created, "
            "status checks, chunks or pages received, asset export, conversion. If the retrieval fails, the last line gives the "
            "cause. The box can be folded."),
          F.une("generer_modeles.png", "Template choice and the Generate button. “View an example” turns the cover preview into the real template, page by page.", 0.55),
          p("**View an example** does not open a dialog: the preview on the right of the page becomes the selected template, filled with fictitious data and with the branding and language of the profile. Use the **‹** and **›** arrows under the preview to move through the pages, and the template menu to switch template; the cover you were editing comes back with the first page."),
          *h2("Branding"),
          p("Title, subtitle, client, distribution mention (a small badge on the cover, which can also appear in the header of "
            "inner pages), watermark (diagonal text on PDF pages, for example “Restricted distribution”, with a box to keep it "
            "off the cover), footer text, main colour and logo. Once a watermark or an inner-page mention is set, tabs under the "
            "preview show two fictitious inner pages."),
          p("As long as the footer text is the default one, it names the product the data comes from (“Data from Tenable "
            "Security Center” or “Data from Tenable Vulnerability Management”). The scope of an API retrieval is added to it "
            "on every page, for example “Scope: Tags: Asset Owner = ludo”. A customised footer text is kept as is."),
          F.une("habillage.png", "The Branding tab.", 0.8),
          *h2("Scope"),
          p("Choose which severities are kept, how many solutions the action plan lists, and which machines to include or "
            "exclude (an IP address, a CIDR network, or a name with wildcards). The number of solutions is a hard limit: the "
            "complete remediation plan presents only those solutions, with no list of lower-priority actions."),
          p("The risk weighting sets how the “% of risk” of each solution is computed (it is calculated by the tool, never read "
            "from the API). A solution's “% of risk” is the weight of its findings divided by the weight of all findings in the "
            "scope, so the percentages add up to 100%. Three weightings are offered: by severity (Critical 40, High 10, Medium 3, "
            "Low 1, Tenable's severity scale); by VPR (each finding weighs its VPR, 0.1 to 10, or the median of its severity, 9.5 / 8.0 / 5.5 / 2.0, when it "
            "has none); by VPR and ACR (VPR × ACR ÷ 10, adding the importance of the machine; Tenable's default ACR of 5 is used "
            "when it is missing). The weighting changes the ranking of solutions, not the per-machine score or the comparison "
            "of two exports."),
          F.une("perimetre.png", "The Scope tab.", 0.8),
          *h2("Configuration"),
          p("Three blocks: **Tenable product** (Security Center or Vulnerability Management, a setting of the profile), the "
            "section of the chosen product (server and API keys, shared by all profiles; the export query, specific to the "
            "profile) and **Email** (SMTP server, shared; default message, specific to the profile). See chapters 5 and 9."),
          F.une("configuration.png", "The Configuration tab. With Vulnerability Management, the export query also offers the detection period.", 0.8),
          p("A fourth block, **endoflife.date**, is used only by the end-of-life software report. It has its own CA certificate "
            "field and a “verify TLS” box, because a TLS-inspecting proxy often affects this public site and not your Tenable "
            "servers. **Test endoflife.date** checks the connection."),
          F.une("eol_configuration.png", "The endoflife.date block: its own certificate, independent from Security Center and Vulnerability Management.", 0.8),
          PageBreak(),

          # 5 --------------------------------------------------------------
          h1("5. Getting the data"),
          *h2("Option A: CSV export from the Security Center interface"),
          liste(["Open **Analysis > Vulnerabilities**.", "Choose the **Vulnerability List** view.", "Apply your filters.",
                 "Click **Export**, then **Export as CSV**."]),
          p("Required columns: Plugin, Plugin Name, Severity, IP Address. Recommended: DNS Name, NetBIOS Name, Family, VPR, CVE, "
            "and Solution for titles that have no rule. Optional: ACR and AES, which add the asset scores to the reports. A CSV "
            "re-saved by a French Excel (semicolon separator, decimal comma) is accepted too."),
          *h2("Option B: query Security Center directly (API)"),
          liste(["**Configuration > Security Center > Connection.** Enter the server address and the API keys (in Security "
                 "Center: Users, then API Keys; a read-only account is best). “Test the connection” checks the keys. For an "
                 "internal PKI, give the authority certificate (PEM file); only disable TLS verification for a test.",
                 "**Export query** (per profile): repositories, asset list or saved query, and optional extra filters in JSON. "
                 "The button that lists the available repositories, asset lists and queries lets you pick them with a click. "
                 "Severities come from the Scope tab. “View the request sent to the API” shows the exact JSON body of the "
                 "`POST /rest/analysis` call.",
                 "**Generate > step 1:** choose “Security Center (API)”, then “Fetch from Security Center”. The retrieval log "
                 "shows the pages as they arrive."]),
          *h2("Option C: Tenable Vulnerability Management"),
          p("A CSV exported from Vulnerability Management (columns asset.* and definition.*) is dropped like any other CSV: the "
            "format is detected automatically. It carries no ACR, AES or last-observed date, so the AES and CES blocks are left "
            "out. A machine is identified by its first IPv4 address, because Vulnerability Management can hold the same host "
            "under several asset identifiers."),
          p("To fetch the data through the API, choose **Configuration > Tenable product > Tenable Vulnerability Management** (a "
            "setting of the profile), then fill in the **Vulnerability Management** section: address (https://cloud.tenable.com "
            "by default) and API keys (Settings, My Profile, API Keys). The export query of the profile sets:"),
          liste(["**Detection period**: 30 days (Tenable's default), 90, 180, 365 days or the whole period. Without a date, the "
                 "export API only returns vulnerabilities seen in the last 30 days, so a machine that has not been rescanned "
                 "since disappears from the report. Widen the period to bring it back.",
                 "**Address range** (optional).",
                 "**ACR and AES**: read from the asset export (`POST /assets/v2/export`). If that export is refused, the "
                 "application reads the scores from the workbench asset list, then tries the asset export v1."], numerotee=False),
          p("Generate > step 1 then offers “Vulnerability Management (API)”. From the command line, `--api` uses the profile's "
            "product. The environment variables are `TENABLE_VM_URL`, `TENABLE_VM_ACCESS_KEY` and `TENABLE_VM_SECRET_KEY`. The "
            "client has been run against a live tenant (vulnerability export, tags, detection period, asset export); if a "
            "field is not recognised, the error lists the fields received."),
          *h2("Choosing the scope"),
          p("Step 1 of the Generate tab offers **Choose the scope**: asset lists with Security Center (several lists are "
            "combined, OR), tags by category with Vulnerability Management (OR within a category, AND between categories), with "
            "a machine count before the export. Use it for one report, or save it in the profile."),
          p("With Vulnerability Management, if the export's tag filter returns nothing or is rejected, the application looks up "
            "the assets that carry those tags in the workbench and keeps only their vulnerabilities; the log says which path was "
            "used. If none of the tagged machines has a vulnerability in the period, the message suggests widening the "
            "detection period."),
          p("The selection appears on the **cover**, in the **footer of every page** and in the Excel plan, and the application "
            "warns when two compared exports differ in scope. It is also written into the fetched CSV (a `Scope` column), so a "
            "report built later from that file still shows it."),
          *h2("Where the fetched data is kept"),
          p("Each retrieval is kept as a timestamped CSV, in `exports_security_center/` or `exports_vulnerability_management/`. "
            "These files are the natural input for comparisons: load last month's file as the previous export, and fetch the "
            "recent one from the API."),
          p("API keys are stored in `config.json`, readable by your user only. You can supply them through the environment "
            "variables `TENABLE_SC_URL`, `TENABLE_SC_ACCESS_KEY`, `TENABLE_SC_SECRET_KEY` (and their `TENABLE_VM_*` "
            "counterparts) instead, which take precedence. Never share `config.json`."),
          PageBreak(),

          # 6 --------------------------------------------------------------
          h1("6. The report templates"),
          p("Seven templates are available. “View an example” next to each one produces the real report from fictitious data, "
            "with the branding and language of the active profile, and shows it page by page.", LEAD),
          *tableau(["Template", "Format", "What it contains"], [
              ["Complete remediation plan", "PDF", "How-to-read guide, graphical summary, action plan, detail by solution with the "
               "machines affected, remediation guide by machine. Only the solutions of the action plan are presented."],
              ["Executive summary", "PDF", "For management: how-to-read guide, indicators, charts, exposure posture, the priority "
               "actions, recommendations."],
              ["Sheets by machine", "PDF", "Guide, index, then one stand-alone sheet per machine: tick-box actions, vulnerabilities "
               "fixed, an intervention tracking box. To hand to the operations teams."],
              ["Comparison of two exports", "PDF", "Change in the risk score, vulnerabilities fixed, new and persistent, progress by "
               "solution and by machine. Load the previous export first, then the recent one."],
              ["PHP2Shell exposure", "PDF", "Dedicated report on the PHP flaws CVE-2026-109618 and CVE-2026-109619: threat summary, "
               "every machine concerned ranked by priority, action plan, interim measures, compromise checklist, detection "
               "reliability, plugin coverage and sources."],
              ["End-of-life software", "PDF", "Software found on your machines (CPE, plugin 45590) matched with endoflife.date: "
               "summary, inventory by product with end-of-support dates, one sheet per product with the machines and the open "
               "vulnerabilities, method and limits."],
              ["Excel action plan", "XLSX", "Tracking workbook: owner, due date and status per solution, status per machine, "
               "vulnerability detail, progress indicators that recalculate."]], [0.24, 0.1, 0.66]),
          p("In every PDF the page that follows the cover is “How to read this report”: method, definitions of VPR, ACR, AES "
            "and CES, and a reading gauge. In the executive summary this page is shorter and written for management."),
          p("In a comparison, a vulnerability counts as fixed only if its machine was rescanned, that is, it appears in the "
            "recent export with any finding, Info included. A machine whose last vulnerability was fixed therefore gets the "
            "credit."),
          F.une("exemple.png", "“View an example”: the preview shows the selected template; ‹ › move through its pages.", 0.55),
          *h2("What the pages look like"),
          F.deux("page_guide_lecture.png", "“How to read this report”, always page 2.", "page_synthese.png",
                 "Summary with the Cyber Exposure Score posture."),
          F.deux("page_plan.png", "Action plan, ranked by risk removed.", "page_detail.png", "Detail by solution, with the machines to treat."),
          F.deux("page_fiche.png", "A sheet for one machine.", "page_comparaison.png", "Comparison summary."),
          *h2("The end-of-life software template"),
          p("This report answers one question: which software installed on your machines is no longer supported by its "
            "vendor, or soon will not be? The software list comes from the CPE that Nessus reports with plugin 45590 "
            "(Common Platform Enumeration), matched with the lifecycle dates of endoflife.date."),
          liste(["**Fetch the data with the template selected.** In the Generate tab, choose the end-of-life template "
                 "before fetching through the API: the CPE are collected together with the usual vulnerability export, "
                 "so the vulnerability statistics are kept. The summary shown after the fetch adds the end-of-life figures: "
                 "products out of support, products ending within 12 months, machines concerned, open vulnerabilities on "
                 "unsupported products.",
                 "**Needs Internet access** to endoflife.date from the computer running the application. Behind a TLS-inspecting "
                 "proxy, give the proxy's root certificate in the endoflife.date block of the Configuration tab.",
                 "**Target version.** The report suggests a version still supported by the vendor and newer than the one found, "
                 "preferring a long-term support (LTS) release. If only an older one is still supported (for example OpenSSL 3.6, "
                 "whose only supported branch is the 3.5 LTS), that one is shown and the product sheet says it is older.",
                 "**Software that declares no CPE, or machines scanned without credentials or agent, do not appear.** The report "
                 "says so, and lists the detected software that could not be matched."], numerotee=False),
          F.une("eol_generer.png", "The Generate tab with the end-of-life template: the summary adds the end-of-life figures.", 0.8),
          F.deux("page_eol_synthese.png", "Summary: status of the products and most widespread ones.", "page_eol_inventaire.png",
                 "Inventory of the products with their end-of-support dates."),
          F.deux("page_eol_fiche.png", "One sheet per product: machines and open vulnerabilities.", "page_eol_methode.png",
                 "Method and limits."),
          *h2("The PHP2Shell template"),
          p("PHP2Shell is the name given to two critical PHP flaws, CVE-2026-109618 and CVE-2026-109619: unauthenticated remote "
            "code execution, exploited in the wild since 21 October 2026. This template isolates, in your export, every finding "
            "that cites either CVE, plus the 43 Nessus plugins published for them."),
          p("Nothing is filtered out. Every machine concerned is listed, whatever its AES or ACR, and the profile's severity "
            "filter is ignored for this report. ACR and AES are shown and used for sorting only. The priority depends on the "
            "level of evidence alone: P1 confirmed flaw, or no vendor fix (act within 24 to 48 hours), P2 to be confirmed "
            "(version read from a remote banner by an unauthenticated scan)."),
          p("The report also explains when an empty result proves nothing: export older than the plugins, unauthenticated or "
            "agent scan, PHP bundled in an application. The threat summary is dated 25 October 2026; check it before "
            "circulating a later report."),
          F.deux("php_lecture.png", "PHP2Shell: how to read this report.", "php_machines.png", "Machines concerned, all listed."),
          PageBreak(),

          # 7 --------------------------------------------------------------
          h1("7. Understanding the scores"),
          p("The reports use five scores. They are Tenable's own scores and apply in the same way to Security Center and "
            "Vulnerability Management data. Knowing which is which makes the rankings easy to explain.", LEAD),
          *tableau(["Score", "Applies to", "Scale", "What it tells you"], [
              ["Risk score", "Report", "40 / 10 / 3 / 1", "Each vulnerability counts by severity, with Tenable's severity scale "
               "(the one behind the Security Center vulnerability score), for both products. The impact of a solution is the "
               "share of the total score it removes. This ranks the solutions."],
              ["VPR", "Vulnerability", "0.1 to 10.0", "Vulnerability Priority Rating: how likely the flaw is to be exploited soon "
               "(exploit maturity, threat intelligence)."],
              ["ACR", "Machine", "1 to 10", "Asset Criticality Rating: how important the machine is to the business."],
              ["AES", "Machine", "0 to 1,000", "Asset Exposure Score: how exposed the machine is; it combines the ACR and the VPR "
               "of its vulnerabilities. Low below 350, Medium 350 to 649, High 650 and above."],
              ["CES", "Scope", "0 to 1,000", "Cyber Exposure Score: Tenable's overall exposure score for a set of machines. The "
               "reports estimate it as the mean AES of the machines analysed (one machine, one vote)."]], [0.13, 0.15, 0.17, 0.55]),
          *h2("Where the scores appear"),
          p("Machines are sorted by AES, most exposed first, and ACR and AES are shown as colour-coded badges. The summary pages "
            "show an exposure posture block: the Cyber Exposure Score of the scope, a gauge from low risk to high risk with a "
            "marker for your value, and the number of machines in each level."),
          p("ACR and AES come from the CSV columns of the same name, from the Security Center API (`acrScore`, "
            "`assetExposureScore`) or from the Vulnerability Management asset export. If they are missing, these elements are "
            "simply left out; nothing else changes."),

          # 8 --------------------------------------------------------------
          h1("8. Rules"),
          p("Rules are what turn a Tenable title such as “Oracle Java SE 8 Update 421 Multiple Vulnerabilities” into an "
            "action. The first rule whose pattern matches the plugin name (and, if given, the Tenable family) is used. Findings "
            "that share a grouping key form one solution.", LEAD),
          p("The rule set covers Linux and Unix, Windows, the main network and security vendors (Cisco, Fortinet, Palo Alto, "
            "Juniper, F5, Check Point, Citrix, SAP, IBM), industrial systems and protocols (Modbus, DNP3, BACnet), and common "
            "issues such as TLS, certificates, SSH, SMB, SNMP, DNS, WPAD, credentials sent in cleartext, Secure Boot, RADIUS "
            "authentication failures and suspicious processes. Generic rules handle titles such as “Product < X” or “Product "
            "X (GHSA-… / CVE-…)”."),
          F.une("regles.png", "The Rules tab: test area on top, then the ordered list of rules.", 0.8),
          *h2("What you can do"),
          liste(["Test one or several titles, including with edits you have not saved yet.",
                 "Pick up unmatched titles from the loaded export in one click, and create a pre-filled rule from one of them.",
                 "Edit, reorder or delete rules. Order matters: the first match wins.",
                 "Import or export the file to work on it in Excel (semicolon separator)."], numerotee=False),
          F.une("regle_edition.png", "Editing a rule: title, grouping key, pattern, action, optional family and comment.", 0.8),
          *h2("Fields you can use in a title or an action"),
          *tableau(["Field", "Content"], [
              ["`{produit}` `{kb}` `{os}` `{ms}` `{famille}`", "Values extracted from the title by the named groups of the pattern"],
              ["`{paquets}` `{avis}` `{notes}` `{bulletins}` `{cves}`", "Lists accumulated over all the vulnerabilities of the solution"],
              ["`{cible}`", "“to version X or later”, from titles like “Product < X” or “Product X (GHSA-…)”"],
              ["`{precision}`", "“(version X or later)” when a version is cited, otherwise empty"],
              ["`{branches}`", "Fixed versions of the other branches, when the title names several"],
              ["`{ref_avis}`", "“(advisory: …)” when the title cites vendor advisory identifiers, GHSA included"],
              ["`{mois}`", "Latest publication month"],
              ["`{redemarrage}`", "A restart sentence when the kernel is concerned"]], [0.42, 0.58]),
          *h2("How the rules are stored"),
          p("The grouping (pattern, key, family) is shared by all languages, in `regles/base.csv`. The texts (title, action, "
            "comment) are one file per language, `regles/textes_<language>.csv`. English is the reference language: a text "
            "missing in another language is taken from English, then from French. Each save writes the files completely before "
            "replacing the old ones, which are kept with a `.bak` extension."),
          note("Target versions are deduced from Tenable titles, so have the technical team review the action plan before it is circulated."),
          PageBreak(),

          # 9 --------------------------------------------------------------
          h1("9. Sending a report by email"),
          p("Sending is always optional and explicit: nothing is ever sent without your choosing it.", LEAD),
          liste(["**Configuration > Email > SMTP server** (shared by all profiles): server, port, encryption (STARTTLS, SSL/TLS, "
                 "or none for an internal relay), credentials if any, and the sender address. “Test the connection” opens a "
                 "session and authenticates without sending a message. The password can come from the `SMTP_PASSWORD` variable.",
                 "**Default message** (per profile): usual recipients, subject and text. Variables: `{titre}`, `{client}`, "
                 "`{date}`, `{fichier}`.",
                 "On **Generate > step 3**, “Generate the report” only creates the file. “Generate and send by email” (shown "
                 "once the SMTP server is configured) also sends it to the profile's recipients."]),
          p("If the send fails, the report is kept and a “Try again” link opens the send form; the “Send” link in the list of "
            "reports does the same, with editable recipients. The report goes as an attachment, 25 MB at most."),

          # 10 -------------------------------------------------------------
          h1("10. Command line and automation"),
          p("Everything the interface does can be run without it, which suits a scheduled task (cron, Windows Task Scheduler). "
            "Use the Python of the `.venv` folder.", LEAD),
          code("python generer.py export.csv --modele synthese --profil client-name",
               "python generer.py old.csv recent.csv --modele comparaison --sortie change.pdf",
               "python generer.py --api --profil client-name --mail defaut",
               "python generer.py old.csv --api --modele comparaison --profil client-name",
               "python generer.py export.csv --langue en"),
          *tableau(["Option", "Meaning"], [
              ["`--modele`", "complet, synthese, fiches, comparaison, php2shell or plan_excel"],
              ["`--profil`", "Profile name: the file name in `profils/` without `.json`"],
              ["`--sortie`", "Output file (default: rapport_<template>.pdf or .xlsx in the current folder)"],
              ["`--langue`", "fr, en, es or it. By default, the profile's language"],
              ["`--theme`", "atelier or tenable. By default, the application's setting"],
              ["`--api` / `--securitycenter`", "Fetch the export through the API of the profile's product, with its query and "
               "scope (for a comparison, it replaces the recent export)"],
              ["`--mail`", "Send the report to the given addresses (comma separated), or to the profile's recipients with “defaut”"]],
              [0.3, 0.7]),

          # 11 -------------------------------------------------------------
          h1("11. Languages"),
          p("The flag selector next to profile management switches the interface and the reports between French, English, "
            "Spanish and Italian. The language is saved in the profile, so each client can have their own. Default texts (title, "
            "footer, email message) follow the language as long as you have not customised them; customised texts are never "
            "overwritten. Rules are translated too (chapter 8). For the command line, `--langue` overrides the profile."),

          # 12 -------------------------------------------------------------
          h1("12. What is in the folder"),
          *tableau(["Item", "Role"], [
              ["`app.py`", "Local server and interface"], ["`generer.py`", "Command-line generation"],
              ["`moteur/`", "Analysis, rules, charts, report templates (`moteur/modeles/`), Security Center and Vulnerability "
               "Management clients, scope, SMTP sending, configuration, translations"],
              ["`web/`", "The interface (HTML, CSS, JavaScript; no external resource)"],
              ["`regles/`", "Rules: `base.csv` (grouping) and one text file per language"],
              ["`profils/`", "Client profiles: branding, scope, logo"],
              ["`config.json`", "Security Center and Vulnerability Management connections, SMTP server (created on save, restricted permissions)"],
              ["`exports_security_center/`", "Security Center exports fetched through the API, kept for comparisons"],
              ["`exports_vulnerability_management/`", "Vulnerability Management exports fetched through the API, kept for comparisons"],
              ["`rapports/`", "Generated reports"],
              ["`polices/`", "Inter and DejaVu fonts, free licences included"],
              ["`outils/guide/`", "The script and screenshots that produce this guide"]], [0.36, 0.64]),
          *h2("Adding a report template"),
          liste(["Create a file in `moteur/modeles/` with a `generer(analyse, habillage, sortie)` function (for a two-export "
                 "template: `generer(avant, apres, habillage, sortie)`).", "Declare it in `moteur/modeles/__init__.py`."]),
          p("Shared layout blocks (cover, tables, severity badges, indicators) are in `moteur/commun.py`. To update this guide, "
            "edit `outils/guide/generer_guide.py` and run it with the Python of the `.venv` folder."),
          PageBreak(),

          # 13 -------------------------------------------------------------
          h1("13. Troubleshooting"),
          *tableau(["You see", "What to do"], [
              ["The application opens with the old layout, or a report ignores a recent change",
               "Quit the application completely (close the terminal window), launch it again and generate a new report. "
               "Reports already generated are not rebuilt."],
              ["macOS refuses to open `lancer.command`", "Right-click the file, choose Open, confirm. This is needed once. If the "
               "message is about permissions, run `chmod +x lancer.command` in the application folder."],
              ["An API retrieval seems slow", "Open the Retrieval log under the fetch button: it shows whether Tenable is still "
               "preparing the export (QUEUED, PROCESSING) or whether chunks are arriving."],
              ["Machines carrying a Vulnerability Management tag are missing", "They were probably not rescanned in the last 30 "
               "days. Widen the Detection period of the profile's export query (90, 180, 365 days or the whole period)."],
              ["ACR and AES are missing", "CSV: the export has no such columns. Security Center API: the fields used are "
               "`acrScore` and `assetExposureScore`. Vulnerability Management API: check the Retrieval log; the scores need a "
               "Tenable One or Lumin licence."],
              ["The scope is not shown on the report", "The scope comes with an API retrieval. A CSV fetched with an older version "
               "has no `Scope` column: fetch it again."],
              ["“The Plugin Name column is empty”", "The file is empty or is not a Vulnerability List export. If it comes from the "
               "API, fetch it again with the latest version."],
              ["“No vulnerabilities in the selected scope”", "Check the severities on the Scope tab and the include/exclude "
               "filters. Info findings are always excluded."],
              ["“N names without a dedicated rule”", "The report is produced, but those titles fall into generic rules. Open "
               "the Rules tab, pick up the unmatched titles and create rules."],
              ["Cannot reach Security Center or Vulnerability Management", "Use “Test the connection” in Configuration. Check "
               "the address, the keys and, for an internal PKI, the PEM certificate."],
              ["The email does not leave", "Use “Test the connection” on the SMTP card. The report is kept; use “Try again”. "
               "Attachments are limited to 25 MB."],
              ["A rule edit went wrong", "Previous files are kept next to the originals in `regles/` with a `.bak` extension; "
               "rename one to restore it."],
              ["The image preview asks for the “pypdfium2” library", "Run `.venv/bin/python -m pip install -r requirements.txt` "
               "(Windows: `.venv\\Scripts\\python.exe`) and relaunch. The launchers do this automatically."]],
              [0.36, 0.64]),
          note("**Before you share.** Check the action plan with the technical team before circulating a report: target versions "
               "are deduced from Tenable titles and should be confirmed against the vendors' bulletins.")]
    return s


def main():
    ap = argparse.ArgumentParser(description="Produit le guide utilisateur PDF.")
    ap.add_argument("--date", default="November 2026")
    ap.add_argument("--sortie", default=os.path.join(RACINE, "Report_Workshop_User_Guide.pdf"))
    a = ap.parse_args()
    Figures.n = 0
    doc = Document(a.sortie, a.date)
    doc.multiBuild(contenu())
    print(a.sortie)


if __name__ == "__main__":
    main()
