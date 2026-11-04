"""Mise en page commune des rapports PDF : polices, couleurs, couverture, en-têtes, blocs réutilisables."""
import datetime
import os
import tempfile
from xml.sax.saxutils import escape as esc

from PIL import Image as PILImage, ImageOps
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)

from . import charte as CH
from . import graphiques as G
from .regles import SEV_FR as FR
from .i18n import tr, plur, date_longue, traductions

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICES = os.path.join(RACINE, "polices")
pdfmetrics.registerFont(TTFont("DejaVu", os.path.join(POLICES, "DejaVuSans.ttf")))


def enregistrer_polices(theme):
    """Les noms « Inter-… » désignent les polices du rapport : Inter par défaut, Aeonik en thème Tenable
    si ses fichiers sont présents dans polices/
    (Bold n'existe pas dans la charte : le gras est du Semibold ; « Inter-Light » est le Light des grands titres)."""
    if theme == "tenable" and CH.aeonik_disponible():
        cartes = {"Light": "Aeonik-Light", "Regular": "Aeonik-Regular", "Medium": "Aeonik-Medium",
                  "SemiBold": "Aeonik-SemiBold", "Bold": "Aeonik-SemiBold"}
    else:
        cartes = {w: f"Inter-{w}" for w in ("Regular", "Medium", "SemiBold", "Bold")}
        cartes["Light"] = "Inter-Regular"
    for w, fichier in cartes.items():
        pdfmetrics.registerFont(TTFont(f"Inter-{w}", os.path.join(POLICES, fichier + ".ttf")))
    registerFontFamily("Inter-Regular", normal="Inter-Regular", bold="Inter-SemiBold", italic="Inter-Regular", boldItalic="Inter-SemiBold")


enregistrer_polices("atelier")

INK, MUTED, RULE = colors.HexColor("#161616"), colors.HexColor("#5A5A5A"), colors.HexColor("#DDDDDD")
ZEBRA = colors.HexColor("#F7F7F7")
SEVC = {k: colors.HexColor(v) for k, v in G.COL.items()}
SEV_TXT = {"Critical": colors.white, "High": colors.white, "Medium": INK, "Low": colors.white}
BON, MAUVAIS = colors.HexColor(G.BON), colors.HexColor(G.MAUVAIS)
MARGE = 18 * mm
W = A4[0] - 2 * MARGE

MOIS = "janvier février mars avril mai juin juillet août septembre octobre novembre décembre".split()

PIED_VM = "Données issues de Tenable Vulnerability Management"      # pied par défaut quand l'export vient de Vulnerability Management


def _ajuster(texte, police, corps, largeur):
    """Texte raccourci (avec « … ») pour tenir dans `largeur` points : le numéro de page reste lisible."""
    from reportlab.pdfbase.pdfmetrics import stringWidth
    if stringWidth(texte, police, corps) <= largeur:
        return texte
    while texte and stringWidth(texte + "…", police, corps) > largeur:
        texte = texte[:-1]
    return texte.rstrip(" ·,;") + "…"


HABILLAGE_DEFAUT = {
    "titre": "Rapport de vulnérabilités",
    "sous_titre": "",
    "client": "",
    "mention": "",
    "couleur": "#000091",
    "logo": None,
    "pied": "Données issues de Tenable Security Center",
    "filigrane": "",                 # texte en diagonale sur chaque page ; vide = aucun
    "filigrane_couverture": True,    # False : pas de filigrane sur la page de couverture
    "mention_interieur": False,      # True : la mention de diffusion est aussi un badge en en-tête des pages intérieures
    "couverture": "claire",          # thème Tenable : couverture « claire » (blanche, défaut) ou « sombre » (Soft Black)
}


# « 3 critiques », « 1 élevée » : une clé de catalogue par sévérité et par nombre (l'accord varie selon la langue)
_SEV_ACCORD = {"Critical": ("critique", "critiques"), "High": ("élevée", "élevées"),
               "Medium": ("moyenne", "moyennes"), "Low": ("faible", "faibles")}


def date_fr(d=None):
    """Date longue dans la langue courante (nom conservé pour compatibilité)."""
    return date_longue(d)


def st(name, **kw):
    base = dict(fontName="Inter-Regular", fontSize=9, leading=12.5, textColor=INK)
    base.update(kw)
    return ParagraphStyle(name, **base)


def pluriel(n, mot, mots=None):
    return plur(n, mot, mots)


def _melange(hexa, part):
    """Couleur claire dérivée de l'accent (part = proportion d'accent sur fond blanc)."""
    c = colors.HexColor(hexa)
    return colors.Color(1 - (1 - c.red) * part, 1 - (1 - c.green) * part, 1 - (1 - c.blue) * part)


def preparer_logo(chemin, dossier):
    """Recadre le logo sur son contenu (supprime les marges blanches) ; renvoie (fichier, ratio)."""
    if not chemin or not os.path.exists(chemin):
        return None, 1
    im = PILImage.open(chemin).convert("RGBA")
    fond = PILImage.new("RGBA", im.size, (255, 255, 255, 255))
    fond.alpha_composite(im)
    im = fond.convert("RGB")
    boite = ImageOps.invert(im.convert("L")).point(lambda p: 255 if p > 12 else 0).getbbox() or (0, 0, *im.size)
    bloc = im.crop(boite)
    sortie = os.path.join(dossier, "logo_bloc.png")
    bloc.save(sortie)
    return sortie, bloc.width / bloc.height


def dessiner_filigrane(c, texte):
    """Texte en diagonale, grisé et translucide, centré sur la page. La taille s'adapte à la longueur du texte."""
    texte = " ".join((texte or "").split()).upper()
    if not texte:
        return
    pw, ph = A4
    taille = min(77.0, 625.0 / max(pdfmetrics.stringWidth(texte, "Inter-Bold", 1), 0.01))
    c.saveState()
    c.setFillColor(colors.HexColor("#5A5A5A"))
    c.setFillAlpha(0.13)
    c.setFont("Inter-Bold", taille)
    c.translate(pw / 2, ph / 2)
    c.rotate(45)
    c.drawCentredString(0, -taille * 0.35, texte)
    c.restoreState()


class _CanvasNumerote(rl_canvas.Canvas):
    def __init__(self, *a, filigrane="", filigrane_couverture=True, **k):
        super().__init__(*a, **k)
        self._pages = []
        self._filigrane = filigrane
        self._fil_couverture = filigrane_couverture

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        n = len(self._pages)
        for i, p in enumerate(self._pages, 1):
            self.__dict__.update(p)
            if i > 1 or self._fil_couverture:
                dessiner_filigrane(self, self._filigrane)      # au-dessus du contenu
            if i > 1:
                self.setFont("Inter-Regular", 8)
                self.setFillColor(MUTED)
                self.drawRightString(A4[0] - MARGE, 8.5 * mm, tr("Page {i} / {n}", i=i, n=n))
            super().showPage()
        super().save()


def _court(v, n=95):
    v = str(v)
    return v if len(v) <= n else v[:n - 1].rstrip() + "…"


class DocumentPDF:
    """Un rapport PDF habillé : couverture, en-tête et pied de page, styles et blocs communs."""

    def __init__(self, sortie, habillage, nom_modele, meta_couverture, produit=None, portee=None):
        """produit (« sc » ou « vm ») et portee (texte du périmètre) complètent le pied de page : le pied par défaut
        nomme le bon produit Tenable, et le périmètre suit sur chaque page."""
        self.sortie = sortie
        self.h = {**HABILLAGE_DEFAUT, **{k: v for k, v in (habillage or {}).items() if v not in (None,)}}
        if produit == "vm" and self.h.get("pied") in traductions(HABILLAGE_DEFAUT["pied"]):
            self.h["pied"] = PIED_VM                                # pied par défaut : il nomme le produit de l'export
        self.portee = portee or ""
        for k in ("titre", "pied", "mention", "filigrane"):      # textes par défaut et mentions usuelles : traduits à l'usage
            if isinstance(self.h.get(k), str) and self.h[k]:
                self.h[k] = tr(self.h[k])
        self.nom_modele = tr(nom_modele)
        self.meta = [(tr(k), v) for k, v in meta_couverture]
        self.theme = self.h.get("theme") if self.h.get("theme") in CH.THEMES else "atelier"
        self.tenable = self.theme == "tenable"
        enregistrer_polices(self.theme)
        G.activer(self.theme)
        if self.tenable:
            self.h["couleur"] = CH.SOFT_BLACK                       # la charte remplace la couleur du profil
        self.tmp = tempfile.mkdtemp(prefix="rapport_")
        self.logo, self.ratio = preparer_logo(self.h.get("logo"), self.tmp)
        self.accent_hex = self.h.get("couleur") or "#000091"
        try:
            self.accent = colors.HexColor(self.accent_hex)
        except Exception:
            self.accent_hex, self.accent = "#000091", colors.HexColor("#000091")
        self.pale = colors.HexColor(CH.GRIS_050) if self.tenable else _melange(self.accent_hex, 0.05)
        titres = "Inter-Medium" if self.tenable else "Inter-SemiBold"        # charte : titres en Medium, Semibold au plus
        self.H1 = st("h1", fontName=titres, fontSize=17, leading=21, textColor=self.accent, spaceAfter=4)
        self.H2 = st("h2", fontName=titres, fontSize=11.5, leading=15, spaceBefore=6, spaceAfter=3)
        self.BODY = st("body", spaceAfter=4)
        self.SMALL = st("small", fontSize=7.8, leading=10.5, textColor=MUTED)
        self.CELL = st("cell", fontSize=8, leading=10.5)
        self.CELLB = st("cellb", fontName="Inter-Medium", fontSize=8, leading=10.5)
        self.CELLH = st("cellh", fontName="Inter-SemiBold", fontSize=7.5, leading=10, textColor=MUTED)
        self.CELLHR = st("cellhr", fontName="Inter-SemiBold", fontSize=7.5, leading=10, textColor=MUTED, alignment=TA_RIGHT)
        self.CELLR = st("cellr", fontSize=8, leading=10.5, alignment=TA_RIGHT)
        self.CELLC = st("cellc", fontSize=8, leading=10.5, alignment=TA_CENTER)
        self.LEAD = st("lead", fontSize=10, leading=14.5, textColor=colors.HexColor("#3A3A3A"), spaceAfter=8)
        self.CAP = st("cap", fontName="Inter-SemiBold", fontSize=9, leading=12, spaceAfter=2)
        self.ACT = st("act", fontSize=8.8, leading=12.5)

    # ------------------------------------------------------------------ pages
    def _logo_entete(self, sombre):
        """(fichier, largeur/hauteur, logo du client ?) : logo du profil, sinon logo Tenable en thème Tenable."""
        if self.logo:
            return self.logo, self.ratio, True
        if self.tenable:
            return CH.logo_tenable(sombre), CH.LOGO_RATIO, False
        return None, 1, False

    def _couverture_tenable(self, c, doc):
        """Couverture de la charte : titre en Light aligné à gauche, un seul mot surligné Hilighter (texte Soft Black)."""
        pw, ph = A4
        sombre = self.h.get("couverture") == "sombre"
        texte, second, filet, label = ((colors.white, colors.HexColor(CH.GRIS_300), colors.HexColor(CH.GRIS_700), colors.HexColor(CH.GRIS_400))
                                       if sombre else (self.accent, colors.HexColor(CH.GRIS_700), colors.HexColor(CH.GRIS_200), colors.HexColor(CH.GRIS_700)))
        c.saveState()
        if sombre:
            c.setFillColor(self.accent)
            c.rect(0, 0, pw, ph, stroke=0, fill=1)
        fichier, ratio, client = self._logo_entete(sombre)
        if fichier:
            h = 24 * mm if client else 11 * mm
            w = min(h * ratio, 70 * mm)
            h = w / ratio
            y = ph - MARGE - h
            if client and sombre:                                   # logo du client (fond blanc) : posé sur un aplat blanc, coins droits
                c.setFillColor(colors.white)
                c.rect(MARGE - 3 * mm, y - 3 * mm, w + 6 * mm, h + 6 * mm, stroke=0, fill=1)
            c.drawImage(fichier, MARGE, y, width=w, height=h, mask="auto")
        if self.h.get("mention"):
            self._mention(c, pw - MARGE, ph - MARGE - 5 * mm, sombre=sombre)
        titre = self.h.get("titre") or tr(HABILLAGE_DEFAUT["titre"])
        taille = 40
        lignes = simpleSplit(titre, "Inter-Light", taille, W)
        while len(lignes) > 3 and taille > 24:
            taille -= 4
            lignes = simpleSplit(titre, "Inter-Light", taille, W)
        lead = taille * 1.14
        base = ph * 0.52
        for i, ligne in enumerate(lignes):
            yb = base - i * lead
            mots = ligne.split(" ")
            if i == len(lignes) - 1 and len(mots) > 0:
                dernier = mots[-1]
                avant = ligne[: len(ligne) - len(dernier)]
                x = MARGE + pdfmetrics.stringWidth(avant, "Inter-Light", taille)
                lw = pdfmetrics.stringWidth(dernier, "Inter-Light", taille)
                c.setFillColor(colors.HexColor(CH.HILIGHTER))                  # bande de surlignage : 1,06 em, centrée sur le mot
                c.rect(x - 0.08 * taille, yb - 0.28 * taille, lw + 0.16 * taille, 1.06 * taille, stroke=0, fill=1)
                c.setFont("Inter-Light", taille)
                c.setFillColor(texte)
                c.drawString(MARGE, yb, avant)
                c.setFillColor(colors.HexColor(CH.SOFT_BLACK))                 # le texte surligné reste en Soft Black
                c.drawString(x, yb, dernier)
            else:
                c.setFont("Inter-Light", taille)
                c.setFillColor(texte)
                c.drawString(MARGE, yb, ligne)
        ys = base - (len(lignes) - 1) * lead - 13 * mm
        c.setFont("Inter-Regular", 15)
        c.setFillColor(second)
        c.drawString(MARGE, ys, self.h.get("sous_titre") or self.nom_modele)
        meta = ([(tr("Client"), self.h["client"])] if self.h.get("client") else []) + self.meta + [(tr("Date d'édition"), date_fr())]
        y = 22 * mm + 8 * mm * len(meta)
        c.setStrokeColor(filet)
        c.setLineWidth(0.6)
        c.line(MARGE, y + 9 * mm, pw - MARGE, y + 9 * mm)
        for k, v in meta:
            c.setFont("Inter-Medium", 8.5)
            c.setFillColor(label)
            c.drawString(MARGE, y, k)                                          # casse de phrase : jamais de capitales
            c.setFont("Inter-Regular", 10)
            c.setFillColor(texte)
            c.drawString(70 * mm, y, _court(v))
            y -= 8 * mm
        c.restoreState()

    def _couverture(self, c, doc):
        if self.tenable:
            return self._couverture_tenable(c, doc)
        c.saveState()
        pw, ph = A4
        if self.logo:
            c.drawImage(self.logo, MARGE, ph - MARGE - 34 * mm, height=34 * mm, width=34 * mm * self.ratio, mask="auto")
        if self.h.get("mention"):
            self._mention(c, pw - MARGE, ph - MARGE - 5 * mm)
        y0 = ph * 0.52
        c.setFillColor(self.accent)
        c.rect(MARGE, y0, 14 * mm, 1.6 * mm, stroke=0, fill=1)
        titre = self.h.get("titre") or tr(HABILLAGE_DEFAUT["titre"])
        taille = 30 if pdfmetrics.stringWidth(titre, "Inter-SemiBold", 30) < W else 22
        c.setFillColor(INK)
        c.setFont("Inter-SemiBold", taille)
        c.drawString(MARGE, y0 - 16 * mm, titre)
        c.setFont("Inter-Regular", 15)
        c.setFillColor(colors.HexColor("#3A3A3A"))
        c.drawString(MARGE, y0 - 25 * mm, self.h.get("sous_titre") or self.nom_modele)
        meta = ([(tr("Client"), self.h["client"])] if self.h.get("client") else []) + self.meta + [(tr("Date d'édition"), date_fr())]
        y = 22 * mm + 8 * mm * len(meta)
        c.setStrokeColor(RULE)
        c.setLineWidth(0.6)
        c.line(MARGE, y + 9 * mm, pw - MARGE, y + 9 * mm)
        for k, v in meta:
            c.setFont("Inter-Medium", 8.5)
            c.setFillColor(MUTED)
            c.drawString(MARGE, y, k.upper())
            c.setFont("Inter-Regular", 10)
            c.setFillColor(INK)
            c.drawString(70 * mm, y, _court(v))
            y -= 8 * mm
        c.restoreState()

    def _mention(self, c, droite, y, petit=False, sombre=False):
        """Badge de mention de diffusion (cadre rouge). `petit` : version d'en-tête des pages intérieures.
        En thème Tenable : coins droits ; sur la couverture sombre le cadre et le texte sont blancs."""
        txt = self.h["mention"].upper()
        taille, marge, haut, bas = (6.5, 4.5 * mm, 4.8 * mm, 1.6 * mm) if petit else (8, 6 * mm, 6.5 * mm, 2 * mm)
        c.setFont("Inter-SemiBold", taille)
        lw = pdfmetrics.stringWidth(txt, "Inter-SemiBold", taille) + marge
        couleur = colors.white if sombre else MAUVAIS
        c.setStrokeColor(couleur)
        c.setFillColor(couleur)
        c.setLineWidth(0.7 if petit else 0.8)
        if self.tenable:
            c.rect(droite - lw, y - bas, lw, haut, stroke=1, fill=0)
        else:
            c.roundRect(droite - lw, y - bas, lw, haut, 1.0 * mm if petit else 1.2 * mm, stroke=1, fill=0)
        c.drawCentredString(droite - lw / 2, y, txt)

    def _page(self, c, doc):
        c.saveState()
        pw, ph = A4
        fichier, ratio, client = self._logo_entete(False)
        if fichier:
            h = 15 * mm if client else 6.5 * mm
            c.drawImage(fichier, MARGE, ph - 8 * mm - (h if client else 14 * mm), height=h, width=h * ratio, mask="auto")
        c.setFont("Inter-Regular", 8)
        c.setFillColor(MUTED)
        badge = bool(self.h.get("mention") and self.h.get("mention_interieur"))
        dy = 1.5 * mm if badge else 0                                  # le texte d'en-tête descend pour laisser la place au badge
        entete = " · ".join(x for x in (self.h.get("titre"), self.nom_modele) if x)
        c.drawRightString(pw - MARGE, ph - 17 * mm - dy, entete[:110])
        if self.h.get("client"):
            c.drawRightString(pw - MARGE, ph - 21 * mm - dy, self.h["client"][:90])
        if badge:
            self._mention(c, pw - MARGE, ph - 11.2 * mm, petit=True)
            c.setFont("Inter-Regular", 8)
            c.setFillColor(MUTED)
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(MARGE, ph - 25 * mm, pw - MARGE, ph - 25 * mm)
        c.line(MARGE, 13 * mm, pw - MARGE, 13 * mm)
        parties = [self.h["mention"]] if self.h.get("mention") and not badge else []   # avec le badge d'en-tête, plus de mention en pied
        parties += [x for x in (self.h.get("pied"), tr("Périmètre : {p}", p=self.portee) if self.portee else "") if x]
        c.drawString(MARGE, 8.5 * mm, _ajuster(" · ".join(parties), "Inter-Regular", 8, W - 24 * mm))
        c.restoreState()

    def construire(self, story):
        doc = BaseDocTemplate(self.sortie, pagesize=A4, leftMargin=MARGE, rightMargin=MARGE, topMargin=31 * mm,
                              bottomMargin=19 * mm, title=f"{self.h.get('titre')} – {self.nom_modele}",
                              author=self.h.get("client") or "", subject=self.nom_modele)
        cadre = Frame(MARGE, 19 * mm, W, A4[1] - 50 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        doc.addPageTemplates([PageTemplate("couverture", [cadre], onPage=self._couverture),
                              PageTemplate("corps", [cadre], onPage=self._page)])
        doc.build([NextPageTemplate("corps"), PageBreak()] + story, canvasmaker=lambda *a, **k: _CanvasNumerote(
            *a, filigrane=self.h.get("filigrane") or "", filigrane_couverture=bool(self.h.get("filigrane_couverture", True)), **k))
        return self.sortie

    # ------------------------------------------------------------------ blocs
    def chemin_tmp(self, nom):
        return os.path.join(self.tmp, nom)

    def image(self, chemin, largeur):
        w, h = PILImage.open(chemin).size
        return Image(chemin, width=largeur, height=largeur * h / w)

    def pastille(self, sev, largeur=17 * mm):
        t = Table([[Paragraph(FR[sev], st("p", fontName="Inter-SemiBold", fontSize=7.2, leading=9,
                                          textColor=SEV_TXT[sev], alignment=TA_CENTER))]],
                  colWidths=[largeur], rowHeights=[4.6 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEVC[sev]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
                               ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]
                              + ([] if self.tenable else [("ROUNDEDCORNERS", [2, 2, 2, 2])])))
        return t

    def pastille_score(self, valeur, sev, largeur=11 * mm):
        """Valeur d'un score (ACR, AES) dans une pastille de la couleur de son niveau ; tiret si inconnu."""
        from .scores import fmt
        if not sev:
            return Paragraph("—", self.CELLR)
        t = Table([[Paragraph(fmt(valeur), st("ps", fontName="Inter-SemiBold", fontSize=7.6, leading=9,
                                              textColor=SEV_TXT[sev], alignment=TA_CENTER))]],
                  colWidths=[largeur], rowHeights=[4.6 * mm], hAlign="RIGHT")
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEVC[sev]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
                               ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1)]
                              + ([] if self.tenable else [("ROUNDEDCORNERS", [2, 2, 2, 2])])))
        return t

    def tableau(self, data, largeurs, entete=True):
        t = Table(data, colWidths=largeurs, repeatRows=1 if entete else 0)
        cmds = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 3.2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2), ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE)]
        if entete:
            cmds += [("LINEBELOW", (0, 0), (-1, 0), 0.9, INK), ("BOTTOMPADDING", (0, 0), (-1, 0), 4)]
        for r in range(1 if entete else 0, len(data)):
            if (r % 2 == 0) == entete:
                cmds.append(("BACKGROUND", (0, r), (-1, r), ZEBRA))
        t.setStyle(TableStyle(cmds))
        return t

    def entete_tableau(self, *titres, droite=()):
        """En-tête de tableau ; `droite` : positions des colonnes numériques, alignées à droite comme leurs valeurs."""
        return [Paragraph(x, self.CELLHR if i in droite else self.CELLH) for i, x in enumerate(titres)]

    def indicateurs(self, tuiles):
        """tuiles : liste de (valeur, libellé, couleur ou None)."""
        cells = []
        for v, lbl, col in tuiles:
            couleur = "#" + (col or INK).hexval()[2:]
            police, taille = ("Inter-Light", 24) if self.tenable else ("Inter-SemiBold", 22)      # grands chiffres : Light dans la charte
            cells.append([Paragraph(f'<font name="{police}" size="{taille}" color="{couleur}">{v}</font>', st("k", leading=taille + 4)),
                          Paragraph(lbl, self.SMALL)])
        t = Table([cells], colWidths=[W / len(tuiles)] * len(tuiles))
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                               ("LINEBEFORE", (1, 0), (-1, -1), 0.5, RULE), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                               ("BACKGROUND", (0, 0), (-1, -1), self.pale), ("TOPPADDING", (0, 0), (-1, -1), 7)]))
        return t

    def puces(self, lignes):
        return [Paragraph(b, st("b", leftIndent=10, bulletIndent=0, spaceAfter=3), bulletText="•") for b in lignes]

    def encadre_action(self, texte, titre=None):
        titre = titre or tr("Action à mener")
        t = Table([[Paragraph(f'<font name="Inter-SemiBold" color="{self.accent_hex}">{esc(titre)}</font><br/>{esc(texte)}', self.ACT)]],
                  colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), self.pale), ("LINEBEFORE", (0, 0), (0, -1), 2.2, self.accent),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        return t

    def bandeau(self, numero, titre, sev=None, ancre=None):
        """En-tête d'une solution : bandeau teinté sur toute la largeur, [numéro] [sévérité] titre.
        La pastille est placée juste après le numéro : elle est ainsi toujours au même endroit, et les titres s'alignent."""
        a = f'<a name="{ancre}"/>' if ancre else ""
        cells = [Paragraph(f"{a}{numero}", st("n", fontName="Inter-SemiBold", fontSize=12.5, textColor=colors.white,
                                               alignment=TA_CENTER, leading=15))]
        larg = [10 * mm]
        if sev:
            cells.append(self.pastille(sev))
            larg.append(17 * mm + 8 * mm)
        cells.append(Paragraph(esc(titre), st("t", fontName="Inter-SemiBold", fontSize=11.5, leading=14.5)))
        larg.append(W - sum(larg))
        t = Table([cells], colWidths=larg, rowHeights=[10 * mm])
        cmds = [("BACKGROUND", (0, 0), (-1, -1), self.pale), ("BACKGROUND", (0, 0), (0, 0), self.accent),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (-1, 0), (-1, 0), 6)]
        if sev:
            cmds += [("LEFTPADDING", (1, 0), (1, 0), 4 * mm), ("RIGHTPADDING", (1, 0), (1, 0), 0), ("LEFTPADDING", (2, 0), (2, 0), 2.5 * mm)]
        else:
            cmds.append(("LEFTPADDING", (1, 0), (1, 0), 3.5 * mm))
        t.setStyle(TableStyle(cmds))
        return t

    def deux_graphiques(self, gauche, droite):
        """gauche / droite : (légende, chemin de l'image)."""
        t = Table([[[Paragraph(gauche[0], self.CAP), self.image(gauche[1], W / 2 - 4 * mm)],
                    [Paragraph(droite[0], self.CAP), self.image(droite[1], W / 2 - 4 * mm)]]], colWidths=[W / 2, W / 2])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        return t

    def compte_sev(self, counts):
        return " · ".join(tr("{n} " + _SEV_ACCORD[k][counts[k] > 1], n=counts[k])
                          for k in ("Critical", "High", "Medium", "Low") if counts.get(k))


__all__ = ["DocumentPDF", "W", "INK", "MUTED", "RULE", "SEVC", "BON", "MAUVAIS", "FR", "esc", "st", "mm",
           "Paragraph", "Spacer", "Table", "TableStyle", "PageBreak", "KeepTogether", "date_fr", "pluriel",
           "HABILLAGE_DEFAUT", "colors", "TA_CENTER", "TA_RIGHT"]
