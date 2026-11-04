"""Graphiques des rapports (matplotlib), rendus en PNG haute définition."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
from matplotlib.ticker import FuncFormatter
import numpy as np

from .i18n import tr

_POLICES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "polices")
for _w in ("Regular", "Medium", "SemiBold"):
    fm.fontManager.addfont(os.path.join(_POLICES, f"Inter-{_w}.ttf"))
plt.rcParams.update({"font.family": "Inter", "font.size": 8.5, "axes.edgecolor": "#C9C9C9",
                     "axes.labelcolor": "#3A3A3A", "xtick.color": "#5A5A5A", "ytick.color": "#3A3A3A",
                     "axes.spines.top": False, "axes.spines.right": False})

_AEONIK = set()


def activer(theme):
    """Police des graphiques : Aeonik en thème Tenable, Inter sinon (les couleurs de sévérité restent des couleurs de données)."""
    if theme == "tenable":
        from .charte import aeonik_disponible
        famille = "Aeonik" if aeonik_disponible() else "Inter"
        for w in (("Light", "Regular", "Medium", "SemiBold") if famille == "Aeonik" else ()):
            if w not in _AEONIK:
                fm.fontManager.addfont(os.path.join(_POLICES, f"Aeonik-{w}.ttf"))
                _AEONIK.add(w)
        plt.rcParams.update({"font.family": famille, "axes.edgecolor": "#CCCCCC", "axes.labelcolor": "#1E2426",
                             "xtick.color": "#5B6062", "ytick.color": "#1E2426"})
    else:
        plt.rcParams.update({"font.family": "Inter", "axes.edgecolor": "#C9C9C9", "axes.labelcolor": "#3A3A3A",
                             "xtick.color": "#5A5A5A", "ytick.color": "#3A3A3A"})


SEV = ["Critical", "High", "Medium", "Low"]
SEV_FR = {"Critical": "Critique", "High": "Élevée", "Medium": "Moyenne", "Low": "Faible"}   # clés de catalogue : lire via nom_sev()
COL = {"Critical": "#A4161A", "High": "#E8590C", "Medium": "#F2A007", "Low": "#2F6FCB"}
INK, MUTED, GRID = "#161616", "#5A5A5A", "#E6E6E6"
BON, MAUVAIS, NEUTRE = "#2E7D32", "#A4161A", "#9AA0A6"


def nom_sev(s):
    """Nom de la sévérité dans la langue courante."""
    return tr(SEV_FR[s])


def _finish(fig, path):
    fig.tight_layout()
    fig.savefig(path, facecolor="white")
    plt.close(fig)
    return path


def _xgrid(ax):
    ax.xaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


def severity_bars(counts, path, size=(3.3, 2.0)):
    fig, ax = plt.subplots(figsize=size, dpi=300)
    labels = [nom_sev(s) for s in SEV][::-1]
    vals = [counts.get(s, 0) for s in SEV][::-1]
    top = max(vals) or 1
    bars = ax.barh(labels, vals, color=[COL[s] for s in SEV][::-1], height=0.62, edgecolor="white", linewidth=1.2)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + top * 0.02, b.get_y() + b.get_height() / 2, str(v), va="center", color=INK, fontweight="semibold")
    ax.set_xlim(0, top * 1.18)
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.set_xlabel(tr("Vulnérabilités (couples machine / vulnérabilité)"), fontsize=7.5, color=MUTED)
    return _finish(fig, path)


def pareto(pcts, path, n=20, accent="#000091", size=(3.3, 2.0)):
    cum = np.cumsum(pcts[:n]) if len(pcts) else np.array([0.0])
    x = np.arange(1, len(cum) + 1)
    fig, ax = plt.subplots(figsize=size, dpi=300)
    ax.plot(x, cum, color=accent, lw=2, solid_capstyle="round", zorder=3)
    ax.fill_between(x, cum, color=accent, alpha=0.06, zorder=1)
    for k in (5, 10):
        if k <= len(cum):
            ax.annotate(tr("{v:.0f} %", v=cum[k-1]), (k, cum[k-1]), xytext=(4, -12), textcoords="offset points",
                        color=INK, fontweight="semibold", fontsize=8)
            ax.plot([k], [cum[k-1]], "o", ms=6, mfc="white", mec=accent, mew=1.5, zorder=4)
    ax.set_ylim(0, 105)
    ax.set_xlim(0.5, len(cum) + 0.5)
    ticks = [t for t in (1, 5, 10, 15, 20, 30, 40, 50) if t <= len(cum)] or [1]
    ax.set_xticks(ticks)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: tr("{v:.0f} %", v=v)))
    ax.yaxis.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    ax.set_xlabel(tr("Nombre de solutions appliquées (par ordre de priorité)"), fontsize=7.5, color=MUTED)
    return _finish(fig, path)


def top_hosts(rows, path, width=7.0):
    """rows : liste de (libellé, {sévérité: score}) triée par score décroissant."""
    rows = rows[::-1]
    fig, ax = plt.subplots(figsize=(width, 0.23 * len(rows) + 0.75), dpi=300)
    left = np.zeros(len(rows))
    y = np.arange(len(rows))
    for s in SEV:
        v = np.array([r[1].get(s, 0) for r in rows], dtype=float)
        ax.barh(y, v, left=left, color=COL[s], height=0.62, edgecolor="white", linewidth=1.2, label=nom_sev(s))
        left += v
    top = left.max() or 1
    for i, t in enumerate(left):
        ax.text(t + top * 0.01, i, f"{int(t)}", va="center", color=INK, fontsize=7.5, fontweight="semibold")
    ax.set_yticks(y, [r[0] for r in rows], fontsize=7.5)
    ax.set_xlim(0, top * 1.08)
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.set_xlabel(tr("Score de risque (Critique 40 · Élevée 10 · Moyenne 3 · Faible 1 par vulnérabilité)"), fontsize=7.5, color=MUTED)
    ax.legend(ncol=4, loc="lower right", bbox_to_anchor=(1, 1.0), frameon=False, fontsize=7.5, handlelength=1, handleheight=0.8)
    return _finish(fig, path)


def compare_severity(avant, apres, path, accent="#000091", size=(3.3, 2.2)):
    """Barres groupées : vulnérabilités par sévérité, export précédent et export récent."""
    fig, ax = plt.subplots(figsize=size, dpi=300)
    y = np.arange(len(SEV))[::-1]
    h = 0.36
    va = [avant.get(s, 0) for s in SEV]
    vb = [apres.get(s, 0) for s in SEV]
    top = max(va + vb) or 1
    ax.barh(y + h / 2 + 0.02, va, height=h, color=NEUTRE, label=tr("Export précédent"), edgecolor="white", linewidth=1)
    ax.barh(y - h / 2 - 0.02, vb, height=h, color=accent, label=tr("Export récent"), edgecolor="white", linewidth=1)
    for yy, a, b in zip(y, va, vb):
        ax.text(a + top * 0.02, yy + h / 2 + 0.02, str(a), va="center", fontsize=7, color=MUTED)
        ax.text(b + top * 0.02, yy - h / 2 - 0.02, str(b), va="center", fontsize=7.5, color=INK, fontweight="semibold")
    ax.set_yticks(y, [nom_sev(s) for s in SEV])
    ax.set_xlim(0, top * 1.2)
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.legend(ncol=2, loc="lower right", bbox_to_anchor=(1, 1.0), frameon=False, fontsize=7, handlelength=1, handleheight=0.8)
    return _finish(fig, path)


def host_delta(rows, path, width=7.0):
    """rows : (libellé, variation du score) ; baisse en vert, hausse en rouge."""
    rows = rows[::-1]
    fig, ax = plt.subplots(figsize=(width, 0.23 * len(rows) + 0.8), dpi=300)
    y = np.arange(len(rows))
    vals = np.array([r[1] for r in rows], dtype=float)
    ax.barh(y, vals, color=[BON if v < 0 else MAUVAIS for v in vals], height=0.6, edgecolor="white", linewidth=1)
    span = np.abs(vals).max() or 1
    for i, v in enumerate(vals):
        ax.text(v + (span * 0.015 if v >= 0 else -span * 0.015), i, f"{int(v):+d}", va="center",
                ha="left" if v >= 0 else "right", fontsize=7.5, color=INK, fontweight="semibold")
    ax.axvline(0, color="#8A8A8A", lw=0.8)
    ax.set_yticks(y, [r[0] for r in rows], fontsize=7.5)
    ax.set_xlim(-span * 1.2, span * 1.2)
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    ax.set_xlabel(tr("Variation du score de risque (négatif = amélioration)"), fontsize=7.5, color=MUTED)
    return _finish(fig, path)


def jauge_aes(path, valeur=None, etiquette="", size=(6.6, 1.05)):
    """Jauge de l'AES (0 à 1 000) : trois zones, de « risque faible » à « risque élevé », avec un repère à `valeur`."""
    fig, ax = plt.subplots(figsize=size, dpi=300)
    zones = [(0, 350, COL["Low"], tr("Risque faible"), "#FFFFFF"), (350, 650, COL["Medium"], tr("Risque moyen"), INK),
             (650, 1000, COL["High"], tr("Risque élevé"), "#FFFFFF")]
    for a, b, c, lib, txt in zones:
        ax.barh(0, b - a, left=a, height=0.42, color=c, edgecolor="white", linewidth=1.6)
        ax.text((a + b) / 2, 0, lib, ha="center", va="center", color=txt, fontsize=8, fontweight="semibold")
    for x in (0, 350, 650, 1000):
        ax.text(x, -0.42, f"{x:,}".replace(",", " ") if x == 1000 else str(x), ha="center", va="top", fontsize=7.2, color=MUTED)
    if valeur is not None:
        v = max(0, min(1000, valeur))
        ax.plot([v], [0.25], marker="v", markersize=9, color=INK, clip_on=False)
        ax.plot([v, v], [0.25, -0.21], color=INK, lw=1.3)
        ax.text(v, 0.5, (f"{etiquette} · " if etiquette else "") + f"{valeur:.0f}", ha="center", va="bottom", fontsize=8.5,
                fontweight="semibold", color=INK)
    ax.set_xlim(-8, 1008)
    ax.set_ylim(-0.75, 0.95)
    ax.axis("off")
    fig.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    fig.savefig(path, facecolor="white")
    plt.close(fig)
    return path


def barres_h(rows, path, size=(3.3, 2.0), xlabel=""):
    """Barres horizontales : rows = liste de (libellé, valeur, couleur), de haut en bas."""
    fig, ax = plt.subplots(figsize=size, dpi=300)
    rows = rows[::-1]
    y = np.arange(len(rows))
    ax.barh(y, [r[1] for r in rows], color=[r[2] for r in rows], height=0.62)
    top = max([r[1] for r in rows] + [1])
    for i, r in enumerate(rows):
        ax.text(r[1] + top * 0.02, i, f"{int(r[1])}", va="center", color=INK, fontsize=8, fontweight="semibold")
    ax.set_yticks(y, [r[0] for r in rows], fontsize=7.6)
    ax.set_xlim(0, top * 1.18)
    ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    _xgrid(ax)
    ax.spines["left"].set_visible(False)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=7.5, color=MUTED)
    return _finish(fig, path)
