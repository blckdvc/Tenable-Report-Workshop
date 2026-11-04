"""Synthèse exécutive : 3 pages pour la direction (indicateurs, graphiques, priorités, recommandations)."""
from ..i18n import tr
from ..commun import DocumentPDF, W, esc, Paragraph, Spacer, PageBreak, pluriel, mm
from .. import graphiques as G
from .complet import chapitre_synthese, guide_lecture, meta, tableau_plan
from ..scores import niveau_aes, source

NOM = "Synthèse exécutive"


def _texte_guide(an):
    if an.ponderation == "vpr":
        return tr("Chaque vulnérabilité pèse selon son VPR, la probabilité qu'elle soit exploitée (de 0,1 à 10). Le « % du risque » d'une action est la part "
                  "du score total qu'elle supprime : plus il est élevé, plus l'action est prioritaire.")
    if an.ponderation == "vpr_acr":
        return tr("Chaque vulnérabilité pèse selon son VPR, la probabilité qu'elle soit exploitée (de 0,1 à 10), et selon l'importance de la machine concernée (ACR). "
                  "Le « % du risque » d'une action est la part du score total qu'elle supprime : plus il est élevé, plus l'action est prioritaire.")
    return tr("Chaque vulnérabilité pèse selon sa sévérité : critique 40, élevée 10, moyenne 3, faible 1. Le « % du risque » d'une action est la part "
              "du score total qu'elle supprime : plus il est élevé, plus l'action est prioritaire.")


def guide_synthese(d, an):
    """Page « Comment lire ce rapport » allégée pour la direction : quelques notions en langage courant, sans méthode détaillée."""
    lignes = [d.entete_tableau(tr("Notion"), tr("En clair")),
              [Paragraph(tr("Action"), d.CELLB), Paragraph(tr("Une mise à jour ou un changement de configuration qui corrige plusieurs vulnérabilités à la fois."), d.CELL)],
              [Paragraph(tr("Score de risque"), d.CELLB),
               Paragraph(_texte_guide(an), d.CELL)],
              [Paragraph(tr("Sévérité"), d.CELLB),
               Paragraph(tr("Critique : CVSS 9,0 à 10 · Élevée : 7,0 à 8,9 · Moyenne : 4,0 à 6,9 · Faible : 0,1 à 3,9."), d.CELL)]]
    out = [Paragraph(tr("Comment lire ce rapport"), d.H1),
           Paragraph(tr("Ce rapport résume en quelques pages l'état du risque et les actions à engager. Voici les notions utilisées."), d.LEAD),
           d.tableau(lignes, [32 * mm, W - 32 * mm])]
    if an.a_aes and an.aes_moy is not None:
        lignes += [[Paragraph("AES", d.CELLB), Paragraph(tr("Exposition d'une machine, de 0 à 1 000 : plus la note est haute, plus elle est exposée."), d.CELL)],
                   [Paragraph("CES", d.CELLB), Paragraph(tr("Même échelle, pour l'ensemble du périmètre ; ici, la moyenne des AES des machines. "
                                                            "Faible en dessous de 350, moyen de 350 à 649, élevé à partir de 650."), d.CELL)]]
        out[2] = d.tableau(lignes, [32 * mm, W - 32 * mm])
        G.jauge_aes(d.chemin_tmp("jauge_guide.png"), an.aes_moy, tr("Votre périmètre"))
        out += [Spacer(1, 10), Paragraph(tr("Lire l'AES et le CES"), d.CAP), d.image(d.chemin_tmp("jauge_guide.png"), W * 0.92)]
    return out


def generer(an, habillage, sortie):
    d = DocumentPDF(sortie, habillage, tr(NOM), meta(an))
    story = [*guide_synthese(d, an), PageBreak(), *chapitre_synthese(d, an, numero="1.")]
    n = an.top                                           # même réglage « solutions du plan d'action » que les autres rapports
    crit = [s for s in an.TOP if s["maxsev"] == "Critical"]
    larges = sorted(an.TOP, key=lambda s: -len(s["hosts"]))[:1]
    recos = [
        tr("<b>Engager sans attendre les {n} premières actions</b> : elles éliminent {pct:.0f} % du risque mesuré.",
           n=min(5, n), pct=an.cum_at(min(5, n))),
    ]
    if crit:
        recos.append(tr("<b>Traiter en priorité {actions} de niveau critique</b>, en commençant par « {titre} ».",
                        actions=pluriel(len(crit), 'action'), titre=esc(crit[0]['title'])))
    if an.machines:
        h = an.machines[0]
        recos.append(tr("<b>Cibler d'abord les machines les plus exposées</b>, à commencer par {nom} "
                        "(score {score}, soit {pct:.0f} % du risque).",
                        nom=esc(h['dns'] or h['ip']), score=h['score'], pct=100 * h['score'] / an.total))
    if larges and len(larges[0]["hosts"]) > 2:
        recos.append(tr("<b>Industrialiser les corrections répétitives</b> : « {titre} » concerne "
                        "{machines} et se prête à un déploiement par lot.",
                        titre=esc(larges[0]['title']), machines=pluriel(len(larges[0]['hosts']), 'machine')))
    if an.a_aes and an.aes_moy is not None:
        recos.append(tr("<b>Réduire l'exposition globale</b> : le Cyber Exposure Score du périmètre est de {aes} ({niveau}) ; il baisse en corrigeant "
                        "d'abord les machines dont l'AES est le plus élevé.", aes=f"{an.aes_moy:.0f}", niveau=niveau_aes(an.aes_moy)))
    recos.append(tr("<b>Mesurer les progrès</b> : relancer une analyse après les corrections et comparer les deux exports "
                    "pour vérifier la baisse du score de risque."))
    story += [PageBreak(), Paragraph(tr("2. Les {n} actions prioritaires", n=n), d.H1),
              Paragraph(tr("Chaque action regroupe toutes les vulnérabilités corrigées par une même mise à jour ou un même changement "
                           "de configuration. Elles sont classées par impact sur la réduction du risque : "
                           "les premières sont celles qui font le plus baisser le score."), d.LEAD),
              tableau_plan(d, an.sols[:n], liens=False), Spacer(1, 4),
              Paragraph(tr("Ces {n} actions réduisent le risque mesuré de {pct:.0f} %.", n=n, pct=an.cum_at(n)), d.SMALL),
              Spacer(1, 14), Paragraph(tr("Recommandations"), d.H2), *d.puces(recos)]
    return d.construire(story)
