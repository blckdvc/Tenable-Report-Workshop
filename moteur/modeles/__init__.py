"""Catalogue des modèles de rapport disponibles."""
from . import complet, synthese, fiches, comparaison, plan_excel, php2shell

MODELES = {
    "complet": dict(nom="Plan de remédiation complet", format="pdf", exports=1, module=complet,
                    description="Synthèse, plan d'action, détail par solution avec les machines concernées, guide par machine."),
    "synthese": dict(nom="Synthèse exécutive", format="pdf", exports=1, module=synthese,
                     description="Trois pages pour la direction : indicateurs, graphiques, actions prioritaires, recommandations."),
    "fiches": dict(nom="Fiches par machine", format="pdf", exports=1, module=fiches,
                   description="Une fiche autonome par serveur, à remettre aux équipes d'exploitation."),
    "comparaison": dict(nom="Comparaison de deux exports", format="pdf", exports=2, module=comparaison,
                        description="Évolution entre deux campagnes : corrigé, nouveau, persistant, avancement par solution."),
    "php2shell": dict(nom="Exposition PHP2Shell", format="pdf", exports=1, module=php2shell, toutes_severites=True,
                      description="Machines concernées par PHP2Shell (CVE-2026-109618 et 109619), priorités, mesures provisoires, vérification de compromission."),
    "plan_excel": dict(nom="Plan d'action Excel", format="xlsx", exports=1, module=plan_excel,
                       description="Tableau de suivi : responsable, échéance, statut, avec indicateurs d'avancement."),
}


def perimetre_pour(modele, perimetre):
    """Périmètre du profil, sans filtre de sévérité pour les modèles qui doivent être exhaustifs (PHP2Shell)."""
    p = dict(perimetre or {})
    if modele.get("toutes_severites"):
        p["severites"] = []
    return p
