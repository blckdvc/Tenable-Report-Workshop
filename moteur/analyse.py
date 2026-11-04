"""Chargement d'un export, application du périmètre et calcul des agrégats partagés par tous les modèles."""
import fnmatch
import ipaddress

from . import regles as R

SEVERITES = ["Critical", "High", "Medium", "Low"]

PERIMETRE_DEFAUT = {
    "severites": ["Critical", "High", "Medium", "Low"],   # sévérités retenues dans le rapport
    "top": 20,                                            # nombre de solutions du plan d'action
    "ponderation": "severite",                            # « severite » (40/10/3/1), « vpr » ou « vpr_acr » : base du % du risque
    "inclure": "",                                        # une entrée par ligne ; vide = toutes les machines
    "exclure": "",
}


def _regles_machines(texte):
    """Une entrée par ligne : adresse IP, réseau CIDR (10.0.0.0/8) ou nom avec jokers (*.lab, srv-*)."""
    out = []
    for ligne in (texte or "").replace(",", "\n").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        try:
            out.append(("reseau", ipaddress.ip_network(ligne, strict=False)))
        except ValueError:
            out.append(("nom", ligne.lower()))
    return out


def _correspond(regles_m, ip, nom):
    nom = (nom or "").lower()
    court = nom.split(".")[0].split("\\")[-1]
    for genre, val in regles_m:
        if genre == "reseau":
            try:
                if ipaddress.ip_address(ip) in val:
                    return True
            except ValueError:
                pass
        elif fnmatch.fnmatch(nom, val) or fnmatch.fnmatch(court, val) or fnmatch.fnmatch(ip, val):
            return True
    return False


def appliquer_perimetre(df, perimetre):
    p = {**PERIMETRE_DEFAUT, **(perimetre or {})}
    df = df[df["Severity"].isin(p["severites"] or SEVERITES)]
    inc, exc = _regles_machines(p["inclure"]), _regles_machines(p["exclure"])
    if inc or exc:
        machines = df[["host", "dns"]].drop_duplicates("host")
        garder = {h for h, d in machines.itertuples(index=False)
                  if (not inc or _correspond(inc, h, d)) and not _correspond(exc, h, d)}
        df = df[df["host"].isin(garder)]
    return df


def libelle_machine(dns, ip, court=True):
    if dns and court:
        return dns.split("\\")[-1].split(".")[0] if "\\" in dns else dns.split(".")[0]
    return dns or ip


class Analyse:
    """Résultat complet pour un export : solutions classées, machines, indicateurs."""

    def __init__(self, chemin, perimetre=None, regles=None, nom_fichier=None, portee=None):
        self.nom_fichier = nom_fichier or chemin
        self.portee = portee                                  # sélection Security Center / Vulnerability Management (voir portee.py)
        self.perimetre = {**PERIMETRE_DEFAUT, **(perimetre or {})}
        self.regles = regles if regles is not None else R.load_rules()
        brut = R.read_export(chemin)
        self.n_info = int((brut["Severity"] == "Info").sum())
        prep = R.preparer(brut)
        self.produit = brut.attrs.get("produit", "sc")                # « sc » : Security Center, « vm » : Vulnerability Management
        self.n_hors_perimetre = prep["host"].nunique()
        self.ponderation = self.perimetre.get("ponderation") if self.perimetre.get("ponderation") in R.PONDERATIONS else "severite"
        self.df = appliquer_perimetre(prep, self.perimetre)
        self.df_, self.occ, self.sols, self.total, self.sans_regle = R.analyser(self.df, self.regles, self.ponderation)
        self.n_hors_perimetre -= self.occ["host"].nunique()
        self.top = min(int(self.perimetre.get("top") or 20), len(self.sols))
        self.TOP, self.RESTE = self.sols[:self.top], self.sols[self.top:]
        self.cles_top = {s["key"] for s in self.TOP}
        self.n_hosts = self.occ["host"].nunique()
        self.acr_part = float(self.occ["ACR"].notna().mean()) if len(self.occ) else 0.0
        self.vpr_part = float(self.occ["vpr_ok"].mean()) if len(self.occ) else 0.0     # part des constats qui portent un VPR
        self.sev_occ = self.occ["Severity"].value_counts().to_dict()
        cum, self.cums = 0, []
        for s in self.sols:
            cum += s["pct"]
            self.cums.append(cum)
        self.machines = self._machines()
        vals = [m["aes"] for m in self.machines if m["aes"] == m["aes"]]       # AES des machines du périmètre (connu pour certaines seulement)
        self.aes_n = len(vals)
        self.aes_moy = sum(vals) / len(vals) if vals else None                  # moyenne simple : une machine = une voix
        self.aes_max = max(vals) if vals else None
        self.aes_rep = {"High": sum(v >= 650 for v in vals), "Medium": sum(350 <= v < 650 for v in vals), "Low": sum(v < 350 for v in vals)}
        self.a_acr, self.a_aes = bool(self.occ["ACR"].notna().any()), bool(self.occ["AES"].notna().any())

    def cum_at(self, k):
        return self.cums[min(k, len(self.cums)) - 1] if self.cums else 0

    def _machines(self):
        out = []
        for h, g in self.occ.groupby("host"):
            out.append(dict(ip=h, dns=g["dns"].iloc[0], score=int(g["weight"].sum()),
                            sevscore=g.groupby("Severity")["weight"].sum().to_dict(),
                            counts=g["Severity"].value_counts().to_dict(), n=len(g),
                            acr=g["ACR"].max(), aes=g["AES"].max(),
                            sols=[s for s in self.sols if h in set(s["hosts"]["host"])]))
        if any(x["aes"] == x["aes"] for x in out):       # AES connu : machines les plus exposées d'abord
            out.sort(key=lambda x: (x["aes"] != x["aes"], -(x["aes"] if x["aes"] == x["aes"] else 0), -x["score"], x["ip"]))
        else:
            out.sort(key=lambda x: (-x["score"], x["ip"]))
        return out

    def resume(self):
        """Aperçu affiché dans l'interface après import."""
        n_plug = self.occ["Plugin"].nunique()
        return {
            "fichier": self.nom_fichier,
            "portee": self.portee,
            "machines": self.n_hosts,
            "machines_exclues": max(self.n_hors_perimetre, 0),
            "vulnerabilites": len(self.occ),
            "par_severite": {k: int(self.sev_occ.get(k, 0)) for k in SEVERITES},
            "info_ignorees": self.n_info,
            "solutions": len(self.sols),
            "ponderation": {"mode": self.ponderation, "vpr": round(100 * self.vpr_part), "acr": round(100 * self.acr_part)},
            "couverture": {"plugins": n_plug, "avec_regle": n_plug - len(self.sans_regle)},
            "sans_regle": self.sans_regle[:200],
            "top": [{"rang": s["rank"], "titre": s["title"], "severite": s["maxsev"],
                     "machines": len(s["hosts"]), "pct": round(s["pct"], 1)} for s in self.sols[:10]],
        }
