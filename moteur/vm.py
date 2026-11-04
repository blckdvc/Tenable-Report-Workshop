"""Export CSV de Tenable Vulnerability Management : conversion vers les colonnes internes (celles de Security Center).

Deux présentations sont reconnues :
- « propriétés d'export » (asset.id, definition.name, severity, state…), celle de l'export des vulnérabilités ;
- « colonnes du CSV de l'interface » (Plugin ID, Name, Plugin Family, Risk, FQDN…), d'après la documentation Tenable.

La première a été vérifiée sur un export réel ; la seconde est reprise de la documentation et n'a pas été éprouvée.
Une machine est identifiée par sa première adresse IPv4 (comme dans Security Center) : Vulnerability Management peut
connaître le même poste sous plusieurs identifiants d'asset, qui seraient sinon comptés deux fois."""
import ipaddress
import re

import pandas as pd

COLONNES = ["Plugin", "Plugin Name", "Family", "Severity", "IP Address", "DNS Name", "NetBIOS Name", "Protocol", "Port", "VPR", "ACR", "AES",
            "CVE", "Repository", "Last Observed", "Solution", "Synopsis", "State"]
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
        "info": "Info", "informational": "Info", "none": "Info"}
_ETATS_FERMES = {"FIXED"}
_API = {"asset.id", "asset.ipv4_addresses", "definition.id", "definition.name", "severity"}
_UI = {"Plugin ID", "Name", "IP Address"}


def format_vm(df):
    """« api », « ui » ou None selon les colonnes."""
    cols = set(df.columns)
    if _API <= cols:
        return "api"
    if _UI <= cols and ("Risk" in cols or "Severity" in cols) and "Plugin Name" not in cols:
        return "ui"
    return None


def _ip(v):
    for part in str(v if v == v else "").split(","):
        part = part.strip()
        try:
            ipaddress.ip_address(part)
            return part
        except ValueError:
            continue
    return ""


def _est_ip(nom):
    try:
        ipaddress.ip_address(str(nom).strip())
        return True
    except ValueError:
        return False


def _cves(*textes):
    trouves = []
    for t in textes:
        trouves += [c.upper() for c in _CVE.findall("" if t != t or t is None else str(t))]
    return ", ".join(dict.fromkeys(trouves))


def convertir(df, fmt):
    g = (lambda c: df[c] if c in df.columns else pd.Series([None] * len(df), index=df.index))
    if fmt == "api":
        out = pd.DataFrame({
            "Plugin": g("definition.id"), "Plugin Name": g("definition.name"), "Family": g("definition.family"),
            "Severity": g("severity"), "IP Address": g("asset.ipv4_addresses").map(_ip), "DNS Name": g("asset.name"),
            "Protocol": g("protocol"), "Port": g("port"), "VPR": g("definition.vpr.score"), "Solution": g("definition.solution"),
            "State": g("state"), "Synopsis": g("definition.synopsis"), "Last Observed": g("last_found"), "ACR": g("acr"), "AES": g("aes"),
            "CVE": [_cves(c, n, d) for c, n, d in zip(g("definition.cve"), g("definition.name"), g("definition.description"))]})
        manque_ip = out["IP Address"] == ""
        out.loc[manque_ip, "IP Address"] = g("asset.id")[manque_ip].astype(str)         # asset sans IPv4 : repli sur son identifiant
    else:
        sev = g("Risk") if "Risk" in df.columns else g("Severity")
        out = pd.DataFrame({
            "Plugin": g("Plugin ID"), "Plugin Name": g("Name"), "Family": g("Plugin Family"), "Severity": sev,
            "IP Address": g("IP Address").map(_ip), "DNS Name": g("FQDN"), "NetBIOS Name": g("NetBios"),
            "Protocol": g("Protocol"), "Port": g("Port"), "VPR": g("Vulnerability Priority Rating (VPR)"),
            "Solution": g("Solution"), "Synopsis": g("Synopsis"), "State": g("Vulnerability State"),
            "CVE": [c if isinstance(c, str) and c else _cves(n, d) for c, n, d in zip(g("CVE"), g("Name"), g("Description"))]})
    out["Severity"] = out["Severity"].map(lambda s: _SEV.get(str(s).strip().lower(), str(s).strip().title()))
    out["Port"] = pd.to_numeric(out["Port"], errors="coerce")
    out["Protocol"] = out["Protocol"].astype("string").str.upper()
    out["Plugin Name"] = out["Plugin Name"].fillna("").astype(str)
    out = out[~out["State"].astype(str).str.upper().isin(_ETATS_FERMES)].copy()
    # un nom d'asset qui est une adresse IP n'est pas un nom DNS ; si un autre asset de la même IP en a un, on le reprend
    nom = out["DNS Name"].where(~out["DNS Name"].map(_est_ip), None)
    nom = nom.where(nom.notna() & (nom.astype(str).str.strip() != ""), None)
    par_ip = nom.groupby(out["IP Address"]).transform(lambda s: s.dropna().iloc[0] if s.notna().any() else None)
    out["DNS Name"] = nom.fillna(par_ip)
    for c in COLONNES:
        if c not in out.columns:
            out[c] = None
    return out[COLONNES].reset_index(drop=True)
