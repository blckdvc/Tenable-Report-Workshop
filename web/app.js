"use strict";
/* Atelier de rapports Tenable : interface locale. Aucune ressource externe. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = [["Critical", "Critique", "--critique"], ["High", "Élevée", "--elevee"], ["Medium", "Moyenne", "--moyenne"], ["Low", "Faible", "--faible"]];
const SEV_FR = Object.fromEntries(SEV.map(([k, v]) => [k, v]));
const MOIS = "janvier février mars avril mai juin juillet août septembre octobre novembre décembre".split(" ");
const sevNom = (k) => t(SEV_FR[k]);                                  // libellé de sévérité dans la langue courante
const locale = () => (LANGUES.find((l) => l.code === I18N.code) || LANGUES[0]).locale;

const etat = {
  modeles: [], profils: [], profil: null, modele: "complet",
  export1: null, export2: null, apercu: null,
  regles: [], reglesOrig: "", ouverte: null, nouveaux: new Set(),
  config: null, source: "fichier", envoi: null,
};

/* ------------------------------------------------------------------ outils */
async function api(methode, url, corps) {
  const opts = { method: methode, headers: {} };
  if (corps instanceof FormData) opts.body = corps;
  else if (corps !== undefined) { opts.body = JSON.stringify(corps); opts.headers["Content-Type"] = "application/json"; }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch { /* réponse vide */ }
  if (!r.ok) throw new Error((data && data.erreur) || t("Erreur {code}", { code: r.status }));
  return data;
}
let toastMinuteur;
function toast(msg, ko = false) {
  const t = $("#toast");
  t.textContent = msg; t.classList.toggle("ko", ko); t.hidden = false;
  clearTimeout(toastMinuteur); toastMinuteur = setTimeout(() => (t.hidden = true), ko ? 6000 : 3000);
}
function statut(id, msg, genre = "") {
  const s = $(id); s.textContent = msg; s.className = "statut " + genre;
}
const taille = (o) => (o > 1048576 ? (o / 1048576).toFixed(1) + " " + t("Mo") : Math.max(1, Math.round(o / 1024)) + " " + t("Ko"));
const dateFr = () => {
  const d = new Date();
  if (I18N.code === "fr") return `${d.getDate()} ${MOIS[d.getMonth()]} ${d.getFullYear()}`;
  return new Intl.DateTimeFormat(locale(), { day: "numeric", month: "long", year: "numeric" }).format(d);
};
const pluriel = (n, mot, mots) => tp(n, mot, mots);

/* ------------------------------------------------------------------ thème (interface et rapports) */
function themeActif() { return document.documentElement.dataset.theme === "tenable" ? "tenable" : "atelier"; }
function majThemeUI() {
  const ten = themeActif() === "tenable";
  $("#theme-nom").textContent = ten ? "Tenable" : "Atelier";
  $$("#theme-menu button").forEach((b) => b.setAttribute("aria-current", String(b.dataset.theme === themeActif())));
  $("#theme-btn").setAttribute("aria-label", `${t("Thème de l'interface et des rapports")} : ${ten ? "Tenable" : "Atelier"}`);
}
function poserTheme(code) {
  document.documentElement.dataset.theme = code === "tenable" ? "tenable" : "atelier";
  try { localStorage.setItem("theme", themeActif()); } catch { /* stockage indisponible */ }
  if (themeActif() === "atelier") document.documentElement.style.removeProperty("--accent");
  majThemeUI();
}
async function chargerTheme() {          // le thème est un réglage de l'application : le serveur fait foi (il s'applique aussi aux rapports)
  try { poserTheme((await api("GET", "/api/theme")).theme); } catch { majThemeUI(); }
}
(() => {
  const btn = $("#theme-btn"), menu = $("#theme-menu");
  btn.addEventListener("click", () => { menu.hidden = !menu.hidden; btn.setAttribute("aria-expanded", String(!menu.hidden)); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".theme-choix")) { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); } });
  menu.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-theme]"); if (!b) return;
    menu.hidden = true; btn.setAttribute("aria-expanded", "false");
    try {
      await api("PUT", "/api/theme", { theme: b.dataset.theme });
      poserTheme(b.dataset.theme);
      epreuve(); if (etat.export1) rafraichirApercu();
      toast(t("Thème : {nom}.", { nom: b.dataset.theme === "tenable" ? "Tenable" : "Atelier" }));
    } catch (err) { toast(err.message, true); }
  });
})();

/* ------------------------------------------------------------------ onglets */
$$(".onglets button").forEach((b) => b.addEventListener("click", () => {
  $$(".onglets button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
  $$(".panneau").forEach((p) => (p.hidden = p.id !== "p-" + b.dataset.onglet));
  if (b.dataset.onglet === "regles" && !etat.regles.length) chargerRegles();
  if (b.dataset.onglet === "configuration") majRequeteJson();
}));

/* ------------------------------------------------------------------ épreuve de couverture */
function epreuve() {
  const p = etat.profil; if (!p) return;
  const h = p.habillage;
  const ten = themeActif() === "tenable", sombre = ten && h.couverture === "sombre";
  document.documentElement.style.setProperty("--accent", ten ? "#1E2426" : (h.couleur || "#000091"));      // la charte remplace la couleur du profil
  const feuille0 = $("#feuille");
  feuille0.classList.toggle("couv-sombre", sombre);
  const logo = $("#f-logo");
  logo.classList.toggle("logo-client", !!h.logo); logo.classList.toggle("logo-tenable", ten && !h.logo);
  if (h.logo) { logo.src = `/api/profils/${p.id}/logo?v=${encodeURIComponent(h.logo + (p._v || ""))}`; logo.hidden = false; }
  else if (ten) { logo.src = `/polices/tenable-logo-${sombre ? "blanc" : "noir"}.svg`; logo.hidden = false; }      // sans logo de profil : logo Tenable
  else { logo.hidden = true; logo.removeAttribute("src"); }
  const m0 = etat.modeles.find((x) => x.id === etat.modele);
  const fil = (h.filigrane || "").trim().replace(/\s+/g, " ").toUpperCase();
  const taille = Math.min(13, 105 / (0.6 * Math.max(fil.length, 1))) + "cqw";            // même adaptation que dans le PDF
  const surCouv = h.filigrane_couverture !== false;
  const poser = (feuille, actif) => { const f = $(".f-filigrane", feuille); f.hidden = !(fil && actif); f.textContent = fil; f.style.fontSize = taille; };
  poser($("#feuille"), surCouv);
  pagesFictives(h, p, fil, taille);
  const pdf = !m0 || m0.format === "pdf";
  etat.pagesVisibles = pdf && !!(fil || (h.mention_interieur && h.mention));   // seulement si une marque s'applique aux pages intérieures
  $("#f-mention").textContent = h.mention || ""; $("#f-mention").hidden = !h.mention;
  const titre = h.titre || t("Rapport de vulnérabilités");
  if (ten) {                                                  // thème Tenable : dernier mot surligné (bande Hilighter, texte Soft Black)
    const i = titre.lastIndexOf(" ") + 1;
    $("#f-titre").innerHTML = `${esc(titre.slice(0, i))}<mark>${esc(titre.slice(i))}</mark>`;
  } else $("#f-titre").textContent = titre;
  const m = etat.modeles.find((x) => x.id === etat.modele);
  $("#f-sous").textContent = h.sous_titre || (m ? m.nom : "");
  const meta = [];
  if (h.client) meta.push([t("Client"), h.client]);
  if (etat.modele === "comparaison") {
    meta.push([t("Export précédent"), etat.export1 ? etat.export1.nom : t("à charger")]);
    meta.push([t("Export récent"), etat.export2 ? etat.export2.nom : t("à charger")]);
  } else {
    meta.push([t("Source des données"), t(etat.source === "sc" && produit() === "vm" ? "Export Tenable Vulnerability Management" : "Export Tenable Security Center")]);
    const a = etat.apercu;
    const vol = a ? `${tp(a.machines, "machine", "machines")}, ${tp(a.vulnerabilites, "vulnérabilité", "vulnérabilités")}` : t("charger un export");
    const cible = libellePortee(a && a.portee ? a.portee : (etat.source === "sc" ? porteeCourante() : null));
    if (cible) { meta.push([t("Périmètre"), cible]); meta.push([t("Volumétrie"), vol]); }
    else meta.push([t("Périmètre"), vol]);
  }
  meta.push([t("Date d'édition"), dateFr()]);
  $("#f-meta").innerHTML = meta.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  afficherPage(etat.pagesVisibles ? etat.pageApercu || 1 : 1);
}
function afficherPage(n) {
  etat.pageApercu = n;
  $("#pages-apercu").hidden = !etat.pagesVisibles;
  ["#feuille", "#feuille-p2", "#feuille-p3"].forEach((sel, i) => ($(sel).hidden = i + 1 !== n));
  $$("#pages-apercu button").forEach((b) => b.setAttribute("aria-selected", String(Number(b.dataset.page) === n)));
  $("#epreuve-note").textContent = n === 1 ? t("Couverture du rapport, telle qu'elle sera imprimée.")
    : t("Page intérieure fictive, pour juger de l'en-tête, du pied de page et du filigrane.");
}
$("#pages-apercu").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) afficherPage(Number(b.dataset.page)); });

/* pages fictives : donnent le rendu d'une page intérieure (en-tête, pied, filigrane) sans export chargé */
function pagesFictives(h, p, fil, taille) {
  const m = etat.modeles.find((x) => x.id === etat.modele);
  const entete = [h.titre || t("Rapport de vulnérabilités"), m ? m.nom : ""].filter(Boolean).join(" · ");
  const logo = h.logo ? `<img class="fc-logo" src="${$("#f-logo").src}" alt="">`
    : themeActif() === "tenable" ? `<img class="fc-logo logo-tenable" src="/polices/tenable-logo-noir.svg" alt="tenable">` : "";
  const badge = !!(h.mention_interieur && h.mention);           // même règle que dans le PDF : badge en en-tête, plus de mention en pied
  const pied = (badge ? [h.pied] : [h.mention, h.pied]).filter(Boolean).join(" · ");
  const cadre = (n, corps) => `<span class="f-filigrane" aria-hidden="true"${fil ? "" : " hidden"} style="font-size:${taille}">${esc(fil)}</span>
    <div class="fc-entete">${badge ? `<span class="fc-badge">${esc(h.mention)}</span>` : ""}${logo}<div class="fc-droite"${badge ? ' style="margin-top:3cqw"' : ""}>${esc(entete)}<br>${esc(h.client || "")}</div></div>
    <div class="fc-corps">${corps}</div>
    <div class="fc-pied"><span>${esc(pied)}</span><span>${t("Page {n} / 12", { n })}</span></div>`;
  const lignes = (...l) => l.map((w) => `<i class="fc-ligne" style="width:${w}%"></i>`).join("");
  const barres = [["Critique", 88, "--critique"], ["Élevée", 70, "--elevee"], ["Moyenne", 52, "--moyenne"], ["Faible", 30, "--faible"]]
    .map(([l, w, c]) => `<div class="fc-barre"><span>${t(l)}</span><i style="width:${w}%;background:var(${c})"></i></div>`).join("");
  $("#feuille-p2").innerHTML = cadre(2, `<h4>${t("1. Synthèse")}</h4>${lignes(100, 97, 64)}
    <div class="fc-kpis"><div><b>126</b>${t("machines")}</div><div><b>842</b>${t("vulnérabilités")}</div><div><b>61</b>${t("critiques")}</div><div><b>54</b>${t("élevées")}</div></div>
    <h5>${t("Points clés")}</h5>${lignes(92, 80, 86)}<h5>${t("Vulnérabilités par sévérité")}</h5>${barres}`);
  const act = [["Mettre à jour Google Chrome", "Critical"], ["Installer les correctifs Windows", "Critical"], ["Mettre à jour Oracle Java SE", "High"],
               ["Désactiver TLS 1.0 et 1.1", "High"], ["Mettre à jour OpenSSH", "Medium"], ["Remplacer le certificat expiré", "Medium"], ["Désactiver SMBv1", "Low"]];
  const sev = { Critical: ["Critique", "--critique"], High: ["Élevée", "--elevee"], Medium: ["Moyenne", "--moyenne"], Low: ["Faible", "--faible"] };
  $("#feuille-p3").innerHTML = cadre(3, `<h4>${t("2. Plan d'action")}</h4>
    <div class="fc-table"><div class="fc-th"><span>${t("N°")}</span><span>${t("Action")}</span><span>${t("Sévérité")}</span><span>${t("Machines")}</span></div>${
      act.map(([txt, s], i) => `<div><span>${i + 1}</span><span>${t(txt)}</span><span><u style="background:var(${sev[s][1]})">${t(sev[s][0])}</u></span><span>${40 - i * 5}</span></div>`).join("")}</div>
    ${lignes(96, 70)}`);
}

/* ------------------------------------------------------------------ exemples de rapports (données fictives) */
const ex = { donnees: null, i: 0, declencheur: null };
async function ouvrirExemple(id, declencheur) {
  const dlg = $("#exemple"), m = etat.modeles.find((x) => x.id === id);
  ex.donnees = null; ex.i = 0; ex.declencheur = declencheur || null; $("#ex-cadre").classList.remove("zoom");
  $("#ex-titre").textContent = m ? m.nom : "";
  $("#ex-sous").textContent = "";
  $("#ex-vignettes").innerHTML = ""; $("#ex-legende").textContent = ""; $("#ex-pos").textContent = "";
  $("#ex-ouvrir").hidden = true; $("#ex-prec").disabled = $("#ex-suiv").disabled = true;
  $("#ex-cadre").innerHTML = `<p class="ex-attente">${t("Génération de l'exemple…")}</p>`;
  if (!dlg.open) dlg.showModal();
  try {
    ex.donnees = await api("GET", `/api/modeles/${id}/exemple?profil=${encodeURIComponent(etat.profil.id)}`);
  } catch (err) { dlg.close(); toast(err.message, true); return; }
  const d = ex.donnees;
  $("#ex-sous").textContent = t("Exemple avec des données fictives, habillage du profil « {profil} »", { profil: d.profil });
  $("#ex-ouvrir").href = d.fichier; $("#ex-ouvrir").hidden = false;
  $("#ex-ouvrir").textContent = d.format === "xlsx" ? t("Ouvrir le classeur d'exemple") : t("Ouvrir le PDF d'exemple");
  const elements = d.feuilles || d.pages || [];
  if (d.feuilles) $("#ex-vignettes").innerHTML = d.feuilles.map((f, i) =>
    `<button type="button" class="ex-feuille" data-i="${i}" data-i18n="non">${esc(f.nom)}</button>`).join("");
  else if (d.pages) $("#ex-vignettes").innerHTML = d.pages.map((p, i) =>
    `<button type="button" class="ex-vignette" data-i="${i}" aria-label="${esc(t("Page {n}", { n: p.n }))}"><img loading="lazy" src="${p.url}" alt=""><span data-i18n="non">${p.n}</span></button>`).join("");
  if (d.sans_images) $("#ex-cadre").innerHTML = `<p class="ex-attente">${esc(d.sans_images)}</p>`;
  else afficherExemple(0);
}
function afficherExemple(i) {
  const d = ex.donnees; if (!d) return;
  const elements = d.feuilles || d.pages || []; if (!elements.length) return;
  ex.i = Math.max(0, Math.min(i, elements.length - 1));
  const e = elements[ex.i];
  if (d.feuilles) $("#ex-cadre").innerHTML = `<div class="ex-xl" data-i18n="non">${e.html}</div>`;
  else $("#ex-cadre").innerHTML = `<img class="ex-page" title="${esc(t("Cliquer pour agrandir ou réduire"))}" src="${e.url}?dpi=130" alt="${esc(t("Page {n}", { n: e.n }))}">`;
  $("#ex-legende").textContent = d.feuilles ? t("Feuille « {nom} »", { nom: e.nom }) : ((e.titre ? `${t("Page {n}", { n: e.n })} · ${e.titre}` : t("Page {n}", { n: e.n })) + " · " + t("Cliquer pour agrandir ou réduire"));
  $("#ex-pos").textContent = t("{n} / {total}", { n: ex.i + 1, total: elements.length });
  $("#ex-prec").disabled = ex.i === 0; $("#ex-suiv").disabled = ex.i === elements.length - 1;
  $$("#ex-vignettes > button").forEach((b, k) => b.setAttribute("aria-current", String(k === ex.i)));
  const cur = $(`#ex-vignettes > button[data-i="${ex.i}"]`); if (cur) cur.scrollIntoView({ block: "nearest" });
  $("#ex-cadre").scrollTop = 0;
}
$("#ex-cadre").addEventListener("click", (e) => { if (e.target.closest(".ex-page")) { $("#ex-cadre").classList.toggle("zoom"); $("#ex-cadre").scrollTop = 0; } });
$("#ex-vignettes").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) afficherExemple(+b.dataset.i); });
$("#ex-prec").addEventListener("click", () => afficherExemple(ex.i - 1));
$("#ex-suiv").addEventListener("click", () => afficherExemple(ex.i + 1));
$("#ex-fermer").addEventListener("click", () => $("#exemple").close());
$("#exemple").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });      // clic sur le fond
$("#exemple").addEventListener("close", () => { if (ex.declencheur) ex.declencheur.focus(); });
$("#exemple").addEventListener("keydown", (e) => {
  if (e.key === "ArrowRight" || e.key === "PageDown") { e.preventDefault(); afficherExemple(ex.i + 1); }
  else if (e.key === "ArrowLeft" || e.key === "PageUp") { e.preventDefault(); afficherExemple(ex.i - 1); }
  else if (e.key === "Home") { e.preventDefault(); afficherExemple(0); }
});

/* ------------------------------------------------------------------ profils */
async function chargerModeles() { etat.modeles = await api("GET", "/api/modeles"); }      // noms et descriptions traduits par le serveur
async function chargerProfils(choisir) {
  etat.profils = await api("GET", "/api/profils");
  const sel = $("#profil-select");
  sel.innerHTML = etat.profils.map((p) => `<option value="${esc(p.id)}">${esc(p.nom)}</option>`).join("");
  let id = choisir || localStorage.getItem("profil");
  if (!etat.profils.some((p) => p.id === id)) id = etat.profils[0].id;
  sel.value = id;
  await choisirProfil(id);
}
async function choisirProfil(id) {
  etat.profil = await api("GET", `/api/profils/${id}`);
  if (etat.profil.langue !== I18N.code) { await appliquerLangue(etat.profil.langue); await chargerModeles(); majPlaceholders(); }      // la langue est celle du profil
  try { localStorage.setItem("profil", id); } catch { /* stockage indisponible */ }
  if (etat.profil.modele) etat.modele = etat.profil.modele;
  majSuggestions(); remplirHabillage(); remplirPerimetre(); remplirSource(); remplirMail(); afficherModeles(); epreuve();
  if (etat.export1) rafraichirApercu();
}
$("#profil-select").addEventListener("change", (e) => choisirProfil(e.target.value));

/* Sélecteur de langue : la langue de l'interface est celle du profil actif, et celle de ses rapports. */
initSelecteurLangue(async (code) => {
  try {
    if (etat.profil) {
      etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { langue: code });
      await appliquerLangue(code); await chargerModeles();
      remplirHabillage(); remplirMail(); afficherModeles(); majPlaceholders(); majRequeteJson(); chargerRapports();
      if (etat.export1) rafraichirApercu();
      etat.regles = []; if (!$("#p-regles").hidden) chargerRegles();
      toast(t("Langue : {nom}.", { nom: LANGUES.find((l) => l.code === code).nom }));
    } else await appliquerLangue(code);
  } catch (err) { toast(err.message, true); }
});

const menu = $("#profil-menu"), menuBtn = $("#profil-menu-btn");
menuBtn.addEventListener("click", () => { menu.hidden = !menu.hidden; menuBtn.setAttribute("aria-expanded", String(!menu.hidden)); });
document.addEventListener("click", (e) => { if (!e.target.closest(".profil-choix")) { menu.hidden = true; menuBtn.setAttribute("aria-expanded", "false"); } });
menu.addEventListener("click", async (e) => {
  const action = e.target.dataset.action; if (!action) return;
  menu.hidden = true;
  const p = etat.profil;
  try {
    if (action === "nouveau") {
      const nom = prompt(t("Nom du nouveau profil (par exemple le nom du client) :")); if (!nom) return;
      const n = await api("POST", "/api/profils", { nom }); await chargerProfils(n.id); toast(t("Profil « {nom} » créé.", { nom: n.nom }));
    } else if (action === "dupliquer") {
      const nom = prompt(t("Nom du profil copié :"), p.nom + t(" (copie)")); if (!nom) return;
      const n = await api("POST", "/api/profils", { nom, copier: p.id }); await chargerProfils(n.id); toast(t("Profil « {nom} » créé.", { nom: n.nom }));
    } else if (action === "renommer") {
      const nom = prompt(t("Nouveau nom du profil :"), p.nom); if (!nom) return;
      await api("PUT", `/api/profils/${p.id}`, { nom }); await chargerProfils(p.id); toast(t("Profil renommé."));
    } else if (action === "supprimer") {
      if (!confirm(t("Supprimer le profil « {nom} » ? Son habillage et son périmètre seront perdus.", { nom: p.nom }))) return;
      await api("DELETE", `/api/profils/${p.id}`); await chargerProfils(); toast(t("Profil supprimé."));
    }
  } catch (err) { toast(err.message, true); }
});

/* ------------------------------------------------------------------ habillage */
const CHAMPS_H = ["titre", "sous_titre", "client", "mention", "filigrane", "pied"];
function remplirHabillage() {
  const h = etat.profil.habillage;
  CHAMPS_H.forEach((k) => ($("#h-" + k).value = h[k] || ""));
  $("#h-couleur").value = h.couleur || "#000091";
  $("#h-couverture").value = h.couverture === "sombre" ? "sombre" : "claire";
  $("#h-filigrane-couv").checked = h.filigrane_couverture !== false;
  $("#h-mention-int").checked = !!h.mention_interieur;
  majPastilles();
  $("#btn-logo-retirer").hidden = !h.logo;
  $("#btn-logo").textContent = h.logo ? t("Remplacer le logo") : t("Choisir un logo");
  statut("#statut-habillage", "");
}
function majPastilles() {
  const c = (etat.profil.habillage.couleur || "").toLowerCase();
  $$(".pastille-c").forEach((b) => { b.style.background = b.dataset.c; b.setAttribute("aria-pressed", String(b.dataset.c.toLowerCase() === c)); });
}
function habillageModifie() { statut("#statut-habillage", t("Modifications non enregistrées")); epreuve(); }
CHAMPS_H.forEach((k) => $("#h-" + k).addEventListener("input", (e) => { etat.profil.habillage[k] = e.target.value; habillageModifie(); }));
$("#h-mention-int").addEventListener("change", (e) => { etat.profil.habillage.mention_interieur = e.target.checked; habillageModifie(); });
$("#h-filigrane-couv").addEventListener("change", (e) => {
  etat.profil.habillage.filigrane_couverture = e.target.checked; habillageModifie();
});
$("#h-couverture").addEventListener("change", (e) => { etat.profil.habillage.couverture = e.target.value; habillageModifie(); });
$("#h-couleur").addEventListener("input", (e) => { etat.profil.habillage.couleur = e.target.value.toUpperCase(); majPastilles(); habillageModifie(); });
$("#couleurs").addEventListener("click", (e) => {
  const b = e.target.closest(".pastille-c"); if (!b) return;
  etat.profil.habillage.couleur = b.dataset.c; $("#h-couleur").value = b.dataset.c; majPastilles(); habillageModifie();
});
$("#form-habillage").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const h = { ...etat.profil.habillage }; delete h.logo;
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { habillage: h });
    statut("#statut-habillage", t("Habillage enregistré"), "ok"); chargerListeProfilsSeule();
  } catch (err) { statut("#statut-habillage", err.message, "ko"); }
});
$("#btn-logo").addEventListener("click", () => $("#fichier-logo").click());
$("#fichier-logo").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const fd = new FormData(); fd.append("fichier", f);
  try {
    const garde = { ...etat.profil.habillage };
    etat.profil = await api("POST", `/api/profils/${etat.profil.id}/logo`, fd);
    etat.profil._v = Date.now();
    Object.assign(etat.profil.habillage, { ...garde, logo: etat.profil.habillage.logo });
    remplirHabillage(); epreuve(); toast(t("Logo enregistré."));
  } catch (err) { toast(err.message, true); }
  e.target.value = "";
});
$("#btn-logo-retirer").addEventListener("click", async () => {
  try {
    const garde = { ...etat.profil.habillage };
    etat.profil = await api("DELETE", `/api/profils/${etat.profil.id}/logo`);
    Object.assign(etat.profil.habillage, { ...garde, logo: null });
    remplirHabillage(); epreuve(); toast(t("Logo retiré."));
  } catch (err) { toast(err.message, true); }
});
async function chargerListeProfilsSeule() {
  etat.profils = await api("GET", "/api/profils");
  const sel = $("#profil-select"), id = etat.profil.id;
  sel.innerHTML = etat.profils.map((p) => `<option value="${esc(p.id)}">${esc(p.nom)}</option>`).join("");
  sel.value = id;
}

/* ------------------------------------------------------------------ périmètre */
function remplirPerimetre() {
  const p = etat.profil.perimetre;
  $$("#sev-choix input").forEach((c) => (c.checked = p.severites.includes(c.value)));
  $("#p-top").value = p.top; $("#p-ponderation").value = ["vpr", "vpr_acr"].includes(p.ponderation) ? p.ponderation : "severite"; majNotePonderation(); $("#p-inclure").value = p.inclure || ""; $("#p-exclure").value = p.exclure || "";
  statut("#statut-perimetre", "");
}
function majNotePonderation() {
  const m = $("#p-ponderation").value;
  $$("#note-ponderation tbody tr").forEach((tr) => tr.classList.toggle("actif", tr.dataset.mode === m));
}
$("#p-ponderation").addEventListener("change", majNotePonderation);
$("#form-perimetre").addEventListener("input", () => statut("#statut-perimetre", t("Modifications non enregistrées")));
$("#form-perimetre").addEventListener("submit", async (e) => {
  e.preventDefault();
  const per = {
    severites: $$("#sev-choix input").filter((c) => c.checked).map((c) => c.value),
    top: Number($("#p-top").value), ponderation: $("#p-ponderation").value, inclure: $("#p-inclure").value, exclure: $("#p-exclure").value,
  };
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { perimetre: per });
    statut("#statut-perimetre", etat.export1 ? t("Périmètre enregistré, aperçu mis à jour") : t("Périmètre enregistré"), "ok");
    if (etat.export1) rafraichirApercu();
  } catch (err) { statut("#statut-perimetre", err.message, "ko"); }
});

/* ------------------------------------------------------------------ modèles */
function afficherModeles() {
  $("#modeles").innerHTML = etat.modeles.map((m) => `
    <div class="modele-ligne">
      <button type="button" class="modele" role="radio" aria-checked="${m.id === etat.modele}" data-id="${m.id}">
        <span class="modele-radio" aria-hidden="true"></span>
        <span class="modele-nom">${esc(m.nom)}</span>
        <span class="modele-format">${m.format === "xlsx" ? "Excel" : "PDF"}</span>
        <span class="modele-desc">${esc(m.description)}</span>
      </button>
      <button type="button" class="modele-exemple" data-exemple="${m.id}">${t("Voir un exemple")}</button>
    </div>`).join("");
  const m = etat.modeles.find((x) => x.id === etat.modele);
  $("#depot2").hidden = !(m && m.exports === 2);
  majSource();
  $("#depot1-texte").textContent = etat.export1 ? `${etat.export1.nom} (${taille(etat.export1.taille)})`
    : (m && m.exports === 2 ? t("Export précédent : déposez le fichier ici ou cliquez pour le choisir") : t("Déposez le fichier ici ou cliquez pour le choisir"));
  majBoutonGenerer(); epreuve();
}
$("#modeles").addEventListener("click", async (e) => {
  const ex = e.target.closest(".modele-exemple"); if (ex) { ouvrirExemple(ex.dataset.exemple, ex); return; }
  const b = e.target.closest(".modele"); if (!b) return;
  etat.modele = b.dataset.id; afficherModeles();
  try { await api("PUT", `/api/profils/${etat.profil.id}`, { modele: etat.modele }); } catch { /* préférence non critique */ }
});
$("#modeles").addEventListener("keydown", (e) => {
  if (!["ArrowDown", "ArrowUp"].includes(e.key)) return;
  e.preventDefault();
  const ids = etat.modeles.map((m) => m.id), i = ids.indexOf(etat.modele);
  etat.modele = ids[(i + (e.key === "ArrowDown" ? 1 : ids.length - 1)) % ids.length];
  afficherModeles(); $(`.modele[data-id="${etat.modele}"]`).focus();
});
function majBoutonGenerer() {
  const m = etat.modeles.find((x) => x.id === etat.modele);
  const pret = etat.export1 && (!m || m.exports === 1 || etat.export2);
  $("#btn-generer").disabled = !pret;
  $("#btn-generer-envoyer").disabled = !pret;
  $("#btn-generer-envoyer").hidden = !smtpConfigure();
  $("#btn-generer-envoyer").textContent = m && m.format === "xlsx" ? t("Générer et envoyer le fichier Excel") : t("Générer et envoyer par courriel");
  $("#btn-generer").textContent = m && m.format === "xlsx" ? t("Générer le fichier Excel") : t("Générer le rapport");
}

/* ------------------------------------------------------------------ exports */
function brancherDepot(zone, input, quand) {
  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("survol"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("survol"));
  zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("survol"); if (e.dataTransfer.files[0]) quand(e.dataTransfer.files[0]); });
  input.addEventListener("change", () => { if (input.files[0]) quand(input.files[0]); input.value = ""; });
}
async function envoyerExport(f, zone, texte) {
  const fd = new FormData(); fd.append("fichier", f);
  zone.classList.remove("charge"); texte.textContent = t("Lecture de {nom}…", { nom: f.name });
  try {
    const e = await api("POST", "/api/exports", fd);
    zone.classList.add("charge"); texte.textContent = `${e.nom} (${taille(e.taille)})`;
    return e;
  } catch (err) { texte.textContent = t("Déposez le fichier ici ou cliquez pour le choisir"); toast(err.message, true); return null; }
}
brancherDepot($("#depot1"), $("#fichier1"), async (f) => {
  const e = await envoyerExport(f, $("#depot1"), $("#depot1-texte"));
  if (e) { etat.export1 = e; await rafraichirApercu(); }
  majBoutonGenerer();
});
brancherDepot($("#depot2"), $("#fichier2"), async (f) => {
  const e = await envoyerExport(f, $("#depot2"), $("#depot2-texte"));
  if (e) etat.export2 = e;
  majBoutonGenerer(); epreuve();
});

async function rafraichirApercu() {
  const zone = $("#apercu");
  try {
    const a = await api("GET", `/api/exports/${etat.export1.id}/apercu?profil=${etat.profil.id}`);
    etat.apercu = a;
    const tot = Object.values(a.par_severite).reduce((x, y) => x + y, 0) || 1;
    const cov = a.couverture, sansRegle = cov.plugins - cov.avec_regle;
    zone.innerHTML = `
      <div class="apercu-chiffres">
        <div><b>${a.machines}</b><span>${t("machines dans le périmètre")}</span></div>
        <div><b>${a.vulnerabilites}</b><span>${t("vulnérabilités")}</span></div>
        <div><b>${a.solutions}</b><span>${t("solutions à mener")}</span></div>
      </div>
      <div class="sevbar" role="img" aria-label="${t("Répartition par sévérité")}">
        ${SEV.map(([k, , v]) => a.par_severite[k] ? `<i style="width:${100 * a.par_severite[k] / tot}%;background:var(${v})"></i>` : "").join("")}
      </div>
      <div class="sev-legende">${SEV.map(([k, fr, v]) => `<span style="--c:var(${v})">${t(fr)} ${a.par_severite[k] || 0}</span>`).join("")}</div>
      <p class="apercu-note">${a.machines_exclues ? `${pluriel(a.machines_exclues, "machine exclue", "machines exclues")} ${t("par le périmètre.")} ` : ""}
        ${a.info_ignorees ? `${t("{n} constats Info ignorés.", { n: a.info_ignorees })} ` : ""}
        ${sansRegle ? `${pluriel(sansRegle, "vulnérabilité", "vulnérabilités")} ${t("sans règle dédiée :")} <a href="#" id="voir-sans-regle">${t("les voir dans l'onglet Règles")}</a>.`
                    : t("Toutes les vulnérabilités sont couvertes par une règle.")}</p>
      ${a.ponderation && a.ponderation.mode !== "severite" ? `<p class="apercu-note">${a.ponderation.mode === "vpr"
        ? t("Pondération par VPR : {vpr} % des constats ont un VPR.", { vpr: a.ponderation.vpr })
        : t("Pondération par VPR et ACR : {vpr} % des constats ont un VPR, {acr} % ont un ACR.", { vpr: a.ponderation.vpr, acr: a.ponderation.acr })}</p>` : ""}
      <ol class="apercu-top">${a.top.slice(0, 5).map((s) => `<li><span>${esc(s.titre)}</span><em>${s.pct.toFixed(1)} %</em></li>`).join("")}</ol>`;
    zone.hidden = false;
    const lien = $("#voir-sans-regle");
    if (lien) lien.addEventListener("click", (e) => { e.preventDefault(); $('.onglets [data-onglet="regles"]').click(); remplirSansRegle(); });
    $("#btn-sans-regle").hidden = !a.sans_regle.length;
  } catch (err) { zone.hidden = false; zone.innerHTML = `<p class="statut ko">${esc(err.message)}</p>`; etat.apercu = null; }
  epreuve();
}

/* ------------------------------------------------------------------ génération */
async function generer(envoyer) {
  const boutons = [$("#btn-generer"), $("#btn-generer-envoyer")]; boutons.forEach((x) => (x.disabled = true));
  statut("#statut-generer", envoyer ? t("Génération puis envoi en cours…") : t("Génération en cours…"));
  try {
    const r = await api("POST", "/api/generer", {
      modele: etat.modele, profil: etat.profil.id, export: etat.export1 && etat.export1.id, export2: etat.export2 && etat.export2.id,
      envoyer,
    });
    const s = $("#statut-generer");
    s.className = "statut ok";
    s.innerHTML = t("Généré : {modele}.", { modele: esc(r.modele) }) + " " + (r.fichier.endsWith(".xlsx")
      ? `<a href="${r.url}?telecharger=1">${t("Télécharger le fichier Excel")}</a>`
      : `<a href="${r.url}" target="_blank" rel="noopener">${t("Ouvrir le rapport")}</a>`);
    if (r.mail) {
      if (r.mail.ok) s.innerHTML += " " + t("Envoyé à {liste}.", { liste: esc(r.mail.destinataires.join(", ")) });
      else { s.className = "statut ko"; s.innerHTML += " " + t("Mais l'envoi a échoué : {erreur}", { erreur: esc(r.mail.erreur) }) + ` <a href="#" data-envoyer="${esc(r.fichier)}">${t("Réessayer")}</a>`; }
    }
    if (r.avertissement) s.innerHTML += " " + esc(r.avertissement);
    etat.nouveaux.add(r.fichier); await chargerRapports();
  } catch (err) { statut("#statut-generer", err.message, "ko"); }
  majBoutonGenerer();
}
$("#btn-generer").addEventListener("click", () => generer(false));
$("#btn-generer-envoyer").addEventListener("click", () => {
  const m = (etat.profil.mail || {}).destinataires || "";
  if (!smtpConfigure()) return statut("#statut-generer", t("Serveur SMTP non configuré : onglet Configuration, section Courriel."), "ko");
  if (!m.trim()) return statut("#statut-generer", t("Aucun destinataire par défaut pour ce profil : onglet Configuration, section Courriel."), "ko");
  generer(true);
});
document.addEventListener("click", (e) => {                       // « Réessayer » après un envoi échoué
  const a = e.target.closest("#statut-generer [data-envoyer]"); if (!a) return;
  e.preventDefault(); ouvrirEnvoi(a.dataset.envoyer); $("#envoi").scrollIntoView({ block: "center", behavior: "smooth" });
});
async function chargerRapports() {
  const d = await api("GET", "/api/rapports");
  $("#dossier-rapports").textContent = t("Enregistrés sur ce poste dans {dossier}", { dossier: d.dossier });
  const ul = $("#liste-rapports");
  if (!d.rapports.length) { ul.innerHTML = `<li class="vide">${t("Aucun rapport pour l'instant. Chargez un export pour commencer.")}</li>`; return; }
  ul.innerHTML = d.rapports.map((r) => {
    const excel = r.fichier.endsWith(".xlsx");
    return `<li class="${etat.nouveaux.has(r.fichier) ? "nouveau" : ""}">
      <span class="nom">${esc(r.fichier)}<small>${r.date}, ${taille(r.taille)}</small></span>
      ${excel ? "<span></span>" : `<a href="${r.url}" target="_blank" rel="noopener">${t("Ouvrir")}</a>`}
      <a href="${r.url}?telecharger=1">${t("Télécharger")}</a>
      <a href="#" data-envoyer="${esc(r.fichier)}">${t("Envoyer")}</a></li>`;
  }).join("");
}


/* ------------------------------------------------------------------ configuration (Security Center, SMTP) */
async function chargerConfig() {
  etat.config = await api("GET", "/api/config");
  remplirConnexion(); remplirSmtp(); majSource(); majBoutonGenerer();
}
const smtpConfigure = () => !!(etat.config && etat.config.smtp.hote);
/* produit Tenable du profil : « sc » (Security Center) ou « vm » (Vulnerability Management) */
const produit = () => (etat.profil && etat.profil.source && etat.profil.source.produit === "vm" ? "vm" : "sc");
const NOM_PRODUIT = { sc: "Security Center", vm: "Vulnerability Management" };
const scConfigure = () => {
  const c = etat.config && etat.config[produit() === "vm" ? "vulnmanagement" : "securitycenter"];
  return !!(c && (produit() === "vm" || c.url) && c.access_key && (c.secret_key_defini || c.secret_key));
};

function majSuggestions() {                      // listes de suggestions (mention, filigrane) dans la langue courante
  const liste = (id, mots) => { $("#" + id).innerHTML = mots.map((m) => `<option value="${esc(t(m))}"></option>`).join(""); };
  liste("mentions", ["Diffusion restreinte", "Confidentiel", "Usage interne", "Document de travail"]);
  liste("filigranes", ["Diffusion restreinte", "Confidentiel", "Projet", "Brouillon"]);
}
function majPlaceholders() {
  majSuggestions();                              // placeholders fixés par le code : à refaire à chaque changement de langue
  if (!etat.config) return;
  $("#sc-secret").placeholder = etat.config.securitycenter.secret_key_defini ? t("Enregistrée (laisser vide pour la conserver)") : "";
  $("#vm-secret").placeholder = etat.config.vulnmanagement.secret_key_defini ? t("Enregistrée (laisser vide pour la conserver)") : "";
  $("#m-pass").placeholder = etat.config.smtp.mot_de_passe_defini ? t("Enregistré (laisser vide pour le conserver)") : "";
}
function remplirConnexion() {
  const c = etat.config.securitycenter;
  $("#sc-url").value = c.url; $("#sc-access").value = c.access_key; $("#sc-secret").value = "";
  majPlaceholders();
  $("#sc-ca").value = c.ca_bundle; $("#sc-tls").checked = c.verifier_tls;
  statut("#statut-sc-connexion", "");
  const v = etat.config.vulnmanagement;
  $("#vm-url").value = v.url; $("#vm-access").value = v.access_key; $("#vm-secret").value = "";
  $("#vm-ca").value = v.ca_bundle; $("#vm-tls").checked = v.verifier_tls;
  statut("#statut-vm-connexion", "");
}
function lireConnexion() {
  return { url: $("#sc-url").value.trim(), access_key: $("#sc-access").value.trim(), secret_key: $("#sc-secret").value,
           ca_bundle: $("#sc-ca").value.trim(), verifier_tls: $("#sc-tls").checked };
}
$("#form-sc-connexion").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.config = await api("PUT", "/api/config", { securitycenter: lireConnexion() });
    remplirConnexion(); majSource(); statut("#statut-sc-connexion", t("Connexion enregistrée"), "ok");
  } catch (err) { statut("#statut-sc-connexion", err.message, "ko"); }
});
$("#btn-sc-tester").addEventListener("click", async () => {
  statut("#statut-sc-connexion", t("Test en cours…"));
  try {
    const r = await api("POST", "/api/securitycenter/tester", { securitycenter: lireConnexion() });
    statut("#statut-sc-connexion", t("Connexion réussie{version}, {depots}.", {
      version: r.version ? ` (Security Center ${r.version})` : "", depots: tp(r.repositories, "dépôt accessible", "dépôts accessibles") }), "ok");
  } catch (err) { statut("#statut-sc-connexion", err.message, "ko"); }
});

/* Vulnerability Management : connexion */
function lireConnexionVm() {
  return { url: $("#vm-url").value.trim(), access_key: $("#vm-access").value.trim(), secret_key: $("#vm-secret").value,
           ca_bundle: $("#vm-ca").value.trim(), verifier_tls: $("#vm-tls").checked };
}
$("#form-vm-connexion").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.config = await api("PUT", "/api/config", { vulnmanagement: lireConnexionVm() });
    remplirConnexion(); majSource(); statut("#statut-vm-connexion", t("Connexion enregistrée"), "ok");
  } catch (err) { statut("#statut-vm-connexion", err.message, "ko"); }
});
$("#btn-vm-tester").addEventListener("click", async () => {
  statut("#statut-vm-connexion", t("Test en cours…"));
  try {
    const r = await api("POST", "/api/vm/tester", { vulnmanagement: lireConnexionVm() });
    statut("#statut-vm-connexion", t("Connexion réussie{utilisateur}.", { utilisateur: r.utilisateur ? ` (${r.utilisateur})` : "" }), "ok");
  } catch (err) { statut("#statut-vm-connexion", err.message, "ko"); }
});

/* choix du produit (réglage du profil) */
function majProduit() {
  const p = produit();
  $("#produit").value = p; $("#cfg-sc").hidden = p !== "sc"; $("#cfg-vm").hidden = p !== "vm";
}
$("#produit").addEventListener("change", async () => {
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { source: { produit: $("#produit").value } });
    majProduit(); majSource(); majBoutonGenerer(); statut("#statut-produit", t("Produit enregistré"), "ok");
  } catch (err) { statut("#statut-produit", err.message, "ko"); majProduit(); }
});

/* requête d'export Vulnerability Management (profil) */
function remplirSourceVm() {
  const s = etat.profil.source || {};
  $("#vm-cidr").value = s.cidr || ""; $("#vm-acr").checked = (s.acr_aes || "1") === "1"; $("#vm-periode").value = s.periode || "30";
  statut("#statut-vm-requete", "");
}
$("#form-vm-requete").addEventListener("input", () => statut("#statut-vm-requete", t("Modifications non enregistrées")));
$("#form-vm-requete").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { source: { cidr: $("#vm-cidr").value, acr_aes: $("#vm-acr").checked ? "1" : "0", periode: $("#vm-periode").value } });
    etat.scope = selectionProfil();
    statut("#statut-vm-requete", t("Requête enregistrée"), "ok"); majRequeteJson(); majSource();
  } catch (err) { statut("#statut-vm-requete", err.message, "ko"); }
});

/* requête d'export (profil) */
const CHAMPS_SRC = { repositories: "#q-repos", asset_list: "#q-asset", query_id: "#q-query", source_type: "#q-type", outil: "#q-outil", filtres: "#q-filtres" };
function remplirSource() {
  const s = etat.profil.source || {};
  Object.entries(CHAMPS_SRC).forEach(([k, sel]) => ($(sel).value = s[k] || ""));
  ["#chips-repos", "#chips-asset", "#chips-query"].forEach((c) => ($(c).innerHTML = ""));
  statut("#statut-sc-requete", ""); remplirSourceVm(); majProduit(); etat.scope = selectionProfil(); majSource();
}
function lireSource() {
  const o = Object.fromEntries(Object.entries(CHAMPS_SRC).map(([k, sel]) => [k, $(sel).value]));
  const connus = { ...Object.fromEntries(selectionProfil().listes.map((x) => [x.id, x.nom])), ...(etat.nomsListes || {}) };
  const ids = o.asset_list.split(/[,;\s]+/).filter(Boolean).filter((i) => connus[i]);       // noms conservés pour la couverture
  o.asset_noms = ids.length ? JSON.stringify(Object.fromEntries(ids.map((i) => [i, connus[i]]))) : "";
  return o;
}
$("#form-sc-requete").addEventListener("input", () => statut("#statut-sc-requete", t("Modifications non enregistrées")));
$("#form-sc-requete").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { source: lireSource() });
    etat.scope = selectionProfil();
    statut("#statut-sc-requete", t("Requête enregistrée"), "ok"); majRequeteJson(); majSource();
  } catch (err) { statut("#statut-sc-requete", err.message, "ko"); }
});
async function majRequeteJson() {
  if (produit() === "vm") {
    try {
      const r = await api("GET", `/api/vm/requete?profil=${etat.profil.id}`);
      $("#requete-vm-json").textContent = `POST ${etat.config && etat.config.vulnmanagement.url || "https://cloud.tenable.com"}/vulns/export\n` + JSON.stringify(r, null, 2);
    } catch { $("#requete-vm-json").textContent = t("Requête indisponible : vérifiez les filtres JSON."); }
    return;
  }
  try {
    const r = await api("GET", `/api/securitycenter/requete?profil=${etat.profil.id}`);
    $("#requete-json").textContent = `POST ${etat.config && etat.config.securitycenter.url || "https://<security-center>"}/rest/analysis\n` + JSON.stringify(r, null, 2);
  } catch { $("#requete-json").textContent = t("Requête indisponible : vérifiez les filtres JSON."); }
}
/* pastilles de choix : un clic ajoute ou retire l'identifiant (dépôts, listes d'actifs) ou le remplace (requête) */
function pastilles(cont, input, items, multiple) {
  const sel = () => $(input).value.split(/[,;\s]+/).filter(Boolean);
  const dessiner = () => {
    const actifs = sel();
    $(cont).innerHTML = items.length ? items.map((x) =>
      `<button type="button" class="chip" aria-pressed="${actifs.includes(x.id)}" data-id="${esc(x.id)}">${esc(x.nom)} <small>#${esc(x.id)}</small></button>`).join("")
      : `<span class="aide">${t("Aucun élément accessible avec ces clés.")}</span>`;
  };
  $(cont).onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    const id = b.dataset.id; let v = sel();
    v = multiple ? (v.includes(id) ? v.filter((x) => x !== id) : [...v, id]) : (v.includes(id) ? [] : [id]);
    $(input).value = v.join(", "); dessiner(); statut("#statut-sc-requete", t("Modifications non enregistrées"));
  };
  dessiner();
}
$("#btn-sc-listes").addEventListener("click", async () => {
  statut("#statut-sc-requete", t("Lecture des listes…"));
  try {
    const l = await api("GET", "/api/securitycenter/listes");
    pastilles("#chips-repos", "#q-repos", l.repositories, true);
    etat.nomsListes = Object.fromEntries(l.listes_actifs.map((x) => [x.id, x.nom]));
    pastilles("#chips-asset", "#q-asset", l.listes_actifs, true);
    pastilles("#chips-query", "#q-query", l.requetes, false);
    statut("#statut-sc-requete", "");
  } catch (err) { statut("#statut-sc-requete", err.message, "ko"); }
});

/* ------------------------------------------------------------------ périmètre : listes d'actifs (SC) ou tags (VM) */
/* sélection = { listes: [{id, nom}], tags: {catégorie: [valeurs]} } ; celle du profil est le défaut, etat.scope celle de la génération */
function selectionProfil() {
  const s = (etat.profil && etat.profil.source) || {};
  const json = (x) => { try { const v = JSON.parse(x || "{}"); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; } catch { return {}; } };
  const noms = json(s.asset_noms);
  const ids = String(s.asset_list || "").split(/[,;\s]+/).filter(Boolean);
  return { listes: ids.map((id) => ({ id, nom: noms[id] || `#${id}` })), tags: json(s.tags) };
}
function selectionVersSource(sel) {
  const noms = Object.fromEntries(sel.listes.map((x) => [x.id, x.nom]));
  return { asset_list: sel.listes.map((x) => x.id).join(", "), asset_noms: sel.listes.length ? JSON.stringify(noms) : "",
           tags: Object.keys(sel.tags).length ? JSON.stringify(sel.tags) : "" };
}
function porteeCourante() {
  const sel = etat.scope || { listes: [], tags: {} };
  if (produit() === "vm") return Object.keys(sel.tags).length ? { produit: "vm", listes: [], tags: sel.tags } : null;
  return sel.listes.length ? { produit: "sc", listes: sel.listes.map((x) => x.nom), tags: {} } : null;
}
function libellePortee(p) {                                          // même mise en forme que dans le rapport PDF
  if (!p) return "";
  if (p.listes && p.listes.length) return t("Listes d'actifs : {liste}", { liste: p.listes.join(", ") });
  const c = Object.entries(p.tags || {});
  return c.length ? t("Tags : {liste}", { liste: c.map(([k, v]) => `${k} = ${v.join(", ")}`).join(" ; ") }) : "";
}
function porteesDifferentes(a, b) {
  const cle = (p) => JSON.stringify(p ? [[...(p.listes || [])].sort(), Object.entries(p.tags || {}).map(([k, v]) => [k, [...v].sort()]).sort()] : [[], []]);
  return !!((a && a.portee) || (b && b.portee)) && cle(a && a.portee) !== cle(b && b.portee);
}
function majPortee() {
  const cible = libellePortee(porteeCourante());
  const memeQueProfil = JSON.stringify(selectionVersSource(etat.scope || { listes: [], tags: {} })) === JSON.stringify(selectionVersSource(selectionProfil()));
  $("#portee-resume").innerHTML = (cible ? esc(cible) : t("Toutes les machines accessibles avec ces clés"))
    + (memeQueProfil ? "" : ` <span class="ponctuel">(${t("pour cette génération seulement")})</span>`);
  $("#btn-portee").textContent = cible ? t("Modifier le périmètre") : t("Choisir le périmètre");
  if (etat.profil) epreuve();
}

const PT = { brouillon: null, donnees: null, minuteur: 0, seq: 0 };
async function ouvrirPortee() {
  const vm = produit() === "vm";
  PT.brouillon = JSON.parse(JSON.stringify(etat.scope || { listes: [], tags: {} }));
  $("#pt-aide").textContent = vm
    ? t("Cochez les valeurs de tags à inclure. Plusieurs valeurs d'une même catégorie s'additionnent (l'une OU l'autre) ; des catégories différentes se cumulent (ET).")
    : t("Cochez les listes d'actifs à inclure : les machines de toutes les listes cochées sont réunies.");
  $("#pt-filtre").value = ""; $("#pt-compte").textContent = ""; $("#pt-liste").innerHTML = `<p class="pt-vide">${t("Lecture en cours…")}</p>`;
  $("#pt-enregistrer").hidden = false;
  const dlg = $("#dlg-portee"); if (!dlg.open) dlg.showModal();
  try {
    PT.donnees = vm ? (await api("GET", "/api/vm/tags")).categories : (await api("GET", "/api/securitycenter/listes")).listes_actifs;
    dessinerPortee(); compterPortee();
  } catch (err) { $("#pt-liste").innerHTML = `<p class="pt-vide statut ko">${esc(err.message)}</p>`; }
}
function dessinerPortee() {
  const vm = produit() === "vm", f = $("#pt-filtre").value.trim().toLowerCase();
  const ok = (txt) => !f || txt.toLowerCase().includes(f);
  let html = "";
  if (vm) {
    for (const c of PT.donnees) {
      const vals = c.valeurs.filter((v) => ok(c.nom) || ok(v.nom));
      if (!vals.length) continue;
      html += `<div class="pt-cat">${esc(c.nom)} <small>${tp(c.valeurs.length, "valeur", "valeurs")}</small></div>`;
      html += vals.map((v) => `<label class="pt-ligne"><input type="checkbox" data-cat="${esc(c.nom)}" data-val="${esc(v.nom)}"${(PT.brouillon.tags[c.nom] || []).includes(v.nom) ? " checked" : ""}>
        <span class="pt-nom">${esc(v.nom)}</span>${v.description ? `<small>${esc(v.description)}</small>` : ""}</label>`).join("");
    }
  } else {
    html = PT.donnees.filter((l) => ok(l.nom)).map((l) => `<label class="pt-ligne"><input type="checkbox" data-id="${esc(l.id)}" data-nom="${esc(l.nom)}"${PT.brouillon.listes.some((x) => x.id === l.id) ? " checked" : ""}>
        <span class="pt-nom">${esc(l.nom)}</span><small>${l.type ? esc(l.type) : ""}${l.machines != null ? ` · ${tp(l.machines, "machine", "machines")}` : ""}</small></label>`).join("");
  }
  $("#pt-liste").innerHTML = html || `<p class="pt-vide">${t(PT.donnees.length ? "Aucun résultat pour ce filtre." : "Aucun élément accessible avec ces clés.")}</p>`;
}
function compterPortee() {
  clearTimeout(PT.minuteur);
  const vide = !PT.brouillon.listes.length && !Object.keys(PT.brouillon.tags).length;
  if (vide) { $("#pt-compte").textContent = t("Aucune sélection : toutes les machines accessibles seront incluses."); return; }
  $("#pt-compte").textContent = t("Décompte des machines…");
  const n = ++PT.seq;
  PT.minuteur = setTimeout(async () => {
    try {
      const r = await api("POST", "/api/perimetre/decompte", { profil: etat.profil.id, selection: PT.brouillon });
      if (n !== PT.seq) return;
      $("#pt-compte").textContent = r.machines == null ? t("Décompte indisponible ; le nombre exact sera connu à la récupération.")
        : produit() === "vm" ? t("{n} dans cette sélection", { n: tp(r.machines, "machine", "machines") })
        : t("{n} avec des vulnérabilités dans cette sélection", { n: tp(r.machines, "machine", "machines") });
    } catch (err) { if (n === PT.seq) $("#pt-compte").textContent = err.message; }
  }, 500);
}
$("#btn-portee").addEventListener("click", ouvrirPortee);
$("#pt-fermer").addEventListener("click", () => $("#dlg-portee").close());
$("#pt-filtre").addEventListener("input", () => PT.donnees && dessinerPortee());
$("#pt-liste").addEventListener("change", (e) => {
  const c = e.target; if (!c.matches("input[type=checkbox]")) return;
  if (produit() === "vm") {
    const v = new Set(PT.brouillon.tags[c.dataset.cat] || []);
    c.checked ? v.add(c.dataset.val) : v.delete(c.dataset.val);
    if (v.size) PT.brouillon.tags[c.dataset.cat] = [...v]; else delete PT.brouillon.tags[c.dataset.cat];
  } else {
    PT.brouillon.listes = PT.brouillon.listes.filter((x) => x.id !== c.dataset.id);
    if (c.checked) PT.brouillon.listes.push({ id: c.dataset.id, nom: c.dataset.nom });
  }
  compterPortee();
});
$("#pt-vider").addEventListener("click", () => { PT.brouillon = { listes: [], tags: {} }; dessinerPortee(); compterPortee(); });
$("#pt-appliquer").addEventListener("click", () => {
  etat.scope = PT.brouillon; $("#dlg-portee").close(); majPortee();
  toast(t("Périmètre appliqué à cette génération."));
});
$("#pt-enregistrer").addEventListener("click", async () => {
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { source: selectionVersSource(PT.brouillon) });
    etat.scope = PT.brouillon; $("#dlg-portee").close(); majRequeteJson(); majSource();
    toast(t("Périmètre enregistré dans le profil."));
  } catch (err) { $("#pt-compte").textContent = err.message; }
});

/* étape 1 : choix de l'origine des données */
function majSource() {
  const m = etat.modeles.find((x) => x.id === etat.modele);
  const comparaison = !!(m && m.exports === 2);
  if (comparaison) etat.source = "fichier";
  const sc = etat.source === "sc";
  $$("#source-choix button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.source === etat.source)));
  $("#source-choix").hidden = comparaison;
  $("#source-sc").hidden = !sc; $("#depot1").hidden = sc; $("#aide-fichier").hidden = sc;
  const per = etat.profil ? etat.profil.perimetre : null, src = etat.profil ? etat.profil.source : null;
  const nom = NOM_PRODUIT[produit()];
  $('#source-choix [data-source="sc"]').textContent = `${nom} (API)`;
  $("#btn-sc-recuperer").textContent = t("Récupérer depuis {produit}", { produit: nom });
  $("#btn-sc-recuperer2").textContent = t("ou récupérer l'export récent depuis {produit}", { produit: nom });
  const sevTxt = per ? t("sévérités {liste}", { liste: per.severites.map((k) => sevNom(k).toLowerCase()).join(", ") }) : "";
  $("#sc-resume").innerHTML = !scConfigure()
    ? `${t("La connexion n'est pas configurée :")} <a href="#" data-aller="securitycenter">${t("renseignez-la dans l'onglet Configuration")}</a>.`
    : produit() === "vm"
    ? `${t("Requête du profil :")} ${[src && src.cidr ? t("plage {liste}", { liste: esc(src.cidr) }) : t("tous les assets"), sevTxt,
        (src && src.periode === "0") ? t("toute la période") : t("vues depuis {n} jours", { n: (src && src.periode) || "30" }),
        (src && src.acr_aes === "0") ? t("sans ACR ni AES") : t("avec ACR et AES")].filter(Boolean).join(" ; ")}. <a href="#" data-aller="securitycenter">${t("Modifier la requête")}</a>`
    : `${t("Requête du profil :")} ${src && src.query_id ? t("requête enregistrée n° {id}", { id: esc(src.query_id) }) : [
        src && src.repositories ? t("dépôts {liste}", { liste: esc(src.repositories) }) : t("tous les dépôts"),
        src && src.asset_list ? t("liste d'actifs {liste}", { liste: esc(src.asset_list) }) : t("tous les actifs"),
        per ? t("sévérités {liste}", { liste: per.severites.map((k) => sevNom(k).toLowerCase()).join(", ") }) : ""].join(" ; ")}. <a href="#" data-aller="securitycenter">${t("Modifier la requête")}</a>`;
  $("#portee").hidden = !!(produit() === "sc" && src && src.query_id);           // une requête enregistrée remplace les filtres
  majPortee();
  $("#btn-sc-recuperer").disabled = !scConfigure();
  $("#sc-recent").hidden = !(comparaison && scConfigure());
}
$("#source-choix").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  etat.source = b.dataset.source;
  try { localStorage.setItem("source", etat.source); } catch { /* facultatif */ }
  majSource();
});
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-aller]"); if (!a) return;
  e.preventDefault(); $('.onglets [data-onglet="configuration"]').click();
});
/* Journal de la récupération : le serveur note chaque étape, l'interface le relit toutes les secondes pendant l'attente. */
function suivreJournal(boiteSel) {
  const boite = $(boiteSel), pre = $("pre", boite);
  const id = (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2)).replace(/[^A-Za-z0-9-]/g, "");
  let vues = 0, actif = true, enCours = false;
  pre.textContent = ""; boite.hidden = false; boite.open = true;
  const lire = async () => {
    if (enCours) return; enCours = true;
    try {
      const r = await fetch(`/api/journal/${id}?depuis=${vues}`).then((x) => x.json());
      if (r.lignes && r.lignes.length) {
        const enBas = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 24;      // ne défile pas si l'utilisateur remonte
        pre.textContent += (vues ? "\n" : "") + r.lignes.join("\n");
        vues += r.lignes.length;
        if (enBas) pre.scrollTop = pre.scrollHeight;
      }
    } catch { /* lecture suivante */ }
    enCours = false;
  };
  const minuteur = setInterval(() => actif && lire(), 1000);
  return { id, async fin() { actif = false; clearInterval(minuteur); while (enCours) await new Promise((r) => setTimeout(r, 50)); await lire(); } };
}
async function recupererSC(cible, boutonSel, statutSel) {
  const b = $(boutonSel); b.disabled = true;
  statut(statutSel, t("Interrogation de {produit}, cela peut prendre quelques minutes…", { produit: NOM_PRODUIT[produit()] }));
  const journal = suivreJournal(cible === 1 ? "#journal-sc" : "#journal-sc2");
  try {
    const r = await api("POST", "/api/securitycenter/exporter", { profil: etat.profil.id, modele: etat.modele, selection: etat.scope, journal: journal.id });
    const e = { id: r.id, nom: r.nom, taille: r.taille, portee: r.portee || null };
    if (cible === 1) { etat.export1 = e; } else { etat.export2 = e; $("#depot2").classList.add("charge"); }
    statut(statutSel, t("{lignes} lignes récupérées en {secondes} s. Copie conservée dans {dossier}", { lignes: r.lignes.toLocaleString(locale()), secondes: r.secondes, dossier: r.dossier }) + (r.avertissement ? " " + r.avertissement : "")
      + (cible === 2 && porteesDifferentes(etat.export1, e) ? " " + t("Attention : les deux exports n'ont pas le même périmètre.") : ""), "ok");
    afficherModeles(); if (cible === 1) await rafraichirApercu();
  } catch (err) { statut(statutSel, err.message, "ko"); }
  await journal.fin();
  b.disabled = !scConfigure(); majBoutonGenerer();
}
$("#btn-sc-recuperer").addEventListener("click", () => recupererSC(1, "#btn-sc-recuperer", "#statut-sc"));
$("#btn-sc-recuperer2").addEventListener("click", () => recupererSC(2, "#btn-sc-recuperer2", "#statut-sc2"));

/* serveur SMTP */
const CHAMPS_SMTP = ["hote", "port", "securite", "utilisateur", "expediteur", "nom_expediteur"];
const idSmtp = { hote: "#m-hote", port: "#m-port", securite: "#m-securite", utilisateur: "#m-user", mot_de_passe: "#m-pass", expediteur: "#m-exp", nom_expediteur: "#m-nom" };
function remplirSmtp() {
  const c = etat.config.smtp;
  CHAMPS_SMTP.forEach((k) => ($(idSmtp[k]).value = c[k] ?? ""));
  $("#m-pass").value = ""; majPlaceholders();
  $("#m-tls").checked = c.verifier_tls; statut("#statut-smtp", "");
}
function lireSmtp() {
  const o = Object.fromEntries(Object.entries(idSmtp).map(([k, sel]) => [k, $(sel).value]));
  o.verifier_tls = $("#m-tls").checked; return o;
}
$("#m-securite").addEventListener("change", (e) => { $("#m-port").value = { starttls: 587, ssl: 465, aucune: 25 }[e.target.value]; });
$("#form-smtp").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.config = await api("PUT", "/api/config", { smtp: lireSmtp() });
    remplirSmtp(); majBoutonGenerer(); statut("#statut-smtp", t("Serveur enregistré"), "ok");
  } catch (err) { statut("#statut-smtp", err.message, "ko"); }
});
$("#btn-smtp-tester").addEventListener("click", async () => {
  statut("#statut-smtp", t("Test en cours…"));
  try {
    await api("POST", "/api/smtp/tester", { smtp: lireSmtp() });
    statut("#statut-smtp", t("Connexion et authentification réussies (aucun message envoyé)."), "ok");
  } catch (err) { statut("#statut-smtp", err.message, "ko"); }
});

/* message par défaut (profil) */
const CHAMPS_MAIL = { destinataires: "#d-dest", objet: "#d-objet", message: "#d-message" };
function remplirMail() {
  const m = etat.profil.mail || {};
  Object.entries(CHAMPS_MAIL).forEach(([k, sel]) => ($(sel).value = m[k] || "")); statut("#statut-mail", "");
}
$("#form-mail").addEventListener("input", () => statut("#statut-mail", t("Modifications non enregistrées")));
$("#form-mail").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    etat.profil = await api("PUT", `/api/profils/${etat.profil.id}`, { mail: Object.fromEntries(Object.entries(CHAMPS_MAIL).map(([k, sel]) => [k, $(sel).value])) });
    statut("#statut-mail", t("Message enregistré"), "ok");
  } catch (err) { statut("#statut-mail", err.message, "ko"); }
});

/* envoi d'un rapport */
function ouvrirEnvoi(fichier) {
  etat.envoi = fichier; const m = etat.profil.mail || {};
  $("#e-dest").value = m.destinataires || ""; $("#e-objet").value = m.objet || ""; $("#e-message").value = m.message || "";
  $("#envoi-fichier").textContent = fichier; statut("#statut-envoi", ""); $("#envoi").hidden = false;
}
$("#liste-rapports").addEventListener("click", (e) => {
  const a = e.target.closest("[data-envoyer]"); if (!a) return;
  e.preventDefault();
  if (!etat.config || !etat.config.smtp.hote) { toast(t("Configurez d'abord le serveur SMTP (onglet Configuration)."), true); return; }
  ouvrirEnvoi(a.dataset.envoyer); $("#envoi").scrollIntoView({ block: "center", behavior: "smooth" });
});
$("#btn-envoi-fermer").addEventListener("click", () => ($("#envoi").hidden = true));
$("#envoi").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("#e-dest").value.trim()) { statut("#statut-envoi", t("Indiquez au moins un destinataire."), "ko"); return; }
  const b = $("#btn-envoyer"); b.disabled = true; statut("#statut-envoi", t("Envoi en cours…"));
  try {
    const r = await api("POST", `/api/rapports/${encodeURIComponent(etat.envoi)}/envoyer`, {
      profil: etat.profil.id, destinataires: $("#e-dest").value, objet: $("#e-objet").value, message: $("#e-message").value });
    statut("#statut-envoi", t("Envoyé à {liste}.", { liste: r.destinataires.join(", ") }), "ok");
  } catch (err) { statut("#statut-envoi", err.message, "ko"); }
  b.disabled = false;
});

/* ------------------------------------------------------------------ règles */
async function chargerRegles() {
  try {
    etat.regles = await api("GET", "/api/regles");
    etat.reglesOrig = JSON.stringify(etat.regles); etat.ouverte = null;
    afficherRegles(); majEtatRegles();
  } catch (err) { toast(err.message, true); }
}
function majEtatRegles() {
  const modif = JSON.stringify(etat.regles) !== etat.reglesOrig;
  $("#btn-regles-enregistrer").disabled = !modif;
  statut("#statut-regles", modif ? t("Modifications non enregistrées") : tp(etat.regles.length, "règle", "règles"));
}
function afficherRegles() {
  const f = $("#regles-filtre").value.trim().toLowerCase();
  $("#regles").innerHTML = etat.regles.map((r, i) => {
    if (f && !`${r.cle} ${r.motif} ${r.titre} ${r.famille}`.toLowerCase().includes(f)) return "";
    const ouverte = etat.ouverte === i;
    return `<li class="regle" data-i="${i}">
      <button type="button" class="regle-ligne" aria-expanded="${ouverte}">
        <span class="regle-num">${i + 1}</span><span class="regle-titre">${esc(r.titre)}</span>
        <span class="regle-motif" title="${esc(r.motif)}">${esc(r.motif)}</span>
        <span class="regle-modif">${ouverte ? t("Fermer") : t("Modifier")}</span>
      </button>
      ${ouverte ? editeurRegle(r, i) : ""}</li>`;
  }).join("") || `<li class="vide" style="padding:12px">${t("Aucune règle ne correspond au filtre.")}</li>`;
}
function editeurRegle(r) {
  const champ = (n, lib, plein = false, zone = false) => `<div class="${plein ? "plein" : ""}"><label>${t(lib)}</label>${
    zone ? `<textarea name="${n}" rows="3">${esc(r[n])}</textarea>` : `<input name="${n}" value="${esc(r[n])}" spellcheck="false">`}</div>`;
  const avis = r.repli ? `<p class="regle-avis plein">${t("Texte non traduit dans cette langue : affichage de la version « {langue} ». Modifiez-le pour créer la traduction.", { langue: r.repli.toUpperCase() })}</p>` : "";
  return `<div class="regle-editeur">
    ${avis}
    ${champ("titre", "Titre de la solution")}${champ("cle", "Clé de regroupement (commune à toutes les langues)")}
    ${champ("motif", "Motif (expression régulière sur l'intitulé Tenable, commun à toutes les langues)", true)}
    ${champ("action", "Action à mener", true, true)}
    ${champ("famille", "Famille Tenable (facultatif)")}${champ("commentaire", "Commentaire")}
    <div class="regle-actions">
      <button type="button" class="btn-discret" data-op="monter">${t("Monter")}</button>
      <button type="button" class="btn-discret" data-op="descendre">${t("Descendre")}</button>
      <button type="button" class="btn-discret danger" data-op="supprimer">${t("Supprimer la règle")}</button>
    </div></div>`;
}
$("#regles").addEventListener("click", (e) => {
  const li = e.target.closest(".regle"); if (!li) return;
  const i = Number(li.dataset.i);
  if (e.target.closest(".regle-ligne")) { etat.ouverte = etat.ouverte === i ? null : i; afficherRegles(); return; }
  const op = e.target.dataset.op; if (!op) return;
  const R = etat.regles;
  if (op === "monter" && i > 0) { [R[i - 1], R[i]] = [R[i], R[i - 1]]; etat.ouverte = i - 1; }
  if (op === "descendre" && i < R.length - 1) { [R[i + 1], R[i]] = [R[i], R[i + 1]]; etat.ouverte = i + 1; }
  if (op === "supprimer" && confirm(t("Supprimer la règle « {titre} » ?", { titre: R[i].titre }))) { R.splice(i, 1); etat.ouverte = null; }
  afficherRegles(); majEtatRegles();
});
$("#regles").addEventListener("input", (e) => {
  const li = e.target.closest(".regle"); if (!li || !e.target.name) return;
  const i = Number(li.dataset.i); etat.regles[i][e.target.name] = e.target.value;
  if (e.target.name === "titre") li.querySelector(".regle-titre").textContent = e.target.value;
  if (e.target.name === "motif") li.querySelector(".regle-motif").textContent = e.target.value;
  majEtatRegles();
});
$("#regles-filtre").addEventListener("input", afficherRegles);
function ajouterRegle(base = {}) {
  const r = { cle: "", famille: "", motif: "", titre: "", action: "", commentaire: "", ...base };
  // les règles génériques sont en fin de fichier : une nouvelle règle spécifique se place avant elles
  const idx = etat.regles.findIndex((x) => x.cle.startsWith("eol:"));
  const pos = idx >= 0 ? idx : etat.regles.length;
  etat.regles.splice(pos, 0, r); etat.ouverte = pos; $("#regles-filtre").value = "";
  afficherRegles(); majEtatRegles();
  const li = $(`.regle[data-i="${pos}"]`); li.scrollIntoView({ block: "center" }); li.querySelector("input[name=titre]").focus();
}
$("#btn-regle-ajouter").addEventListener("click", () => ajouterRegle());
$("#btn-regles-enregistrer").addEventListener("click", async () => {
  try {
    const r = await api("PUT", "/api/regles", etat.regles);
    etat.reglesOrig = JSON.stringify(etat.regles); majEtatRegles();
    toast(t("{n} règles enregistrées. Une copie de l'ancien fichier est conservée (dossier regles/, fichiers .bak).", { n: r.nombre, code: I18N.code }));
    if (etat.export1) rafraichirApercu();
  } catch (err) { statut("#statut-regles", err.message, "ko"); }
});
$("#btn-regles-importer").addEventListener("click", () => $("#fichier-regles").click());
$("#fichier-regles").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  if (!confirm(t("Remplacer toutes les règles par celles de {nom} ? Une copie de l'ancien fichier est conservée.", { nom: f.name }))) { e.target.value = ""; return; }
  const fd = new FormData(); fd.append("fichier", f);
  try { const r = await api("POST", "/api/regles/fichier", fd); await chargerRegles(); toast(t("{n} règles importées.", { n: r.nombre })); }
  catch (err) { toast(err.message, true); }
  e.target.value = "";
});

/* testeur */
async function tester() {
  const txt = $("#test-intitules").value; if (!txt.trim()) return;
  try {
    const res = await api("POST", "/api/regles/tester", { intitules: txt, regles: etat.regles });
    $("#resultats-test").innerHTML = res.map((r, k) => `<li>
      <div class="intitule">${esc(r.intitule)}</div>
      ${r.ligne ? `<div class="titre">${esc(r.titre)} <span class="intitule">${t("(règle {n})", { n: r.ligne - 1 })}</span></div><div>${esc(r.action)}</div>`
                : `<div class="aucune">${t("Aucune règle : l'intitulé sera traité seul, avec le texte de la colonne Solution de l'export s'il est présent.")}</div>
                   <button type="button" class="btn-secondaire" data-creer="${k}">${t("Créer une règle pour cet intitulé")}</button>`}</li>`).join("");
    $("#resultats-test").dataset.res = JSON.stringify(res.map((r) => r.intitule));
  } catch (err) { toast(err.message, true); }
}
$("#btn-tester").addEventListener("click", tester);
$("#resultats-test").addEventListener("click", (e) => {
  const k = e.target.dataset.creer; if (k === undefined) return;
  const intitule = JSON.parse($("#resultats-test").dataset.res)[Number(k)];
  const produit = intitule.split(/\s+(?:<|\(|\d)/)[0].trim();
  const motif = "^" + produit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  ajouterRegle({ cle: produit.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""), motif,
                 titre: t("Mettre à jour {produit}", { produit }), action: t("Installer la dernière version corrigée de {produit}.", { produit }) });
  toast(t("Règle ajoutée : complétez-la puis enregistrez."));
});
function remplirSansRegle() {
  if (!etat.apercu) return;
  $("#test-intitules").value = etat.apercu.sans_regle.join("\n"); tester();
}
$("#btn-sans-regle").addEventListener("click", remplirSansRegle);

window.addEventListener("beforeunload", (e) => {
  if (etat.regles.length && JSON.stringify(etat.regles) !== etat.reglesOrig) { e.preventDefault(); e.returnValue = ""; }
});

/* ------------------------------------------------------------------ démarrage */
(async () => {
  try {
    await chargerTheme();
    await chargerModeles();
    try { etat.source = localStorage.getItem("source") === "sc" ? "sc" : "fichier"; } catch { /* facultatif */ }
    await chargerConfig();
    await chargerProfils();
    await chargerRapports();
  } catch (err) { toast(t("Le serveur local ne répond pas : relancez l'application. ({erreur})", { erreur: err.message }), true); }
})();

