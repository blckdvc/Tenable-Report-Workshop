"use strict";
/* Internationalisation de l'interface : français (langue des textes du code), anglais, espagnol, italien.
   - t("texte français", {variable: valeur}) traduit un texte ; les {variables} sont remplacées.
   - Le DOM statique et les contenus ajoutés dynamiquement sont traduits automatiquement quand leur texte
     complet correspond à une entrée du catalogue (web/langues/<code>.json : { "français": "traduction" }).
   - Un élément portant data-i18n-html est traduit à partir de son innerHTML complet. data-i18n="non" l'exclut. */

const DRAPEAUX = {
  fr: '<svg viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#0055A4"/><rect x="10" width="10" height="20" fill="#fff"/><rect x="20" width="10" height="20" fill="#EF4135"/></svg>',
  en: '<svg viewBox="0 0 60 40" aria-hidden="true"><rect width="60" height="40" fill="#012169"/><path d="M0,0 L60,40 M60,0 L0,40" stroke="#fff" stroke-width="8"/><path d="M0,0 L60,40 M60,0 L0,40" stroke="#C8102E" stroke-width="3"/><path d="M30,0 V40 M0,20 H60" stroke="#fff" stroke-width="13"/><path d="M30,0 V40 M0,20 H60" stroke="#C8102E" stroke-width="8"/></svg>',
  es: '<svg viewBox="0 0 30 20" aria-hidden="true"><rect width="30" height="20" fill="#AA151B"/><rect y="5" width="30" height="10" fill="#F1BF00"/></svg>',
  it: '<svg viewBox="0 0 30 20" aria-hidden="true"><rect width="10" height="20" fill="#009246"/><rect x="10" width="10" height="20" fill="#fff"/><rect x="20" width="10" height="20" fill="#CE2B37"/></svg>',
};
const LANGUES = [
  { code: "fr", nom: "Français", court: "FR", locale: "fr-FR" },
  { code: "en", nom: "English", court: "EN", locale: "en-GB" },
  { code: "es", nom: "Español", court: "ES", locale: "es-ES" },
  { code: "it", nom: "Italiano", court: "IT", locale: "it-IT" },
];
const I18N = { code: "fr", cat: {}, cache: {} };

function t(texte, vars) {
  let s = (I18N.code !== "fr" && I18N.cat[texte]) || texte;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));
  return s;
}

/* Pluriel : tp(n, "machine", "machines") ; catalogue : clé = singulier français, valeur = « singulier|pluriel ». */
function tp(n, mot, mots) {
  const v = I18N.code !== "fr" && I18N.cat[mot];
  if (v && v.includes("|")) { const [un, pl] = v.split("|"); return `${n} ${n === 1 ? un : pl}`; }
  return `${n} ${n > 1 ? (mots || mot + "s") : mot}`;
}

/* --- traduction du DOM --- */
const ATTRS = ["placeholder", "title", "aria-label", "alt"];
const cle = (s) => s.replace(/\s+/g, " ").trim();
function traduireTexte(noeud) {
  if (noeud.__fr === undefined) {
    const k = cle(noeud.nodeValue);
    if (!k) return;
    noeud.__fr = noeud.nodeValue;
  }
  const k = cle(noeud.__fr), tr = I18N.code === "fr" ? null : I18N.cat[k];
  const nouveau = tr ? noeud.__fr.replace(k, tr) : noeud.__fr;
  if (noeud.nodeValue !== nouveau) { noeud.__ecrit = true; noeud.nodeValue = nouveau; }
}
function traduireElement(el) {
  if (el.closest && el.closest('[data-i18n="non"], script, style')) return;
  if (el.hasAttribute && el.hasAttribute("data-i18n-html")) {
    if (el.__frHtml === undefined) el.__frHtml = el.innerHTML;
    const tr = I18N.code === "fr" ? null : I18N.cat[cle(el.__frHtml)];
    const nouveau = tr || el.__frHtml;
    if (el.innerHTML !== nouveau) el.innerHTML = nouveau;
    return;
  }
  for (const a of ATTRS) {
    if (!el.hasAttribute || !el.hasAttribute(a)) continue;
    el.__frAttr = el.__frAttr || {};
    if (el.__frAttr[a] === undefined) el.__frAttr[a] = el.getAttribute(a);
    const tr = I18N.code === "fr" ? null : I18N.cat[cle(el.__frAttr[a])];
    const nouveau = tr || el.__frAttr[a];
    if (el.getAttribute(a) !== nouveau) el.setAttribute(a, nouveau);
  }
  if (el.tagName === "INPUT" && (el.type === "button" || el.type === "submit")) { /* valeur non traduite */ }
}
function traduireArbre(racine) {
  if (racine.nodeType === 3) { if (!racine.parentElement || !racine.parentElement.closest('[data-i18n="non"], script, style, [data-i18n-html]')) traduireTexte(racine); return; }
  if (racine.nodeType !== 1) return;
  traduireElement(racine);
  if (racine.hasAttribute("data-i18n-html")) return;
  const w = document.createTreeWalker(racine, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  let n;
  while ((n = w.nextNode())) {
    if (n.nodeType === 3) { if (!n.parentElement.closest('[data-i18n="non"], script, style, [data-i18n-html]')) traduireTexte(n); }
    else traduireElement(n);
  }
}
const observateur = new MutationObserver((muts) => {
  for (const m of muts) {
    if (m.type === "childList") m.addedNodes.forEach((n) => traduireArbre(n));
    else if (m.type === "characterData" && !m.target.__ecrit) { m.target.__fr = undefined; traduireTexte(m.target); }
    else if (m.type === "characterData") m.target.__ecrit = false;
  }
});

async function chargerCatalogue(code) {
  if (code === "fr") return {};
  if (!I18N.cache[code]) {
    try { const r = await fetch(`/web/langues/${code}.json`); I18N.cache[code] = r.ok ? await r.json() : {}; }
    catch { I18N.cache[code] = {}; }
  }
  return I18N.cache[code];
}

/* Change la langue de l'interface (sans toucher au profil : voir app.js). */
async function appliquerLangue(code) {
  if (!LANGUES.some((l) => l.code === code)) code = "fr";
  I18N.cat = await chargerCatalogue(code);
  I18N.code = code;
  document.documentElement.lang = code;
  traduireArbre(document.body);
  document.title = t("Atelier de rapports Tenable");
  majSelecteurLangue();
  document.dispatchEvent(new CustomEvent("langue", { detail: code }));
}

/* Toutes les requêtes portent la langue : les messages d'erreur du serveur arrivent déjà traduits. */
const fetchOrigine = window.fetch.bind(window);
window.fetch = (url, opts = {}) => {
  opts = { ...opts, headers: { ...(opts.headers || {}), "X-Langue": I18N.code } };
  return fetchOrigine(url, opts);
};

/* --- sélecteur (drapeaux) --- */
function majSelecteurLangue() {
  const l = LANGUES.find((x) => x.code === I18N.code) || LANGUES[0];
  const bouton = document.getElementById("langue-btn");
  if (!bouton) return;
  bouton.querySelector(".drapeau").innerHTML = DRAPEAUX[l.code];
  bouton.querySelector(".langue-code").textContent = l.court;
  bouton.title = t("Langue de l'interface et des rapports");
  bouton.setAttribute("aria-label", t("Langue de l'interface et des rapports"));
  document.querySelectorAll("#langue-menu button").forEach((b) => b.setAttribute("aria-current", String(b.dataset.langue === l.code)));
}
function initSelecteurLangue(surChoix) {
  const menu = document.getElementById("langue-menu"), bouton = document.getElementById("langue-btn");
  if (!menu || !bouton) return;
  menu.innerHTML = LANGUES.map((l) => `<button type="button" data-langue="${l.code}" data-i18n="non"><span class="drapeau">${DRAPEAUX[l.code]}</span><span>${l.nom}</span></button>`).join("");
  bouton.addEventListener("click", () => { menu.hidden = !menu.hidden; bouton.setAttribute("aria-expanded", String(!menu.hidden)); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".langue-choix")) { menu.hidden = true; bouton.setAttribute("aria-expanded", "false"); } });
  menu.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-langue]"); if (!b) return;
    menu.hidden = true; bouton.setAttribute("aria-expanded", "false");
    surChoix(b.dataset.langue);
  });
  majSelecteurLangue();
}
observateur.observe(document.body, { childList: true, subtree: true, characterData: true });
