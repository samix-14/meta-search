const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let analysis = null, labTab = "strings", toastTimer;
function toast(message) {
  const node = $("#toast"); node.textContent = message; node.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => node.classList.remove("show"), 2800);
}
function navigate(view) {
  $$(".view").forEach((el) => { el.classList.toggle("hidden", el.id !== "view-" + view); el.classList.toggle("active", el.id === "view-" + view); });
  $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.view === view));
  $("#crumb").textContent = ({analyzer:"ANALIZZATORE",results:"RISULTATI",lab:"LABORATORIO TECNICO"})[view] || view.toUpperCase();
}
$$(".nav-item").forEach((el) => el.addEventListener("click", () => navigate(el.dataset.view)));
$$("[data-goto]").forEach((el) => el.addEventListener("click", () => navigate(el.dataset.goto)));
async function checkStatus() {
  try { const r = await fetch("/api/status"); if (!r.ok) throw new Error(); const d = await r.json(); $("#api-status").textContent = "ONLINE · " + d.version; }
  catch { $("#api-status").textContent = "OFFLINE"; toast("Backend non raggiungibile. Avvia app.py e apri http://127.0.0.1:5000."); }
}
$("#choose-file").addEventListener("click", () => $("#file-input").click());
$("#file-input").addEventListener("change", (e) => { if (e.target.files[0]) selectFile(e.target.files[0]); });
function selectFile(file) {
  $("#selected-file").textContent = "SELEZIONATO · " + file.name + " · " + (file.size / 1024 / 1024).toFixed(2) + " MB";
  $("#selected-file").classList.remove("hidden"); analyze(file);
}
const dropZone = $("#drop-zone");
["dragenter","dragover"].forEach((name) => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add("dragover"); }));
["dragleave","drop"].forEach((name) => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove("dragover"); }));
dropZone.addEventListener("drop", (e) => { const file = e.dataTransfer.files[0]; if (file) selectFile(file); });
async function analyze(file) {
  if (file.size > 100 * 1024 * 1024) { toast("Il file supera il limite di 100 MB della versione 0.1."); return; }
  const button = $("#choose-file"), oldText = button.innerHTML;
  button.disabled = true; button.textContent = "Analisi in corso...";
  try {
    const form = new FormData(); form.append("file", file, file.name);
    const response = await fetch("/api/analyze", {method:"POST",body:form}), data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analisi non riuscita.");
    analysis = data; renderResults(); renderLab(); toast("Analisi completata: " + data.name); navigate("results");
  } catch (error) { toast(error.message || "Errore durante l'analisi."); }
  finally { button.disabled = false; button.innerHTML = oldText; }
}
function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function renderResults() {
  if (!analysis) return;
  $("#empty-results").classList.add("hidden"); $("#results-content").classList.remove("hidden");
  $("#result-subtitle").textContent = analysis.name + " · " + analysis.size_human + " · analizzato " + new Date(analysis.analyzed_at).toLocaleString();
  const cards = [["FILE",analysis.name],["DIMENSIONE",analysis.size_human],["FORMATO RILEVATO",analysis.detected_type],["SHA-256",analysis.sha256,true]];
  $("#summary-grid").innerHTML = cards.map((item) => '<div class="summary-card"><small>' + escapeHTML(item[0]) + '</small><strong class="' + (item[2] ? "hash" : "") + '" title="' + escapeHTML(item[1]) + '">' + escapeHTML(item[1]) + '</strong></div>').join("");
  $("#metadata-count").textContent = analysis.metadata.length + " CAMPI"; $("#export-json").disabled = false; renderHighlights(); renderMetadata();
}
function renderHighlights() {
  const h = analysis?.highlights || {};
  const cards = [
    {title:"DOVE È STATA SCATTATA", value:h.location, detail:"Coordinate GPS incorporate nella foto.", map:h.map_url},
    {title:"DATA DELLO SCATTO", value:h.photo_date, detail:"Data dichiarata nei metadati della fotocamera."},
    {title:"FOTOCAMERA", value:h.camera, detail:"Marca e modello dichiarati dalla fotocamera."}
  ];
  $("#quick-insights").innerHTML = '<div class="insights-heading"><strong>IN PAROLE SEMPLICI</strong><span>Informazioni principali, se presenti</span></div><div class="insights-grid">' +
    cards.map(card => '<article class="insight-card"><small>' + escapeHTML(card.title) + '</small><strong>' + escapeHTML(card.value || "Non disponibile") + '</strong><p>' + escapeHTML(card.value ? card.detail : (card.title === "DOVE È STATA SCATTATA" ? "Questa foto non contiene coordinate GPS leggibili." : "Il file non contiene questo dato, oppure non è stato riconosciuto.")) + '</p>' +
    (card.map && card.value ? '<a href="' + escapeHTML(card.map) + '" target="_blank" rel="noopener noreferrer">Apri posizione su Google Maps ↗</a>' : '') + '</article>').join("") +
    '</div>';
}
function renderMetadata() {
  if (!analysis) return;
  const q = $("#metadata-search").value.trim().toLowerCase();
  const rows = analysis.metadata.filter((item) => [item.group,item.key,item.value,item.explanation].some((v) => String(v).toLowerCase().includes(q)));
  $("#metadata-count").textContent = rows.length + " / " + analysis.metadata.length + " CAMPI";
  $("#metadata-list").innerHTML = rows.length ? rows.map((item) => '<article class="metadata-row"><div class="metadata-key"><span class="metadata-group">' + escapeHTML(item.group) + '</span>' + escapeHTML(item.key) + '</div><div><div class="metadata-value">' + escapeHTML(item.value) + '</div><div class="metadata-explanation">' + escapeHTML(item.explanation) + '</div></div></article>').join("") : '<div class="empty-state"><h2>Nessun risultato</h2><p>Prova con un termine diverso.</p></div>';
}
$("#metadata-search").addEventListener("input", renderMetadata);
$("#export-json").addEventListener("click", () => {
  if (!analysis) return;
  downloadFile(JSON.stringify(analysis,null,2), safeName(analysis.name) + ".metasearch.json", "application/json");
  toast("Esportazione JSON preparata.");
});
function safeName(name) { return name.replace(/[<>:"/\\|?*\x00-\x1f]/g,"_").slice(0,100) || "file"; }
function downloadFile(content,name,type) {
  const url = URL.createObjectURL(new Blob([content],{type})), link = document.createElement("a");
  link.href = url; link.download = name; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
}
$$(".lab-tab").forEach((button) => button.addEventListener("click", () => {
  labTab = button.dataset.tab; $$(".lab-tab").forEach((tab) => tab.classList.toggle("active",tab === button)); renderLab();
}));
function renderLab() {
  if (!analysis) return;
  $("#lab-empty").classList.add("hidden"); $("#lab-content").classList.remove("hidden");
  const output = labTab === "strings" ? (analysis.strings.length ? analysis.strings.map((v,i) => String(i+1).padStart(3,"0") + "  " + v).join("\n") : "Nessuna stringa ASCII leggibile trovata.") : analysis.hex_preview || "(file vuoto)";
  $("#lab-output").textContent = output; $("#lab-caption").textContent = labTab === "strings" ? "STRINGHE LEGGIBILI · " + analysis.strings.length : "HEX · PRIMI 512 BYTE";
}
$("#copy-lab").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#lab-output").textContent); toast("Contenuto copiato."); }
  catch { toast("Copia bloccata dal browser. Seleziona il testo manualmente."); }
});
checkStatus();