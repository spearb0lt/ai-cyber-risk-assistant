/* Cyber Risk Assistant front end.
 *
 * No build step and no framework. The page is small enough that plain DOM work
 * is clearer than a toolchain, and it keeps the deployment a single process.
 *
 * API keys a visitor pastes are held in this browser's localStorage and sent
 * as X-LLM-Key-<slug> headers with that visitor's own requests. They are never
 * posted to the server as data and never stored server side.
 */

/* ------------------------------------------------------------------ state */

const KEY_STORE = "cra.keys";
const BASE_STORE = "cra.bases";
const ACCOUNT_STORE = "cra.accounts";
const WEIGHT_STORE = "cra.weights";

function readStored(name) {
  try {
    const parsed = JSON.parse(localStorage.getItem(name) || "{}");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (e) {
    return {};
  }
}

const store = {
  config: null,
  analysis: null,
  view: "risks",
  provider: localStorage.getItem("cra.provider") || "",
  model: localStorage.getItem("cra.model") || "",
  keys: readStored(KEY_STORE),
  bases: readStored(BASE_STORE),
  accounts: readStored(ACCOUNT_STORE),
  nist: null,
  // Scoring weight overrides. Empty means the published default model.
  weights: readStored(WEIGHT_STORE),
  weightSchema: null,
  rerank: localStorage.getItem("cra.rerank") === "1",
};

function persistKeys() {
  try {
    localStorage.setItem(KEY_STORE, JSON.stringify(store.keys));
    localStorage.setItem(BASE_STORE, JSON.stringify(store.bases));
    localStorage.setItem(ACCOUNT_STORE, JSON.stringify(store.accounts));
  } catch (e) {
    toast("warn", "Could not save the key", "This browser blocks local storage, so it lasts for this tab only.");
  }
}

function setKey(slug, value) {
  const trimmed = (value || "").trim();
  if (trimmed) store.keys[slug] = trimmed;
  else delete store.keys[slug];
  persistKeys();
}

function setBase(slug, value) {
  const trimmed = (value || "").trim().replace(/\/+$/, "");
  if (trimmed) store.bases[slug] = trimmed;
  else delete store.bases[slug];
  persistKeys();
}

function setAccount(slug, value) {
  const trimmed = (value || "").trim();
  if (trimmed) store.accounts[slug] = trimmed;
  else delete store.accounts[slug];
  persistKeys();
}

function persistWeights() {
  try {
    localStorage.setItem(WEIGHT_STORE, JSON.stringify(store.weights));
  } catch (e) {
    /* A tuning that cannot be saved still applies for this session. */
  }
}

function hasCustomWeights() {
  return Object.keys(store.weights).length > 0;
}

function weightBody(extra) {
  const body = Object.assign({}, extra || {});
  if (hasCustomWeights()) body.weights = store.weights;
  return body;
}

function keyHeaders() {
  const headers = {};
  Object.keys(store.keys).forEach((slug) => {
    if (store.keys[slug]) headers["X-LLM-Key-" + slug] = store.keys[slug];
  });
  Object.keys(store.bases).forEach((slug) => {
    if (store.bases[slug]) headers["X-LLM-Base-" + slug] = store.bases[slug];
  });
  Object.keys(store.accounts).forEach((slug) => {
    if (store.accounts[slug]) headers["X-LLM-Account-" + slug] = store.accounts[slug];
  });
  return headers;
}

/* -------------------------------------------------------------------- api */

async function api(path, options) {
  const opts = Object.assign({ headers: {} }, options || {});
  Object.assign(opts.headers, keyHeaders());
  if (opts.json !== undefined) {
    opts.method = opts.method || "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
    delete opts.json;
  }

  let response;
  try {
    response = await fetch("/api" + path, opts);
  } catch (err) {
    throw Object.assign(new Error("The server could not be reached."), {
      hint: "Check your connection and try again.",
    });
  }

  const isJson = (response.headers.get("content-type") || "").includes("application/json");
  if (!response.ok) {
    let payload = null;
    try {
      payload = isJson ? await response.json() : { detail: await response.text() };
    } catch (e) {
      payload = null;
    }
    const info = (payload && payload.detail && payload.detail.error) || (payload && payload.error) || {};
    throw Object.assign(new Error(info.message || `Request failed (${response.status}).`), {
      hint: info.hint || "",
      status: response.status,
    });
  }
  return isJson ? response.json() : response.text();
}

/* ----------------------------------------------------------------- helpers */

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    Object.keys(attrs).forEach((k) => {
      if (k === "class") node.className = attrs[k];
      else if (k === "html") node.innerHTML = attrs[k];
      else if (k === "text") node.textContent = attrs[k];
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== null && attrs[k] !== undefined) node.setAttribute(k, attrs[k]);
    });
  }
  (children || []).forEach((child) => {
    if (child === null || child === undefined || child === false) return;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  });
  return node;
}

/* Everything rendered from API data goes through this. The data is trusted
 * (it is our own CSVs) but escaping is the correct default regardless. */
function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function bandClass(band) {
  return (band || "low").toLowerCase();
}

function toast(kind, title, body) {
  const node = el("div", { class: "toast " + (kind === "error" ? "err" : kind === "ok" ? "ok" : "") }, [
    el("b", { text: title }),
    body ? el("span", { text: body }) : null,
  ]);
  $("#toasts").appendChild(node);
  setTimeout(() => node.remove(), 7000);
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/* ------------------------------------------------------------------ stats */

function renderStats() {
  const s = store.analysis.summary;
  const kev = store.analysis.kev;
  const cards = [
    { v: s.vulnerabilities, k: "Open findings", sub: `${s.assets} assets, ${s.business_services} services` },
    { v: s.kev_confirmed_vulnerabilities, k: "CISA KEV confirmed", sub: `${s.ransomware_linked_vulnerabilities} ransomware linked` },
    { v: s.internet_exposed_assets, k: "Internet exposed", sub: `${s.assets_without_edr} assets without EDR` },
    { v: `${s.intel_matched}/${s.intel_records}`, k: "Intel matched", sub: `${s.intel_unmatched} excluded as noise` },
    { v: s.bands.Critical, k: "Critical band", sub: `${s.bands.High} high, ${s.bands.Medium} medium` },
    { v: kev.age_days === null ? "?" : `${kev.age_days}d`, k: "KEV snapshot age", sub: `${kev.entries} entries` },
  ];
  $("#stats").innerHTML = "";
  cards.forEach((c) => {
    $("#stats").appendChild(
      el("div", { class: "stat" }, [
        el("div", { class: "v", text: String(c.v) }),
        el("div", { class: "k", text: c.k }),
        el("div", { class: "sub", text: c.sub }),
      ])
    );
  });
}

/* ------------------------------------------------------------- risk cards */

/* Labels only. The ceilings come from the weighting the analysis was actually
   produced under, so a tuned run shows its own caps rather than the defaults. */
const FACTOR_META = [
  ["exploitability", "Active exploitation"],
  ["exposure", "Internet exposure"],
  ["campaign", "Threat campaign"],
  ["business_impact", "Business impact"],
  ["missing_controls", "Missing controls"],
  ["cvss", "CVSS severity"],
];

function capForAmplifier() {
  const weights = (store.analysis && store.analysis.weights) || {};
  return typeof weights.amplifier_cap === "number" ? weights.amplifier_cap : 6;
}

function capFor(key) {
  const weights = (store.analysis && store.analysis.weights) || {};
  const cap = weights["cap_" + key];
  return typeof cap === "number" ? cap : 0;
}


/* The alternative control that was considered and rejected.
 *
 * Only shown when the runner up is a genuinely different control. A base
 * control beating its own enhancement, SI-2 over SI-2(3), is decided by a
 * rule rather than by the scores, so printing a margin for it would dress a
 * fixed outcome up as a contest; seventeen of the twenty pairings in this
 * brief are that case.
 *
 * The fused score itself is deliberately not shown. It is a reciprocal rank
 * fusion sum, not a probability or a confidence, so a reader cannot do
 * anything with the number. It is still returned by /api/analysis for anyone
 * auditing the retrieval. What a reader can use is the name of the control
 * that came second, which is a judgement they can disagree with.
 */
function retrievalLine(control) {
  const r = control.retrieval;
  if (!r || !r.runner_up || r.same_family) return "";
  const close = r.margin_percent < 10;
  return (
    `<div class="retrieval${close ? " close" : ""}">` +
    `Also considered: <strong>${esc(r.runner_up)} ${esc(r.runner_up_name)}</strong>` +
    (close
      ? `, which scored almost the same. <strong>Treat this choice as uncertain.</strong>`
      : `, which scored lower.`) +
    `</div>`
  );
}

function riskCard(risk) {
  const lead = risk.lead;

  const assetList = risk.assets
    .map(
      (a) =>
        `<li><strong>${esc(a.asset_name)}</strong>, ${esc(a.asset_type)}, ${esc(a.environment)}` +
        `${a.internet_exposed ? ", internet exposed" : ", internal"}` +
        `${a.edr_installed ? "" : ", <em>no EDR</em>"}` +
        `${a.owner_team ? `, owned by ${esc(a.owner_team)}` : ", <em>no owner</em>"}</li>`
    )
    .join("");

  const vulnList = risk.vulnerabilities
    .map(
      (v) =>
        `<li><strong>${esc(v.cve)}</strong> ${esc(v.name)}<br />` +
        `<span style="color:var(--dim)">CVSS ${v.cvss.toFixed(1)}, open ${v.days_open} days, ` +
        `${v.patch_available ? "patch available" : "no patch"}${v.in_kev ? ", <strong style='color:var(--critical)'>in CISA KEV</strong>" : ""}` +
        `${v.kev_ransomware ? ", ransomware linked" : ""}</span></li>`
    )
    .join("");

  const intelHtml = risk.threat_intel.length
    ? risk.threat_intel
        .map(
          (t) =>
            `<li><strong>${esc(t.threat_actor)}</strong>, campaign "${esc(t.campaign_name)}"<br />` +
            `<span style="color:var(--dim)">${esc(t.target_sector)}, ${esc(t.target_region)}. ` +
            `${esc(t.exploit_maturity)}, ${esc(t.confidence).toLowerCase()} confidence, last seen ${esc(t.active_last_seen)}` +
            `${t.ransomware_association ? ", ransomware" : ""}. Matches ${esc(t.matched_cve)}.</span></li>`
        )
        .join("")
    : `<li style="color:var(--muted)">No campaign in the feed references these identifiers. This ranks on exposure and business impact alone.</li>`;

  const serviceHtml = risk.service_owner
    ? `<strong>${esc(risk.business_service)}</strong>, owned by ${esc(risk.service_owner)}.<br />` +
      `<span style="color:var(--dim)">${esc(risk.service_impact)}<br />` +
      `Compliance scope ${esc(risk.compliance_scope)}. Recovery objective ${esc(risk.rto_hours)}h.</span>`
    : `<strong>${esc(risk.business_service)}</strong>`;

  const factorsHtml = FACTOR_META.map(([key, label]) => {
    const cap = capFor(key);
    const value = risk.factors[key] || 0;
    const pct = cap > 0 ? Math.round((value / cap) * 100) : 0;
    const off = cap <= 0;
    return (
      `<div class="factor"${off ? ' style="opacity:.45"' : ""}>` +
      `<div class="name">${esc(label)}${off ? " (off)" : ""}</div>` +
      `<div class="bar"><span style="width:${pct}%"></span></div>` +
      `<div class="num">${value.toFixed(1)}/${cap}</div></div>`
    );
  }).join("");

  const amplifierHtml = risk.amplifier
    ? `<div class="factor"><div class="name">Blast radius</div>` +
      `<div class="bar"><span style="width:${Math.round((risk.amplifier / Math.max(capForAmplifier(), 1)) * 100)}%;background:#8b5cf6"></span></div>` +
      `<div class="num">+${risk.amplifier.toFixed(1)}</div></div>`
    : "";

  const controlsHtml = risk.controls.length
    ? risk.controls
        .map(
          (c) =>
            `<div class="control">` +
            `<div><span class="cid">${esc(c.identifier)}</span> <span class="cname">${esc(c.name)}</span></div>` +
            `<div class="cmeta">${esc(c.family_name)}${c.retrieved_for ? ` &middot; retrieved for: ${esc(c.retrieved_for.toLowerCase())}` : ""}` +
            `${c.is_enhancement ? " &middot; control enhancement" : ""}</div>` +
            `<blockquote>${esc(c.excerpt)}</blockquote>` +
            retrievalLine(c) +
            (c.discussion
              ? `<details><summary>Full discussion from the catalogue</summary><p>${esc(c.discussion)}</p></details>`
              : "") +
            `</div>`
        )
        .join("")
    : `<p class="note">No NIST control could be retrieved for this risk.</p>`;

  const caveatsHtml = risk.warnings.length
    ? `<div class="caveats"><strong>Caveats on this finding</strong><ul>` +
      risk.warnings.map((w) => `<li>${esc(w)}</li>`).join("") +
      `</ul></div>`
    : "";

  const advisoryHtml = risk.advisory
    ? `<div class="advisory-quote">` +
      `<div class="ah">Named in this morning's MDR advisory</div>` +
      `<strong>${esc(risk.advisory.actor)}</strong>, campaign "${esc(risk.advisory.campaign)}". ` +
      `${esc(risk.advisory.body)}` +
      `<div class="chain">Exploit chain: ${esc(risk.advisory.exploit_chain)}<br />` +
      `Ransomware: ${esc(risk.advisory.ransomware || "not stated")}</div></div>`
    : "";

  const hintHtml = risk.hint
    ? `<div class="hint-box">` +
      `<div class="hh">Security team's own note <span class="prio">${esc(risk.hint.priority_hint)}</span></div>` +
      `<strong>${esc(risk.hint.finding_type)}</strong>` +
      `<p>${esc(risk.hint.recommended_action)}</p>` +
      `<div class="ev">Evidence expected at closure: ${esc(risk.hint.validation_evidence)}</div>` +
      `<div class="ev">From remediation_guidance.csv, a starting point rather than the authority. ` +
      `The controlling requirement is the NIST control above.</div></div>`
    : "";

  const narrativeTag =
    risk.narrative.source === "model"
      ? `<span class="pill neutral">written by ${esc(risk.narrative.provider)}/${esc(risk.narrative.model)}</span>`
      : `<span class="pill neutral">composed from evidence</span>`;

  const card = el("article", { class: "risk" });
  card.innerHTML =
    `<div class="risk-head">` +
    `<div class="rank">${risk.rank}</div>` +
    `<div style="min-width:0">` +
    `<h3>${esc(risk.title)}</h3>` +
    `<div class="risk-sub">` +
    `<span class="pill ${bandClass(risk.band)}">${esc(risk.band)}</span>` +
    (risk.vulnerabilities.some((v) => v.in_kev) ? `<span class="pill kev">CISA KEV</span>` : "") +
    `<span>${esc(risk.business_service)}</span><span>&middot;</span>` +
    `<span>${plural(risk.assets.length, "asset")}</span><span>&middot;</span>` +
    `<span>${plural(risk.vulnerabilities.length, "finding")}</span>` +
    `</div></div>` +
    `<div class="score-box"><div class="n">${risk.score.toFixed(1)}</div><div class="of">of 100</div></div>` +
    `</div>` +
    `<div class="risk-body">` +
    `<div class="facts">` +
    `<div class="fact"><div class="label">Asset</div><div class="value"><ul>${assetList}</ul></div></div>` +
    `<div class="fact"><div class="label">Vulnerability</div><div class="value"><ul>${vulnList}</ul></div></div>` +
    `<div class="fact"><div class="label">Matched threat intel</div><div class="value"><ul>${intelHtml}</ul></div></div>` +
    `<div class="fact"><div class="label">Business service at risk</div><div class="value">${serviceHtml}</div></div>` +
    `</div>` +
    advisoryHtml +
    `<div class="why"><div class="label">Why this ranks here ${narrativeTag}</div>${esc(risk.narrative.why)}</div>` +
    `<h4 class="section">Score breakdown</h4>` +
    `<div class="factors">${factorsHtml}${amplifierHtml}</div>` +
    `<h4 class="section">Remediation guidance, retrieved from NIST SP 800-53 Rev. 5` +
    (risk.control_selection && risk.control_selection.used_model
      ? ` &middot; <span style="text-transform:none;letter-spacing:0;color:var(--accent)">order chosen by ${esc(risk.control_selection.model)}</span>`
      : ``) +
    `</h4>` +
    (risk.control_selection && risk.control_selection.reason
      ? `<p class="note" style="margin-bottom:9px">${esc(risk.control_selection.reason)}</p>`
      : ``) +
    controlsHtml +
    `<p style="font-size:13.5px;color:#c4cfdd">${esc(risk.narrative.remediation)}</p>` +
    hintHtml +
    caveatsHtml +
    `</div>`;
  return card;
}

/* ------------------------------------------------------------------ views */

function viewRisks() {
  const wrap = el("div");

  if (store.analysis.weights_are_default === false) {
    const changed = store.analysis.weights_changed || {};
    const parts = Object.keys(changed)
      .map((k) => `${k.replace(/^cap_/, "")} ${changed[k].default} to ${changed[k].current}`)
      .slice(0, 6);
    const note = el("div", { class: "tuned-note" });
    const text = el("span");
    text.innerHTML =
      `<strong>Custom weighting in use.</strong> ` +
      esc(parts.join("; ")) +
      (Object.keys(changed).length > 6 ? ", and more" : "") +
      `. This is not the published default model.`;
    const undo = el("button", { type: "button", text: "Reset to default" });
    undo.addEventListener("click", async () => {
      store.weights = {};
      persistWeights();
      await applyWeights();
    });
    note.appendChild(text);
    note.appendChild(undo);
    wrap.appendChild(note);
  }
  const note = el("p", { class: "note" });
  const src = store.analysis.narrative_source || "deterministic";
  note.innerHTML =
    src === "model"
      ? `Narratives were written by a language model, constrained to the retrieved evidence and checked for fabricated control and CVE citations. Ranking and control retrieval are deterministic.`
      : `Narratives are composed from the scored evidence with no language model. Add an API key and press <strong>Generate with AI</strong> for model written prose. Ranking never uses a model either way.`;
  wrap.appendChild(note);
  store.analysis.risks.forEach((risk) => wrap.appendChild(riskCard(risk)));
  return wrap;
}

function viewRanking() {
  const rows = store.analysis.ranked;
  const wrap = el("div");
  wrap.appendChild(
    el("p", {
      class: "note",
      html:
        `All ${rows.length} findings, ranked by the same model. The top 5 above are these rows ` +
        `grouped by campaign and business service, so one intrusion is reported once rather than ` +
        `once per affected appliance.`,
    })
  );
  const body = rows
    .map(
      (r) =>
        `<tr><td class="num">${r.rank}</td>` +
        `<td class="num">${r.score.toFixed(1)}</td>` +
        `<td><span class="pill ${bandClass(r.band)}">${esc(r.band)}</span></td>` +
        `<td class="num">${r.cvss.toFixed(1)}</td>` +
        `<td>${esc(r.vuln_id)}</td>` +
        `<td>${esc(r.cve)}${r.in_kev ? ' <span style="color:var(--critical)">KEV</span>' : ""}</td>` +
        `<td class="wrap">${esc(r.name)}</td>` +
        `<td>${esc(r.asset_name)}${r.internet_exposed ? "" : ' <span style="color:var(--dim)">(internal)</span>'}</td>` +
        `<td>${esc(r.business_service)}</td></tr>`
    )
    .join("");
  const table = el("div", { class: "table-wrap" });
  table.innerHTML =
    `<table><thead><tr><th>#</th><th>Score</th><th>Band</th><th>CVSS</th><th>Finding</th>` +
    `<th>CVE</th><th class="wrap">Vulnerability</th><th>Asset</th><th>Service</th></tr></thead>` +
    `<tbody>${body}</tbody></table>`;
  wrap.appendChild(table);
  return wrap;
}

function viewIntel() {
  const rows = store.analysis.unmatched_intel;
  const wrap = el("div");
  wrap.appendChild(
    el("p", {
      class: "note",
      html:
        `${rows.length} of ${store.analysis.summary.intel_records} threat intel records reference ` +
        `vulnerabilities or techniques with no match in TawasolPay's inventory. They contributed ` +
        `<strong>nothing</strong> to any score. They are listed because "we checked and it does not ` +
        `affect us" is itself a finding, and because silently dropping them would hide a whole ` +
        `class of ingest bug.`,
    })
  );
  const body = rows
    .map(
      (r) =>
        `<tr><td>${esc(r.intel_id)}</td><td>${esc(r.threat_actor)}</td>` +
        `<td>${esc(r.campaign_name)}</td><td>${esc(r.matched_cve)}</td>` +
        `<td>${esc(r.target_sector)}</td><td>${esc(r.target_region)}</td>` +
        `<td>${r.ransomware_association ? "yes" : "no"}</td>` +
        `<td>${esc(r.confidence)}</td></tr>`
    )
    .join("");
  const table = el("div", { class: "table-wrap" });
  table.innerHTML =
    `<table><thead><tr><th>ID</th><th>Actor</th><th>Campaign</th><th>Reference</th>` +
    `<th>Sector</th><th>Region</th><th>Ransomware</th><th>Confidence</th></tr></thead>` +
    `<tbody>${body}</tbody></table>`;
  wrap.appendChild(table);
  return wrap;
}

function viewQuality() {
  const dq = store.analysis.summary.data_quality;
  const wrap = el("div");
  wrap.appendChild(
    el("p", {
      class: "note",
      html:
        `${dq.total} problems found in the source records during ingest, ${dq.warnings} of them ` +
        `warnings. Each one is a concrete reason a finding above could be wrong, which is why they ` +
        `are surfaced next to the analysis rather than logged and forgotten.`,
    })
  );
  const body = dq.issues
    .map(
      (i) =>
        `<tr><td>${esc(i.kind.replace(/_/g, " "))}</td>` +
        `<td><span class="pill ${i.severity === "warning" ? "high" : "neutral"}">${esc(i.severity)}</span></td>` +
        `<td>${esc(i.subject)}</td><td class="wrap">${esc(i.message)}</td></tr>`
    )
    .join("");
  const table = el("div", { class: "table-wrap" });
  table.innerHTML =
    `<table><thead><tr><th>Issue</th><th>Severity</th><th>Record</th><th class="wrap">Detail</th></tr></thead>` +
    `<tbody>${body}</tbody></table>`;
  wrap.appendChild(table);
  return wrap;
}

function viewNist() {
  const wrap = el("div");
  wrap.appendChild(
    el("p", {
      class: "note",
      html:
        `Search the NIST SP 800-53 Rev. 5 catalogue directly, over the same ` +
        `${store.analysis.retrieval.chunks} passages the risk briefs retrieve from. ` +
        `Mode: <strong>${esc(store.analysis.retrieval.mode)}</strong>` +
        (store.analysis.retrieval.embedding_model
          ? ` (${esc(store.analysis.retrieval.embedding_model)}, ${store.analysis.retrieval.dimensions} dimensions, fused with BM25).`
          : ` (lexical only).`),
    })
  );

  const input = el("input", {
    type: "search",
    placeholder: "for example: containing ransomware after initial access",
    value: (store.nist && store.nist.query) || "",
  });
  const button = el("button", { class: "btn primary", type: "button", text: "Search" });
  const results = el("div");

  async function run() {
    const q = input.value.trim();
    if (q.length < 3) return;
    button.disabled = true;
    results.innerHTML = `<p class="note">Searching...</p>`;
    try {
      const data = await api("/nist/search?q=" + encodeURIComponent(q) + "&limit=6");
      store.nist = data;
      results.innerHTML = data.controls.length
        ? data.controls
            .map(
              (c) =>
                `<div class="control">` +
                `<div><span class="cid">${esc(c.identifier)}</span> <span class="cname">${esc(c.name)}</span></div>` +
                `<div class="cmeta">${esc(c.family_name)}${c.is_enhancement ? " &middot; control enhancement" : ""}</div>` +
                `<blockquote>${esc(c.excerpt)}</blockquote></div>`
            )
            .join("")
        : `<p class="note">Nothing matched.</p>`;
    } catch (err) {
      results.innerHTML = `<p class="note">${esc(err.message)}</p>`;
    } finally {
      button.disabled = false;
    }
  }

  button.addEventListener("click", run);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") run();
  });

  wrap.appendChild(el("div", { class: "search-row" }, [input, button]));
  wrap.appendChild(results);
  if (store.nist) {
    input.value = store.nist.query;
    run();
  }
  return wrap;
}

function viewMethod() {
  const r = store.analysis.retrieval;
  const wrap = el("div", { class: "prose" });
  wrap.innerHTML = `
    <h3>What gets queried, and what gets embedded</h3>
    <p>
      Assets, vulnerabilities, threat intelligence, business services and the CISA KEV
      catalogue are <strong>queried as structured records</strong>. They have stable schemas
      and exact join keys (<code>asset_id</code>, <code>cve</code>, <code>business_service</code>),
      and the ranking depends on comparing their numbers exactly. Embedding them would turn a
      reliable join into a similarity guess and make the ranking impossible to audit.
    </p>
    <p>
      Only the <strong>NIST SP 800-53 prose is embedded</strong>, because there is no key that
      joins "an internet facing payment gateway with no EDR" to a control id. That mapping is
      semantic, which is exactly what embeddings are for. The catalogue's 1,189 controls are
      chunked into ${r.chunks} passages.
    </p>

    <h3>Retrieval</h3>
    <p>
      Dense cosine similarity over ${r.dimensions || 384} dimension vectors
      ${r.embedding_model ? `from <code>${esc(r.embedding_model)}</code>` : ""}, fused with BM25
      by reciprocal rank fusion. Ranks are fused rather than scores because a cosine sits in
      [-1, 1] while BM25 is unbounded, so there is no honest way to add them. Lexical search is
      not just a fallback: control identifiers and fixed phrases such as "flaw remediation" are
      rare, precise tokens that BM25 weights heavily and a dense model tends to smooth over.
    </p>
    <p>
      The index is a plain numpy matrix, not Chroma or FAISS. At ${r.chunks} passages a full
      exact scan is a single matrix multiply taking well under a millisecond; an approximate
      index would add a dependency and an approximation to make an already instant search
      slower and less accurate. At a hundred times this size that trade would flip.
    </p>

    <h3>Where the language model is, and is not</h3>
    <p>
      <strong>Not</strong> in the ranking. Scores, evidence and control retrieval are entirely
      deterministic, so the same data always produces the same top 5 and every point is
      traceable to a named record. A model only rewrites the prose, constrained to the supplied
      evidence, and anything it writes is checked: a sentence citing a NIST control that was not
      retrieved, or a CVE not attached to the risk, is dropped and the drop is reported.
    </p>

    <h3>The scoring model</h3>
    <p>Six factors, each capped, summed and normalised to 0 to 100:</p>
    <ul>
      <li><strong>Active exploitation (30)</strong> - presence in CISA KEV, known ransomware use, public exploit, intel exploit maturity.</li>
      <li><strong>Internet exposure (22)</strong> - reachability, and whether exploitation needs credentials.</li>
      <li><strong>Threat campaign match (20)</strong> - a named actor targeting this sector and region, weighted down when the target profile only partly matches.</li>
      <li><strong>Business impact (20)</strong> - revenue, customer exposure, compliance scope, recovery objective, and how many other services depend on this one.</li>
      <li><strong>Missing controls (12)</strong> - no EDR, no patch, age of the finding, stale inventory, no assigned owner.</li>
      <li><strong>CVSS (10)</strong> - technical severity, deliberately capped at under 9% of the raw total.</li>
    </ul>
    <p>
      That cap is the point. The brief requires a CVSS 10 on an internal development box to rank
      below a CVSS 8 on an internet facing payment gateway under an active campaign, and a model
      that let severity dominate could not do that. In this dataset the highest CVSS findings on
      internal development servers land around rank 25, and a pure CVSS ordering would promote a
      CVSS 10 that this model scores in the thirties.
    </p>
  `;
  return wrap;
}

function viewAdvisory() {
  const adv = store.analysis.advisory || { campaigns: [] };
  const wrap = el("div");
  wrap.appendChild(
    el("p", {
      class: "note",
      html:
        `The MDR advisory is ingested, not just stored. Each campaign's exploit chain ` +
        `is parsed for identifiers, and a finding whose identifier appears here scores ` +
        `additional campaign points and carries the analyst's own paragraph as evidence. ` +
        `That matters most for the pack's synthetic identifiers: ` +
        `<code>CVE-SYN-2026-0011</code> can never appear in CISA KEV, so without the ` +
        `advisory there would be nothing to confirm WinterViper is actively exploiting it.`,
    })
  );
  adv.campaigns.forEach((c) => {
    const inEstate = (c.identifiers || []).filter((i) =>
      (store.analysis.ranked || []).some((r) => r.cve === i)
    );
    const card = el("div", { class: "control" });
    card.innerHTML =
      `<div><span class="cname">${esc(c.actor)}</span>, campaign "${esc(c.campaign)}"</div>` +
      `<div class="cmeta">${esc(c.target_profile)}</div>` +
      `<blockquote>${esc(c.body)}</blockquote>` +
      `<div class="cmeta" style="margin-top:8px">` +
      `Exploit chain: <span style="font-family:var(--mono)">${esc(c.exploit_chain)}</span><br />` +
      `Ransomware: ${esc(c.ransomware || "not stated")}<br />` +
      `Confidence: ${esc(c.confidence || "not stated")}<br />` +
      `Identifiers present in this estate: ` +
      (inEstate.length
        ? `<strong style="color:var(--critical)">${esc(inEstate.join(", "))}</strong>`
        : `none`) +
      `</div>`;
    wrap.appendChild(card);
  });
  return wrap;
}

const VIEWS = {
  risks: viewRisks,
  ranking: viewRanking,
  intel: viewIntel,
  quality: viewQuality,
  advisory: viewAdvisory,
  nist: viewNist,
  method: viewMethod,
};

function render() {
  const view = $("#view");
  view.innerHTML = "";
  if (!store.analysis) {
    view.appendChild(el("div", { class: "loading", text: "Loading analysis..." }));
    return;
  }
  view.appendChild(VIEWS[store.view]());
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.view === store.view);
  });
}


/* ----------------------------------------------------------- tuning panel */

/* Presets are shortcuts to a point of view, not new logic. Each one is just a
   set of weight overrides, and every one is reachable by moving sliders. */
const PRESETS = {
  "Published default": {},
  "Ignore CVSS entirely": { cap_cvss: 0 },
  "CVSS only": {
    cap_exploitability: 0,
    cap_exposure: 0,
    cap_campaign: 0,
    cap_business_impact: 0,
    cap_missing_controls: 0,
  },
  "Business impact first": { cap_business_impact: 40, cap_cvss: 4 },
  "Active exploitation first": { cap_exploitability: 45, cap_campaign: 28, cap_cvss: 4 },
  "One per asset, top 10": { top_n: 10, max_risks_per_service: 3 },
};

function weightValue(field) {
  if (Object.prototype.hasOwnProperty.call(store.weights, field)) return store.weights[field];
  return store.weightSchema.defaults[field];
}

function tuneRow(field, label, sublabel, max) {
  const def = store.weightSchema.defaults[field];
  const value = weightValue(field);
  const row = el("div", { class: "tune-row" + (Number(value) === 0 ? " off" : "") });

  const title = el("div", { class: "tl" });
  title.innerHTML = esc(label) + (sublabel ? `<small>${esc(sublabel)}</small>` : "");

  const slider = el("input", {
    type: "range",
    min: "0",
    max: String(max),
    step: max <= 25 ? "1" : "1",
    value: String(value),
  });
  const out = el("output", {
    class: Number(value) !== Number(def) ? "changed" : "",
    text: String(value),
  });

  slider.addEventListener("input", () => {
    const next = Number(slider.value);
    out.textContent = String(next);
    out.className = next !== Number(def) ? "changed" : "";
    row.classList.toggle("off", next === 0);
    if (next === Number(def)) delete store.weights[field];
    else store.weights[field] = next;
  });

  row.appendChild(title);
  row.appendChild(slider);
  row.appendChild(out);
  return row;
}

function openTuningPanel() {
  const schema = store.weightSchema;
  const body = el("div");

  body.appendChild(
    el("div", {
      class: "tune-intro",
      html:
        `Every number in the ranking is on this panel. <strong>Setting a factor to 0 ` +
        `removes it entirely</strong>: it leaves both the score and the total it is ` +
        `measured against, so the remaining factors still span 0 to 100 and the ` +
        `results stay comparable.<br /><br />` +
        `Re-ranking is deterministic and needs no API key.`,
    })
  );

  const presets = el("div", { class: "preset-row" });
  Object.keys(PRESETS).forEach((name) => {
    const button = el("button", { class: "preset", type: "button", text: name });
    button.addEventListener("click", async () => {
      store.weights = Object.assign({}, PRESETS[name]);
      persistWeights();
      closeModal();
      await applyWeights();
    });
    presets.appendChild(button);
  });
  body.appendChild(el("h4", { class: "section", text: "Presets" }));
  body.appendChild(presets);

  body.appendChild(el("h4", { class: "section", text: "Factor ceilings" }));
  schema.factors.forEach((factor) => {
    const wrap = el("div", { class: "tune-factor" });
    wrap.appendChild(
      tuneRow(factor.cap_field, factor.label, `default ${factor.cap_default}`, 50)
    );
    if (factor.signals.length) {
      const details = el("details", { class: "tune-signals" });
      details.appendChild(
        el("summary", { text: `Individual signals inside ${factor.label.toLowerCase()}` })
      );
      factor.signals.forEach((sig) => {
        details.appendChild(tuneRow(sig.field, sig.label, "", 20));
      });
      wrap.appendChild(details);
    }
    body.appendChild(wrap);
  });

  body.appendChild(el("h4", { class: "section", text: "Grouping and output" }));
  schema.grouping.forEach((g) => body.appendChild(tuneRow(g.field, g.label, "", 15)));
  schema.output.forEach((o) =>
    body.appendChild(tuneRow(o.field, o.label, "", o.field === "top_n" ? 25 : 10))
  );

  body.appendChild(el("h4", { class: "section", text: "Band thresholds" }));
  schema.bands.forEach((b) => body.appendChild(tuneRow(b.field, b.label, "", 100)));

  const apply = el("button", { class: "btn primary", type: "button", text: "Apply and re-rank" });
  const reset = el("button", { class: "btn ghost", type: "button", text: "Reset to default" });
  apply.addEventListener("click", async () => {
    persistWeights();
    closeModal();
    await applyWeights();
  });
  reset.addEventListener("click", async () => {
    store.weights = {};
    persistWeights();
    closeModal();
    await applyWeights();
  });
  const actions = el("div", { class: "tune-actions" }, [apply, reset]);
  body.appendChild(actions);

  showModal("Tune the scoring model", body);
}

async function applyWeights() {
  const button = $("#tuneBtn");
  button.disabled = true;
  button.textContent = "Re-ranking...";
  try {
    await loadAnalysis();
    toast(
      "ok",
      hasCustomWeights() ? "Re-ranked with your weights" : "Back to the default model",
      hasCustomWeights() ? `${Object.keys(store.weights).length} value(s) changed.` : ""
    );
  } catch (err) {
    toast("error", err.message, err.hint || "");
  } finally {
    button.disabled = false;
    button.textContent = "Tune weights";
  }
}

/* ------------------------------------------------------------ key manager */

const KEY_HELP = {
  gemini: "Free tier at Google AI Studio. Generous daily quota.",
  groq: "Free and very fast. Llama and GPT OSS models.",
  openrouter: "Has a number of models that are free to call.",
  omnirouter: "OpenAI compatible gateway fronting many providers.",
  cloudflare: "Workers AI. Needs both an API token and your account id, because the account id is part of the request URL.",
  huggingface: "Inference router. The token needs inference permission.",
  openai: "Also works with Ollama, LM Studio, vLLM or any OpenAI compatible gateway, if you set its base URL below.",
};

function keyRow(provider) {
  const row = el("div", { class: "keyrow" });
  const badge =
    provider.key_source === "client"
      ? `<span class="pill low">your key</span>`
      : provider.key_source === "server"
      ? `<span class="pill neutral">provided by host</span>`
      : `<span class="pill neutral">no key</span>`;

  const head = el("div", { class: "kh" });
  head.innerHTML =
    `<strong>${esc(provider.label)}</strong>${badge}` +
    (provider.docs_url ? ` <a href="${esc(provider.docs_url)}" target="_blank" rel="noreferrer noopener">get a key</a>` : "");
  row.appendChild(head);
  row.appendChild(el("div", { class: "cmeta", style: "font-size:12px;color:var(--dim);margin-bottom:7px", text: KEY_HELP[provider.id] || "" }));

  const input = el("input", {
    type: "password",
    placeholder: provider.key_source === "server" ? "Host key in use. Paste your own to override." : "Paste your API key",
    value: store.keys[provider.id] || "",
  });
  const save = el("button", { class: "btn primary", type: "button", text: "Save and test" });
  const remove = el("button", { class: "btn ghost", type: "button", text: "Remove" });
  const status = el("div", { class: "status" });

  save.addEventListener("click", async () => {
    const value = input.value.trim();
    if (!value) {
      status.className = "status err";
      status.textContent = "Paste a key first.";
      return;
    }
    setKey(provider.id, value);
    save.disabled = true;
    status.className = "status";
    status.textContent = "Checking with " + provider.label + "...";
    try {
      const result = await api("/providers/verify", { json: { provider: provider.id } });
      await refreshConfig();
      status.className = "status ok";
      status.textContent = plural(result.callable_models, "model") + " callable with this key.";
      toast("ok", provider.label + " connected", "Press Generate with AI to rewrite the narratives.");
    } catch (err) {
      /* A key the provider rejected is dropped, so the app does not keep
         sending a bad credential with every later request. */
      setKey(provider.id, "");
      status.className = "status err";
      status.textContent = err.hint || err.message;
    } finally {
      save.disabled = false;
    }
  });

  remove.addEventListener("click", async () => {
    setKey(provider.id, "");
    setBase(provider.id, "");
    setAccount(provider.id, "");
    input.value = "";
    await refreshConfig();
    status.className = "status";
    status.textContent = "Removed.";
    openKeyManager();
  });

  row.appendChild(el("div", { class: "kf" }, [input, save, remove]));

  if (provider.needs_account) {
    const accountInput = el("input", {
      type: "text",
      placeholder: "Account id (32 hex characters, from your Cloudflare dashboard)",
      value: store.accounts[provider.id] || "",
    });
    accountInput.addEventListener("change", () => {
      const value = accountInput.value.trim();
      if (value && !/^[0-9a-zA-Z]{8,64}$/.test(value)) {
        status.className = "status err";
        status.textContent = "An account id is letters and digits only.";
        return;
      }
      setAccount(provider.id, value);
      status.className = "status ok";
      status.textContent = value ? "Account id saved. Now press Save and test." : "Account id cleared.";
    });
    row.appendChild(el("div", { class: "kf", style: "margin-top:7px" }, [accountInput]));
  }

  if (provider.accepts_base_url) {
    const details = el("details");
    const baseInput = el("input", {
      type: "text",
      placeholder: "https://your-gateway.example/v1",
      value: store.bases[provider.id] || "",
    });
    baseInput.addEventListener("change", () => {
      const value = baseInput.value.trim();
      if (value && !/^https:\/\//i.test(value)) {
        status.className = "status err";
        status.textContent = "The base URL must start with https://";
        return;
      }
      setBase(provider.id, value);
      status.className = "status ok";
      status.textContent = value ? "Gateway set." : "Gateway cleared.";
    });
    details.appendChild(el("summary", { text: "Advanced: point this provider at another gateway" }));
    details.appendChild(el("div", { class: "kf", style: "margin-top:7px" }, [baseInput]));
    row.appendChild(details);
  }

  row.appendChild(status);
  return row;
}

function openKeyManager() {
  const body = el("div");
  body.appendChild(
    el("div", {
      class: "privacy",
      html:
        `The analysis, the ranking and the NIST retrieval all work with <strong>no key at all</strong>. ` +
        `A key only upgrades the written narrative from a composed template to model prose.<br /><br />` +
        `A key you paste here is held in this browser, sent as a request header with your own ` +
        `requests only, and never stored on the server or written to a log.`,
    })
  );
  const toggle = el("div", { class: "toggle-row" });
  const box = el("input", { type: "checkbox", id: "rerankToggle" });
  box.checked = store.rerank;
  box.addEventListener("change", () => {
    store.rerank = box.checked;
    localStorage.setItem("cra.rerank", box.checked ? "1" : "0");
  });
  const label = el("label", { for: "rerankToggle" });
  label.innerHTML =
    `Let the model reorder the retrieved NIST controls` +
    `<small>Retrieval still decides which controls are admissible. The model only ` +
    `ranks that shortlist by applicability and cannot introduce one of its own, so ` +
    `the guidance still comes from the document.</small>`;
  toggle.appendChild(box);
  toggle.appendChild(label);
  body.appendChild(el("h4", { class: "section", text: "Control selection" }));
  body.appendChild(toggle);

  body.appendChild(el("h4", { class: "section", text: "Providers" }));
  (store.config.providers || []).forEach((p) => body.appendChild(keyRow(p)));
  const clear = el("button", { class: "btn ghost", type: "button", text: "Remove all keys" });
  clear.addEventListener("click", async () => {
    store.keys = {};
    store.bases = {};
    store.accounts = {};
    persistKeys();
    await refreshConfig();
    openKeyManager();
    toast("ok", "All keys removed");
  });
  body.appendChild(el("div", { style: "margin-top:14px" }, [clear]));
  showModal("API keys", body);
}

function showModal(title, body) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = "";
  $("#modalBody").appendChild(body);
  $("#modal").hidden = false;
}

function closeModal() {
  $("#modal").hidden = true;
}

/* ------------------------------------------------------------------- boot */

function renderBanner() {
  const banner = $("#banner");
  const cfg = store.config;
  const a = store.analysis;

  const problems = [];
  if (a && a.retrieval.mode === "lexical") {
    problems.push(
      "Semantic retrieval is unavailable on this instance, so NIST guidance is being found by lexical search only."
    );
  }
  if (a && a.kev && a.kev.age_days !== null && a.kev.age_days > 30) {
    problems.push(
      `The CISA KEV snapshot is ${a.kev.age_days} days old, so a CVE added since then will not be flagged as exploited.`
    );
  }

  if (problems.length) {
    banner.className = "banner warn";
    banner.innerHTML = problems.map(esc).join(" ");
    banner.hidden = false;
    return;
  }
  if (cfg && cfg.byok_only && !Object.keys(store.keys).length) {
    banner.className = "banner";
    banner.innerHTML =
      `This deployment ships no AI keys, and it does not need any: the full ranking and the ` +
      `NIST guidance below are already computed. Add your own key under <strong>API keys</strong> ` +
      `only if you want the narratives rewritten by a model.`;
    banner.hidden = false;
    return;
  }
  banner.hidden = true;
}

async function refreshConfig() {
  store.config = await api("/config");
  renderBanner();
  return store.config;
}

async function loadAnalysis() {
  /* A custom weighting needs the POST form, because the ranking has to be
     re-derived rather than read from the default cache. */
  store.analysis = hasCustomWeights()
    ? await api("/analysis", { json: weightBody() })
    : await api("/analysis");
  renderStats();
  renderBanner();
  render();
}

async function generateWithAi() {
  const button = $("#briefBtn");
  if (!store.config.any_provider) {
    openKeyManager();
    toast("warn", "No AI provider available", "Paste a key for any provider to use this.");
    return;
  }
  button.disabled = true;
  button.textContent = "Generating...";
  try {
    const data = await api("/analysis/brief", {
      json: weightBody({
        provider: store.provider || null,
        model: store.model || null,
        rerank_controls: store.rerank,
      }),
    });
    store.analysis = data;
    renderStats();
    render();
    const errors = data.narrative_errors || [];
    if (data.narrative_source === "model") {
      toast("ok", "Narratives rewritten", errors.length ? `${errors.length} fell back to the composed text.` : "");
    } else {
      toast("error", "Model narratives were not used", errors[0] || "Every attempt fell back to the composed text.");
    }
  } catch (err) {
    toast("error", err.message, err.hint || "");
  } finally {
    button.disabled = false;
    button.textContent = "Generate with AI";
  }
}

async function downloadBrief() {
  const button = $("#downloadBtn");
  button.disabled = true;
  try {
    const markdown = hasCustomWeights()
      ? await api("/report.md", { json: weightBody() })
      : await api("/report.md");
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: "tawasolpay-cyber-risk-brief.md" });
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    toast("error", err.message, err.hint || "");
  } finally {
    button.disabled = false;
  }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    store.view = tab.dataset.view;
    render();
  });
});

$("#keysBtn").addEventListener("click", openKeyManager);
$("#tuneBtn").addEventListener("click", () => {
  if (!store.weightSchema) {
    toast("warn", "Tuning model still loading", "Try again in a moment.");
    return;
  }
  openTuningPanel();
});
$("#briefBtn").addEventListener("click", generateWithAi);
$("#downloadBtn").addEventListener("click", downloadBrief);
$("#modalClose").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (e) => {
  if (e.target === $("#modal")) closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

(async function boot() {
  try {
    await refreshConfig();
    store.weightSchema = await api("/weights");
    $("#appName").textContent = store.config.app_name;
    $("#appTagline").textContent = store.config.tagline;
    document.title = store.config.app_name;
    await loadAnalysis();
  } catch (err) {
    $("#view").innerHTML = `<p class="note">${esc(err.message)} ${esc(err.hint || "")}</p>`;
  }
})();
