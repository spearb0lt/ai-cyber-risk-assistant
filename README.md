# AI-Powered Cyber Risk Assistant

Takes TawasolPay's data pack and produces a prioritised, explainable risk picture: a ranked
top 5 with evidence, matched threat intelligence, business impact, and remediation guidance
retrieved from the real NIST SP 800-53 Rev. 5 catalogue.

**Live:** <https://cyber-risk-assistant-8tun.onrender.com>
&nbsp;·&nbsp; [Brief as Markdown](https://cyber-risk-assistant-8tun.onrender.com/api/report.md)
&nbsp;·&nbsp; [API docs](https://cyber-risk-assistant-8tun.onrender.com/api/docs)

> Hosted on Render's free tier, which sleeps after 15 minutes idle. A first
> request after that wakes the instance and rebuilds the analysis, so allow
> about a minute. Every request after it is immediate.

> The deployed instance ships **no API keys and needs none**. Ranking, KEV cross-referencing
> and NIST retrieval are deterministic and run locally, so the complete brief is there on
> first load. A key only upgrades the written narrative from a composed template to model
> prose, and you can paste your own in the UI.

---

## What it does

| | |
|---|---|
| **Ingests** | 60 assets, 114 vulnerabilities, 40 threat intel records, 20 business services, 30 remediation hints, and the MDR advisory |
| **Cross-references** | the live CISA KEV catalogue (1,709 CVEs) by exact CVE id |
| **Retrieves** | NIST SP 800-53 Rev. 5 (1,189 controls, chunked to 1,602 passages) by hybrid dense + lexical search |
| **Produces** | a ranked top 5 with per-risk evidence, score breakdown, cited controls and caveats, as a dashboard and as Markdown |

Two things it deliberately also does, because leaving them out would be a quiet lie:

- **Reports the 16 threat intel records that do not match this estate.** They score zero.
  They are still listed, because "we checked and it does not affect us" is a finding.
- **Reports 6 data quality problems found during ingest** — an exposure contradiction, an
  ownerless asset, 3 stale assets, and 59 identifiers that are not real CVEs — next to the
  findings they affect.

---

## The top 5 it produces

Derived, not hardcoded. Each entry turns out to be one of the five campaigns named in the
MDR advisory, against a distinct business service:

| # | Score | Risk | Business service | Confirmed in KEV |
|---|---|---|---|---|
| 1 | 93.6 | CitrixBleed (CVE-2023-4966) on the payment load balancer | Payment Processing | yes, ransomware |
| 2 | 91.6 | CitrixBleed on the customer login load balancer | Customer Login | yes, ransomware |
| 3 | 90.7 | Fortinet SSL-VPN chain (CVE-2024-21762 → CVE-2024-55591) | Remote Access | yes, ransomware |
| 4 | 82.7 | Atlassian Jira/Confluence RCE chain | Software Delivery | yes, ransomware |
| 5 | 77.3 | TeamCity/Jenkins auth bypass and file read | DevOps Platform | yes |

---

## How the ranking works

Six factors, each capped, summed to a raw 114 and normalised to 0–100:

| Factor | Cap | What it measures |
|---|---:|---|
| Active exploitation | 30 | presence in CISA KEV, known ransomware use, public exploit, intel exploit maturity |
| Internet exposure | 22 | reachability, and whether exploitation needs credentials |
| Threat campaign match | 20 | a named actor targeting this sector and region, downweighted when the profile only partly matches |
| Business impact | 20 | revenue, customer exposure, compliance scope, recovery objective, and how many services depend on this one |
| Missing controls | 12 | no EDR, no patch, age of the finding, stale inventory, no assigned owner |
| **CVSS** | **10** | technical severity, capped at **under 9%** of the raw total |

**That CVSS cap is the whole point.** The brief requires a CVSS 10 on an internal dev server
to rank below a CVSS 8 on an internet-facing payment gateway under an active campaign. Over
this dataset:

- the highest-CVSS findings on internal development servers land at ranks **25, 26 and 73**
- a pure-CVSS ordering would promote **V-2089 (CVSS 10.0)**, which this model scores **37.2**
- `pearson(score, cvss) = 0.52` — correlated, because CVSS is real signal, but not governing

`tests/test_scoring.py` asserts each of these as a property of the output, not as a comment.

### Grouping: why the top 5 is not simply the five highest rows

Ungrouped, the five highest-scoring rows are four near-identical entries for the same
Fortinet exploit chain across a pair of VPN appliances. Accurate, and useless to brief: one
decision, one owner, one change window, reported four times.

So rows are collapsed into a risk when they describe **the same campaign against the same
business service**, and the number of distinct assets affected becomes an amplifier (+2 each,
capped at +6) rather than a repeat. The business service is the grouping unit because it is
what has an owner, a recovery objective and a compliance obligation — the thing a decision
attaches to. The full 114-row ranking is still available under **Full ranking** and `/api/risks`.

---

## Supporting question 1 — the data split

**Queried as structured records:** assets, vulnerabilities, threat intelligence, business
services, and the CISA KEV catalogue. Each has a stable schema and an exact join key
(`asset_id`, `cve`, `business_service`), and the ranking depends on comparing their fields
exactly — `internet_exposed`, `edr_installed`, `cvss`, `days_open`, `knownRansomwareCampaignUse`.
Embedding any of it would replace a deterministic join with a similarity guess, and a risk
score that cannot be traced back to a named record is not explainable, which was the point of
the exercise.

**Embedded:** only the NIST SP 800-53 prose. There is no key that joins "an internet-facing
payment gateway with no EDR and a 180-day-old finding" to a control identifier — that mapping
is genuinely semantic, and it is the one place in this system where approximate matching is
the right tool rather than a shortcut. The 1,189 controls are chunked into 1,602 passages
(median 670 characters, hard-capped at 1,500 so nothing is silently truncated by the
embedding model's 512-token window) and embedded with `BAAI/bge-small-en-v1.5`.

Retrieval fuses dense cosine with BM25 by reciprocal rank fusion. Ranks are fused rather than
scores because a cosine sits in [-1, 1] while BM25 is unbounded, so adding them directly would
be meaningless. Lexical search is not merely a fallback: control identifiers and fixed phrases
("flaw remediation", "boundary protection", "session authenticity") are rare, precise tokens
that BM25 weights heavily and a dense model tends to smooth over.

The index is a plain numpy matrix rather than Chroma, FAISS or Qdrant. At 1,602 × 384 floats
(2.3 MB) a full exact scan is one matrix multiply well under a millisecond; an ANN index would
add a dependency and an approximation in order to make an already-instant, already-exact
search slower and less accurate. At a hundred times this corpus size that trade flips, and the
`store.py` interface would not have to change.

---

## Supporting question 2 — three specific ways this produces wrong output

**1. 59 of the 79 distinct identifiers in `vulnerabilities.csv` are not real CVE ids, so KEV
cannot adjudicate them — and absence from KEV is not absence of exploitation.**
Only 29 of 114 findings resolve against the live KEV catalogue. `CVE-SYN-2026-0011` (the API
Admin Interface exposure that WinterViper is actively exploiting per the MDR advisory) will
never appear in KEV, so it forfeits the 14 points a KEV listing carries and can be ranked
below a real CVE that is objectively less urgent here. The same failure applies to any
genuine zero-day: real, exploited, not yet catalogued.
*What I did:* `Vulnerability.is_synthetic_id` distinguishes "not in KEV" from "cannot be
checked against KEV", and every affected finding carries an explicit caveat saying which. The
KEV snapshot's age is computed from its newest entry and shown in the UI, with a warning
banner past 30 days, because a stale snapshot fails silently and looks identical to a fresh
one. *What I would add:* a second corroborating source (NVD CVSS vectors, VulnCheck KEV,
EPSS probability) so exploitation evidence does not rest on one catalogue.

**2. `asset_exposure` in `vulnerabilities.csv` and `internet_exposed` in `assets.csv`
disagree, and exposure is worth 14 points.** V-2014 is recorded as `Internal` while its asset
A-1004 is `internet_exposed=Yes`. I resolve to the more severe reading, which is the safe
default but is a guess: if the vulnerability feed is right, that finding is over-ranked by 14
points and something genuinely exposed may be under-ranked below it.
*What I did:* the conflict is detected at ingest, reported in **Data quality**, and attached
as a caveat to the specific finding rather than resolved silently. *What I would add:* treat
disagreement as a third state rather than picking a winner — rank the finding under both
readings and surface the spread, so the reviewer sees the ranking is unstable there instead of
seeing a confident number.

**3. Grouping by campaign and business service can merge two things that need separate
decisions, or split one that needs a single decision.** CVE-2023-4966 appears as risks 1 and 2
because it hits two services with different owners — correct here, since the CFO and the Chief
Digital Officer act separately, but it spends two of five slots on one CVE. Conversely, a
finding with no matched intel groups by `affected_component`, so two genuinely different
weaknesses sharing a component string ("OpenSSH" covers 6 findings across 6 assets) can be
merged and the quieter one disappears from the brief entirely.
*What I did:* the diversity cap (`MAX_RISKS_PER_SERVICE`) is configurable, the amplifier is
bounded at +6 so blast radius cannot manufacture a top-5 entry, and the complete ungrouped
114-row ranking is one click away so nothing is only visible through the grouping.
*What I would add:* assert that no finding above a score threshold is absent from the brief
while being non-adjacent to anything in it, which would catch a merge that swallowed a
distinct risk.

Two more the system already guards against, since they are the obvious ones:
**the LLM citing a control it never retrieved** — `briefing/guard.py` drops any sentence
citing a NIST control outside the retrieved set or a CVE not attached to the risk, reports the
drop, and falls back to the composed narrative if the text does not survive; and
**threat intel that does not apply to this estate** — the 16 unmatched records contribute
exactly zero and are reported separately, with region and sector relevance downweighting
partial matches rather than counting them at full strength.

---

## Supporting question 3 — the one thing I would change

**Replace the hand-tuned factor weights with something calibrated, and show the uncertainty.**
The six caps (30/22/20/20/12/10) are defensible and reproduce the brief's own worked example,
but they are ultimately my judgement encoded as integers. The two highest risks sit 2.0 points
apart, which is well inside the noise those weights carry, and the brief presents that ordering
with a confidence the method does not earn. With another day I would (a) run a sensitivity
analysis — perturb each weight ±25% and report how often the top 5 membership changes, which
converts "these are the top 5" into "these 4 are stable under any reasonable weighting, and the
fifth slot is contested between these three"; and (b) fold in EPSS exploitation probability so
the exploitability factor rests on a published empirical estimate rather than on a binary KEV
membership plus a feed's own boolean. That is the biggest gap because everything else in the
system is auditable — every point traces to a named record — while the weights themselves are
the one input nobody can check.

---

## Running it locally

```bash
git clone https://github.com/spearb0lt/ai-cyber-risk-assistant.git
cd ai-cyber-risk-assistant

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. That is all that is required — no API key, no `.env`, no
external service. The reference snapshots and the vector index are committed.

To refresh the public reference documents and rebuild the index:

```bash
python scripts/fetch_reference_data.py   # CISA KEV + NIST SP 800-53
python scripts/build_index.py            # re-embed the catalogue
pytest                                   # 40 tests
```

### Optional: model-written narratives

Paste a key under **API keys** in the UI, or set one in `.env` (see `.env.example`):

| Provider | Free tier | Env var |
|---|---|---|
| Google Gemini | yes | `GEMINI_API_KEY` |
| Groq | yes | `GROQ_API_KEY` |
| OpenRouter | yes, 19 free models | `OPENROUTER_API_KEY` |
| OmniRouter | — | `OMNIROUTER_API_KEY` |
| Cloudflare Workers AI | yes | `CLOUDFLARE_API_TOKEN` **and** `CLOUDFLARE_ACCOUNT_ID` |
| OpenAI-compatible | Ollama, LM Studio, vLLM | `OPENAI_API_KEY` + `OPENAI_BASE_URL` |
| Hugging Face | yes | `HUGGINGFACE_API_KEY` |

`.env.example` lists the usable model ids for each provider, including every
current OpenRouter free model. Cloudflare needs both values because the account
id is part of the request URL, so the key panel renders a second field for it.

A caveat worth stating: OpenRouter's free models are individually unreliable.
Of the eight tested against a live key, most returned a 429, a 403, or their own
reasoning text instead of the JSON they were asked for. The picker therefore
orders free models ahead of paid ones and defaults to `nex-agi/nex-n2.5-mini:free`,
which was verified to return well formed JSON. When a model does fail, that risk
falls back to its composed narrative and the UI says so rather than showing a gap.

A key pasted in the UI is held in that browser, sent as an `X-LLM-Key-<provider>` header with
that visitor's own requests, and never stored on the server or written to a log. Provider
adapters are process-wide singletons, so the credential lives in a `contextvar` bound per
request — one visitor's key can never serve another's.

---

## Layout

```
app/
  ingest/      typed loaders for the 5 CSVs + advisory, and the data quality report
  reference/   CISA KEV lookup; NIST catalogue loader and chunker
  embeddings/  pluggable backends: local ONNX (default) or Gemini
  retrieval/   numpy vector store, BM25, and the RRF hybrid retriever
  scoring/     the six-factor engine, and campaign x service grouping
  briefing/    retrieval queries, grounding guard, narrative, Markdown report
  llm/         provider registry, per-request keyring, 7 adapters
  api/         FastAPI routes and the BYOK dependency
web/           dashboard, no build step
scripts/       fetch_reference_data.py, build_index.py
data/          dataset, reference snapshots, committed vector index
tests/         40 tests
```

### API

| Endpoint | |
|---|---|
| `GET /api/analysis` | full deterministic analysis, no key needed |
| `POST /api/analysis/brief` | same, narratives rewritten by a model |
| `GET /api/report.md` | the brief as Markdown |
| `GET /api/risks` | all 114 findings ranked |
| `GET /api/intel/unmatched` | the 16 intel records that do not apply |
| `GET /api/data-quality` | ingest problems found |
| `GET /api/nist/search?q=` | search the NIST catalogue directly |
| `GET /api/config`, `GET /api/health` | provider status, liveness |

---

## Deployment

Render free web service from the committed `Dockerfile` and `render.yaml`, in the Singapore
region. The embedding model is baked into the image at build time so a cold start does not
spend 30 seconds downloading weights, and the whole analysis is computed once in the FastAPI
`lifespan` rather than on first request, which moves the roughly 44 seconds of ingest,
scoring and retrieval into the cold start the platform is already waiting on.

Semantic retrieval does run on the free tier: the deployed instance reports
`"mode": "hybrid"` at `/api/config`, so ONNX inference fits inside the 512 MB
comfortably. The image is host-agnostic and runs unchanged anywhere Docker does.

## Sources

- CISA Known Exploited Vulnerabilities catalogue — <https://github.com/cisagov/kev-data>
- NIST SP 800-53 Rev. 5 control catalogue — <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads>
- TawasolPay data pack and MDR advisory, as supplied with the assignment (synthetic)
