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
| **Ingests** | 60 assets, 114 vulnerabilities, 40 threat intel records, 20 business services, 30 remediation hints, and the MDR advisory. All six files are used, not just parsed |
| **Cross-references** | the live CISA KEV catalogue (1,709 CVEs) by exact CVE id |
| **Retrieves** | NIST SP 800-53 Rev. 5 (1,189 controls, chunked to 1,602 passages) by hybrid dense + lexical search |
| **Produces** | a ranked top 5 with per-risk evidence, score breakdown, cited controls and caveats, as a dashboard and as Markdown |

Four things it deliberately also does, because leaving them out would be a quiet lie:

- **Reads the MDR advisory as evidence, not decoration.** Each campaign's exploit chain is
  parsed for identifiers; all 10 it names are present here, matching 19 open findings, which
  score extra and carry the analyst's own paragraph as quoted evidence. This is the only thing
  that corroborates `CVE-SYN-2026-0011`, a synthetic identifier that can never appear in KEV
  yet which the advisory says WinterViper is actively exploiting.
- **Uses `remediation_guidance.csv` as a hint, exactly as the brief frames it.** It is matched
  to 49 of 114 findings and shown as the team's operational starting point with its P0 to P2
  triage and its closing evidence, always beside the retrieved NIST control and never instead
  of it.
- **Reports the 16 threat intel records that do not match this estate.** They score zero.
  They are still listed, because "we checked and it does not affect us" is a finding.
- **Reports 25 data quality problems found during ingest**, an exposure contradiction, an
  ownerless asset, 3 stale assets, 59 identifiers that are not real CVEs, and 19 assets with no
  findings at all, next to the findings they affect. That last group matters most: an asset with
  no records is invisible in a report that only lists risks, and nothing in the pack says whether
  it was scanned and clean or never scanned.

---

## The top 5 it produces

Derived, not hardcoded. Each entry turns out to be one of the five campaigns named in the
MDR advisory, against a distinct business service:

| # | Score | Risk | Business service | In KEV | In advisory |
|---|---|---|---|---|---|
| 1 | 98.0 | CitrixBleed (CVE-2023-4966) on the payment load balancer | Payment Processing | yes, ransomware | yes |
| 2 | 96.0 | CitrixBleed on the customer login load balancer | Customer Login | yes, ransomware | yes |
| 3 | 90.7 | Fortinet SSL-VPN chain (CVE-2024-21762 then CVE-2024-55591) | Remote Access | yes, ransomware | yes |
| 4 | 82.7 | Atlassian Jira and Confluence RCE chain | Software Delivery | yes, ransomware | yes |
| 5 | 82.5 | TeamCity and Jenkins auth bypass and file read | DevOps Platform | yes | yes |

---

## How the ranking works

Six factors, each capped, summed to a raw 114 and normalised to 0 to 100:

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

- the highest-CVSS findings on internal development servers land at ranks **18, 19, 40 and 60**
- a pure-CVSS ordering would promote **V-2089 (CVSS 10.0)**, which this model scores **37.2**
- `pearson(score, cvss) = 0.53`, correlated, because CVSS is real signal, but not governing

`tests/test_scoring.py` asserts each of these as a property of the output, not as a comment.

### Every weight is adjustable, and any factor can be switched off

The six caps above are a judgement, and a judgement a reviewer cannot inspect or change is
indistinguishable from an arbitrary one. So all 50 numbers in the model are exposed: the six
factor ceilings, every individual signal inside them, the blast radius amplifier, the band
thresholds, and how many risks to report. **Tune weights** in the UI, or `POST /api/analysis`
with a `weights` object.

**Setting a factor to 0 removes it entirely.** It leaves the numerator and the denominator
together, so the remaining factors still span 0 to 100 and two tunings stay comparable rather
than one collapsing toward zero. Re-ranking is deterministic and needs no API key.

Presets in the panel make the point quickly. "CVSS only" reproduces the naive ranking the
brief warns against, and the difference from the default is the argument for the whole model.
A tuned ranking is labelled as such everywhere it appears, including in the exported Markdown,
so a custom weighting can never be mistaken for the published one.

### Grouping: why the top 5 is not simply the five highest rows

Ungrouped, the five highest-scoring rows are four near-identical entries for the same
Fortinet exploit chain across a pair of VPN appliances. Accurate, and useless to brief: one
decision, one owner, one change window, reported four times.

So rows are collapsed into a risk when they describe **the same campaign against the same
business service**, and the number of distinct assets affected becomes an amplifier (+2 each,
capped at +6) rather than a repeat. The business service is the grouping unit because it is
what has an owner, a recovery objective and a compliance obligation, the thing a decision
attaches to. The full 114-row ranking is still available under **Full ranking** and `/api/risks`.

---

## Supporting question 1, the data split

**Queried as structured records:** assets, vulnerabilities, threat intelligence, business
services, and the CISA KEV catalogue. Each has a stable schema and an exact join key
(`asset_id`, `cve`, `business_service`), and the ranking depends on comparing their fields
exactly, `internet_exposed`, `edr_installed`, `cvss`, `days_open`, `knownRansomwareCampaignUse`.
Embedding any of it would replace a deterministic join with a similarity guess, and a risk
score that cannot be traced back to a named record is not explainable, which was the point of
the exercise.

**Embedded:** only the NIST SP 800-53 prose. There is no key that joins "an internet-facing
payment gateway with no EDR and a 180-day-old finding" to a control identifier, that mapping
is genuinely semantic, and it is the one place in this system where approximate matching is
the right tool rather than a shortcut. The 1,189 controls are chunked into 1,602 passages
(median 670 characters, hard-capped at 1,500 so nothing is silently truncated by the
embedding model's 512-token window) and embedded with `BAAI/bge-small-en-v1.5`.

Retrieval fuses dense cosine with BM25 by reciprocal rank fusion. Ranks are fused rather than
scores because a cosine sits in [-1, 1] while BM25 is unbounded, so adding them directly would
be meaningless. Lexical search is not merely a fallback: control identifiers and fixed phrases
("flaw remediation", "boundary protection", "session authenticity") are rare, precise tokens
that BM25 weights heavily and a dense model tends to smooth over.

### Why the control is retrieved and not simply asked for

A language model could name a NIST control for any risk instantly, and it would usually be
right. The brief rules that out on purpose: guidance "must come from the actual NIST document,
not from the LLM's training data". The reason is not pedantry. A recalled control id is
indistinguishable on the page from a retrieved one, cites nothing, and is wrong often enough
to matter, and nobody reading the brief can tell which kind they are looking at.

Retrieval and recall are not the only options, though, and the system offers the third:
**optional model reranking, off by default**. Retrieval still decides which controls are
admissible, and the model is only allowed to reorder that shortlist and say why the first one
controls. It cannot add to the list; every id it returns is checked against the candidate set
and anything invented is dropped. The worst case is a worse ordering of correct controls,
never a fabricated one.

It earns its place because similarity and applicability are different questions. Cosine
distance matches "session token leak" to SC-23 Session Authenticity on vocabulary. Deciding
whether SC-23 or SI-2 is the *controlling* requirement for this particular asset is a reading
task, and a model does it better than a distance metric. Turn it on under **API keys**, and
each risk then shows which model chose the order and its one sentence reason.

### Why an exact index and not a vector database

The index is a plain numpy matrix rather than Chroma, FAISS or Qdrant. At 1,602 × 384 floats
(2.3 MB) a full exact scan is one matrix multiply well under a millisecond; an ANN index would
add a dependency and an approximation in order to make an already-instant, already-exact
search slower and less accurate. At a hundred times this corpus size that trade flips, and the
`store.py` interface would not have to change.

---

## Supporting question 2, three specific ways this produces wrong output

**1. Most of the identifiers here are not real CVE ids, so CISA KEV cannot judge them, and
"not in KEV" is not the same as "not being exploited".**

`vulnerabilities.csv` contains 79 distinct identifiers. Only 20 are real CVE ids such as
`CVE-2023-4966`. The other 59 are invented for this exercise: `CVE-SYN-2026-0011`,
`CICD-SYN-001`, `K8S-SYN-002`. CISA KEV is a real public catalogue of real CVEs, so looking up
an invented id returns nothing. The trap is that "nothing" has two completely different
meanings, and a naive system treats them the same:

- *CISA checked and it is not being exploited.* Genuinely reassuring.
- *CISA has no opinion, because this id does not exist to them.* Tells you nothing.

Reading the second as the first silently costs the finding the 14 points a KEV listing carries.
The concrete case is `CVE-SYN-2026-0011` on `partner-api-gateway-prod`: absent from KEV, so its
exploitation evidence sits at 12 of 30, while the MDR advisory says in plain English that
WinterViper is exploiting that exact weakness in the Gulf right now. This is not an artefact of
synthetic data. Every genuine zero-day has the same shape: real, exploited, not yet catalogued.

*What I did.* Two things, and the second was added after this problem was written up.
`Vulnerability.is_synthetic_id` separates "not in KEV" from "cannot be checked against KEV",
and every affected finding carries a caveat saying which one applies. Then the MDR advisory was
wired in as a second, independent source of exploitation evidence. It closes this specific case:
`CVE-SYN-2026-0011` now scores 71.3 with the full 20 of 20 campaign points, because the advisory
names it even though KEV cannot. The KEV snapshot's own age is also computed from its newest
entry and shown in the UI, with a warning past 30 days, since a stale catalogue fails silently
and looks identical to a fresh one.
*What is still open.* The advisory only covers the 10 identifiers it happens to name. The other
49 synthetic ids remain unverifiable by any external source, and a real zero-day absent from both
KEV and the advisory would still be under-scored. The fix is a third source, EPSS exploitation
probability or VulnCheck KEV, so no single catalogue's blind spot is the system's blind spot.

**2. The two files disagree about whether an asset is reachable from the internet, and that is
worth 14 points.**

Exposure is the second largest single signal in the model, and two different files assert it:

```
vulnerabilities.csv   V-2014   asset_exposure   = "Internal"
assets.csv            A-1004   internet_exposed = "Yes"        (payment-api-prod-02)
```

They cannot both be right. I resolve to the more severe reading and treat it as exposed, which
is the safe default but is still a guess. If the vulnerability feed is the accurate one, V-2014
is over-ranked by 14 points it did not earn, and something genuinely exposed sits below it. It
currently scores 38.5 with 14 of 22 exposure points that may be entirely unwarranted. One row
disagrees today; in a real estate of a hundred thousand findings this class of contradiction is
constant, and quietly picking a winner hides it.

*What I did.* The conflict is detected at ingest, listed under **Data quality**, and attached as
a caveat to that specific finding rather than resolved out of sight.
*What I would add.* Treat disagreement as a third state instead of picking a winner: score the
finding under both readings and show the spread, so a reader sees the ranking is unstable there
rather than a single confident number.

**3. An asset with no findings looks exactly like an asset that is safe, and 19 of the 60 are in
that position.**

This is the quietest failure of the three, and the most dangerous, because the other two
mis-rank something that is at least visible. This one makes things invisible.

The system reports risks. An asset with no vulnerability records produces no risks, so it never
appears anywhere in the brief. A reader would reasonably conclude those assets are fine. But
`assets.csv` has no column recording when an asset was last scanned, so **there is no way to tell
"scanned and clean" from "never scanned at all"**. Both are simply an absence of rows.

19 of the 60 assets are in this state, and five of them are not the sort you would want silently
omitted from a board brief:

```
A-1036  auth-gateway-staging   internet exposed
A-1031  compliance-db-prod     high criticality
A-1035  crm-db-prod            high criticality
A-1053  exec-laptop-cto        high criticality
A-1054  exec-laptop-ciso       high criticality
```

An internet-facing authentication gateway and the CISO's own laptop are absent from the risk
picture entirely, and nothing in the output says so.

*What I did.* Ingest now emits a `no_findings_recorded` issue for every one of them, raised to a
warning when the asset is internet exposed or high criticality, with wording that says the
absence is unverified rather than clean. They are listed under **Data quality**, so a reader sees
the 19 gaps beside the 5 ranked risks.
*What I would add.* Reporting a gap is weaker than closing one. The real fix is a scan coverage
field in the inventory, so the system can say "last scanned 3 days ago, clean" or "never scanned",
and then treat an unscanned internet-facing asset as a risk in its own right rather than a
footnote. That is a change to the data contract, not to the code.

Two further failure modes the system already guards against, since they are the obvious ones:
**a language model citing a control it never retrieved**, where `briefing/guard.py` drops any
sentence naming a NIST control outside the retrieved set or a CVE not attached to the risk,
reports the drop, and falls back to the composed narrative if nothing survives; and **threat
intel that does not apply to this estate**, where the 16 unmatched records contribute exactly
zero, are reported separately, and partial region or sector matches are downweighted rather than
counted at full strength.

## Supporting question 3, the one thing I would change

**Replace the hand-tuned weights with something calibrated, and show the uncertainty.** Making
every weight adjustable, which this now does, is only half an answer. **You can explore the
weights; you still cannot know which weighting is right.** The panel lets a reviewer move all 50
numbers and watch the top 5 reorder, but it offers no evidence about which arrangement is
correct, and the defaults remain my judgement encoded as integers.

The sharpest evidence is in this repository's own test suite. Risks 4 and 5 sit **0.2 points
apart**, and `test_the_briefs_own_example_holds` had to be narrowed to the brief's literal
wording because a looser reading of it fails: CVE-2024-23897 on an internal development build
server scores 63.9, about two points above a well patched internet facing Jira box at 62.0.
That ordering is defensible, the dev server is KEV confirmed and named in today's advisory as
part of a campaign explicitly targeting CI/CD, but a two point margin is well inside the noise
those weights carry, and the brief currently presents it with a confidence the method has not
earned.

There is one external check I have not used. The MDR advisory states its own recommended
priority order: internet exposure, then active exploitation, then ransomware association, then
business criticality, then missing compensating controls. My model leads with exploitation at 30
and exposure at 22, so it inverts the advisory's top two. That may well be the right call, since
KEV confirmation is harder evidence than reachability, but it is a disagreement with the one
authority in the data pack that expressed an opinion, and this README should not pass over it in
silence.

With another day I would, first, run a sensitivity sweep server side: perturb every weight by
plus or minus 25 per cent a few hundred times and report how often each risk stays in the top 5,
turning "these are the top 5" into "these three are stable under any reasonable weighting, and
the last two slots are contested between these four". Second, fold in EPSS exploitation
probability so the exploitability factor rests on a published empirical estimate rather than on
binary KEV membership plus a feed's own boolean. That is the biggest gap because everything else
is auditable, every point traces to a named record, while the weights themselves remain the one
input nobody can independently check.

## Running it locally

```bash
git clone https://github.com/spearb0lt/ai-cyber-risk-assistant.git
cd ai-cyber-risk-assistant

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. That is all that is required, no API key, no `.env`, no
external service. The reference snapshots and the vector index are committed.

To refresh the public reference documents and rebuild the index:

```bash
python scripts/fetch_reference_data.py   # CISA KEV + NIST SP 800-53
python scripts/build_index.py            # re-embed the catalogue
pytest                                   # 63 tests
```

### Optional: model-written narratives

Paste a key under **API keys** in the UI, or set one in `.env` (see `.env.example`):

| Provider | Free tier | Env var |
|---|---|---|
| Google Gemini | yes | `GEMINI_API_KEY` |
| Groq | yes | `GROQ_API_KEY` |
| OpenRouter | yes, 19 free models | `OPENROUTER_API_KEY` |
| OmniRouter |, | `OMNIROUTER_API_KEY` |
| Cloudflare Workers AI | yes | `CLOUDFLARE_API_TOKEN` **and** `CLOUDFLARE_ACCOUNT_ID` |
| OpenAI-compatible | Ollama, LM Studio, vLLM | `OPENAI_API_KEY` + `OPENAI_BASE_URL` |
| Hugging Face | yes | `HUGGINGFACE_API_KEY` |

`.env.example` lists the usable model ids for each provider, including every
current OpenRouter free model. Cloudflare needs both values because the account
id is part of the request URL, so the key panel renders a second field for it.

A caveat worth stating: OpenRouter's free models are individually unreliable. Of the eight
tested against a live key, most returned a 429, a 403, or their own reasoning text instead of
the JSON they were asked for. The picker therefore orders free models ahead of paid ones and
defaults to `nex-agi/nex-n2.5-mini:free`, which was verified to return well formed JSON. When
a model does fail, that risk falls back to its composed narrative and the UI says so rather
than showing a gap.

Providers are ordered by measured latency on this workload rather than alphabetically, so the
fastest available one becomes the default. Cloudflare Workers AI writes all five narratives in
about 45 seconds where the OpenRouter free models take about 105.

A key pasted in the UI is held in that browser, sent as an `X-LLM-Key-<provider>` header with
that visitor's own requests, and never stored on the server or written to a log. Provider
adapters are process-wide singletons, so the credential lives in a `contextvar` bound per
request, one visitor's key can never serve another's.

---

## Layout

```
app/
  ingest/      typed loaders for the 5 CSVs, the MDR advisory parser, data quality
  reference/   CISA KEV lookup; NIST catalogue loader and chunker
  embeddings/  pluggable backends: local ONNX (default) or Gemini
  retrieval/   numpy vector store, BM25, and the RRF hybrid retriever
  scoring/     the six-factor engine, the tunable weights, campaign x service grouping
  briefing/    retrieval queries, hint matching, grounding guard, control rerank,
               narrative, Markdown report
  llm/         provider registry, per-request keyring, 7 adapters
  api/         FastAPI routes and the BYOK dependency
web/           dashboard, no build step
scripts/       fetch_reference_data.py, build_index.py
data/          dataset, reference snapshots, committed vector index
tests/         63 tests
```

### API

| Endpoint | |
|---|---|
| `GET /api/analysis` | full deterministic analysis, no key needed |
| `POST /api/analysis` | re-rank under custom `weights`, still no key needed |
| `GET /api/weights` | the tunable model and its defaults |
| `POST /api/analysis/brief` | narratives rewritten by a model, optional `rerank_controls` |
| `GET` or `POST /api/report.md` | the brief as Markdown, POST accepts `weights` |
| `GET /api/risks` | all 114 findings ranked |
| `GET /api/advisory` | the MDR advisory as parsed, and what it matched |
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

- CISA Known Exploited Vulnerabilities catalogue, <https://github.com/cisagov/kev-data>
- NIST SP 800-53 Rev. 5 control catalogue, <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads>
- TawasolPay data pack and MDR advisory, as supplied with the assignment (synthetic)
