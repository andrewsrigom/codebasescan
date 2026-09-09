# Initial engineering decisions

| Decision | Rationale / consequence |
| --- | --- |
| Local-first, single user | Avoid uploading proprietary repositories and avoid premature SaaS infrastructure. No public hosting mode. |
| Next.js + TypeScript | Strong product UI and shared readable domain contracts. Node 22.16+ enables the selected native TypeScript/SQLite execution path. |
| Separate worker | Audits and human-resume requests survive browser closure. No fire-and-forget audit in a route handler. |
| SQLite, one consumer | Minimal setup for one machine. Not a distributed queue or multi-host deployment architecture. |
| Official LangGraph SQLite saver | Learn real framework persistence; do not simulate checkpoints using a JSON file. |
| No AI by default | A reproducible demo must not require hardware, model downloads, keys, or fake model activity. |
| Optional fixed-loopback Ollama | Local inference first; no cloud fallback. Strict offline isolation still requires operator/network controls. |
| Seven heuristics + two optional scanner adapters | Small implemented vertical slice. OSV, Trivy, AST/dataflow, and broad AI security coverage are later work. |
| Source snapshot before analysis | Give tools a bounded fixed in-memory view and evidence digests. Exclude credentials files and unsupported inputs. |
| No shell or target execution | Scanner subprocesses are trusted fixed binaries, not model-chosen commands or target scripts. |
| No automatic exploit or fix | Verification means evidence review, not a claim of exploitation. Future dynamic tests require a separate threat model. |
| No numeric security score | A high number could imply assurance unsupported by coverage. Display findings, coverage, and dispositions instead. |
| Human publication separate from finding confirmation | Reviewing a report must not falsely confirm every candidate. |
| Explicit limitations in every export | Portable artifacts must preserve uncertainty even when viewed outside the app. |
| Custom CSS and system fonts | Small UI dependency surface, offline assets, readable components. No forced component library migration. |
| Apache-2.0 for original starter | Explicit open-source intention. External binary, rules, and model licenses must be reviewed separately. |
| No bundled binary/model/font files | Keep redistribution auditable and the starter lightweight. |

Changes to these decisions should be deliberate. Add a dated decision with the problem, alternatives, trade-offs, and migration impact. Do not create endless documentation for ordinary implementation details.
