# Serhii Shunko (`@ccsimplyspolit`) — Security Research & Binary Auditing Portal

[![Live Portal](https://img.shields.io/badge/Live_Portal-ccsimplyspolit.github.io-0b0e14?style=flat-square&logo=googlechrome&logoColor=38bdf8&labelColor=111622)](https://ccsimplyspolit.github.io/)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0002--4183--0361-0b0e14?style=flat-square&logo=orcid&logoColor=34d399&labelColor=111622)](https://orcid.org/0009-0002-4183-0361)
[![Zenodo DOIs](https://img.shields.io/badge/CERN_Zenodo-3_Published_DOIs-0b0e14?style=flat-square&logo=zenodo&logoColor=38bdf8&labelColor=111622)](https://doi.org/10.5281/zenodo.23641037)
[![ISO/IEC 29147](https://img.shields.io/badge/Policy-ISO%2FIEC_29147_CVD-0b0e14?style=flat-square&logoColor=34d399&labelColor=111622)](https://ccsimplyspolit.github.io/#policy)

Source repository for **[ccsimplyspolit.github.io](https://ccsimplyspolit.github.io/)**, the public security research, Coordinated Vulnerability Disclosure (CVD), and reverse-engineering portal of **Serhii Shunko (`@ccsimplyspolit` / `@sshunko`)**.

---

## Portal Structure

| Section | Path | Contents |
|:---|:---|:---|
| **Interactive Advisory & Suite Index** | [`index.html`](index.html) | Live filterable catalog of 12+ published GitHub Security Advisories (GHSAs), 16+ upstream fixes, and 7 open-source security/reverse-engineering suites. |
| **Security Advisories (`advisories/`)** | [`advisories/`](advisories/) | Standalone technical advisory pages (`GHSA-45rj-2wq9-r9mr`, `GHSA-g275-mf26-qx9r`, `GHSA-r5j2-ghh9-2jqw`, `GHSA-qr8h-p53p-x564`, `GHSA-pvw7-7j8c-qx96`, `GHSA-g52w-56c5-674f`, `GHSA-8885-xrq4-j47h`, `GHSA-4x7j-8w5q-5f7w`, `GHSA-hw42-92fr-x9vc`, `GHSA-j7g2-gm7j-mfvm`, `GHSA-qm7x-j9xp-x3gv`, `GHSA-w6v4-9j58-rv79`, `GHSA-x9vx-8c8r-c57x`, `GHSA-6hh9-gpj4-cr69`, `H1-4148578`). |
| **Technical Write-ups (`writeups/`)** | [`writeups/`](writeups/) | Deep-dive whitebox post-mortems on ZIP parser differentials, unsigned integer underflows in C/C++ packet parsers, `libprotobuf-mutator` subtick invariants, embeddable VM union type confusion, and CoW snapshot fuzzing. |
| **CVP Verification Dossier** | [`Serhii_Shunko_CVP_Verification_Dossier_Oct2026.pdf`](Serhii_Shunko_CVP_Verification_Dossier_Oct2026.pdf) | Coordinated Vulnerability Disclosure verification dossier with upstream commit/PR references and ORCID links. |

---

## Featured Open-Source Engineering & Audit Suites

- **[`tenda-ac10-v1-hybrid-openwrt`](https://github.com/ccsimplyspolit/tenda-ac10-v1-hybrid-openwrt)** — Hybrid OpenWrt 4.14.187 firmware (`RTL8197FS` + `RTL8822BE` + `RTL8367RB`), 34 kernel binary patches, and autonomous TFTP/SSH recovery suite ([Live Portal](https://ccsimplyspolit.github.io/tenda-ac10-v1-hybrid-openwrt/)).
- **[`protobuf-bounds-auditor`](https://github.com/ccsimplyspolit/protobuf-bounds-auditor)** — Static & dynamic security analyzer for `.proto` schemas (`CWE-1284`, `CWE-20`, `CWE-674`) with `DEFINE_PROTO_FUZZER` generation ([DOI: `10.5281/zenodo.23641037`](https://doi.org/10.5281/zenodo.23641037)).
- **[`mcp-ssrf-auditor`](https://github.com/ccsimplyspolit/mcp-ssrf-auditor)** — Security evaluation harness for Model Context Protocol (MCP) servers (`CWE-918`, `CWE-22`, `CWE-78`, `CWE-1384`).
- **[`c-bounds-audit-framework`](https://github.com/ccsimplyspolit/c-bounds-audit-framework)** — Automated C/C++ memory-bounds and signed-length underflow static auditor (`CWE-125`, `CWE-190`, `CWE-195`, `CWE-908`).
- **[`cs-telemetry-internals`](https://github.com/ccsimplyspolit/cs-telemetry-internals)** — Source 2 server input validation whitepapers and dual IDAPython/CLI static analyzer ([DOI: `10.5281/zenodo.23640494`](https://doi.org/10.5281/zenodo.23640494)).
- **[`cardinal-engine-integrity`](https://github.com/ccsimplyspolit/cardinal-engine-integrity)** — Relocation-normalized PE32+ binary integrity and lockstep simulation auditor ([DOI: `10.5281/zenodo.23640496`](https://doi.org/10.5281/zenodo.23640496)).
- **[`discord-quest-helper`](https://github.com/ccsimplyspolit/discord-quest-helper)** — Full IDA Pro reverse-engineering audit of `discord_utils.node` (`sub_a3990` / `sub_1350`) and `libdiscore-wasm`.
