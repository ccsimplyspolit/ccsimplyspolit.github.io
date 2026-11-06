# Serhii Shunko (`@ccsimplyspolit`) -- Security Research & Advisory Portal

**Live Portal:** [https://ccsimplyspolit.github.io](https://ccsimplyspolit.github.io)  
**ORCID:** [0009-0002-4183-0361](https://orcid.org/0009-0002-4183-0361)  
**CERN / Zenodo DOIs:** [`10.5281/zenodo.23641037`](https://doi.org/10.5281/zenodo.23641037) · [`10.5281/zenodo.23640494`](https://doi.org/10.5281/zenodo.23640494) · [`10.5281/zenodo.23640496`](https://doi.org/10.5281/zenodo.23640496)

---

## Maintainer-Published GitHub Security Advisories (17 Published GHSAs)

All advisories indexed in this repository are officially published by upstream project maintainers on GitHub Security Advisories following coordinated vulnerability disclosure (ISO/IEC 29147). Zero uncoordinated or embargoed vulnerabilities are published.

| # | Advisory ID | Repository | Vulnerability Summary & CWE | Severity | Remediation |
|:---:|:---|:---|:---|:---:|:---|
| 01 | [`GHSA-g275-mf26-qx9r`](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-g275-mf26-qx9r) | **siyuan-note/siyuan** | Stored XSS Escalating to RCE via Unescaped Checkbox Column in Kanban/Table Attribute Views (`CWE-79` / `CWE-94`) | **Critical (9.6)** | Patched in `3.8.10` |
| 02 | [`GHSA-3xjw-gv43-3w62`](https://github.com/mastodon/mastodon/security/advisories/GHSA-3xjw-gv43-3w62) | **mastodon/mastodon** | Pre-OTP Session Fixation & Unthrottled 2FA Brute-Force via Shared Pending User Session State (`CWE-287` / `CWE-307` / `CWE-613`) | **High (8.8)** | Patched in `5.0.0-alpha.4 / 4.7.5` |
| 03 | [`GHSA-45rj-2wq9-r9mr`](https://github.com/electerm/electerm/security/advisories/GHSA-45rj-2wq9-r9mr) | **electerm/electerm** | Missing Host & Origin Validation in Built-in MCP HTTP Server Enables DNS Rebinding RCE (`CWE-306` / `CWE-346` / `CWE-350`) | **High (8.8)** | Patched in `5.8.2` |
| 04 | [`GHSA-jpm2-x6wf-fxjc`](https://github.com/nektos/act/security/advisories/GHSA-jpm2-x6wf-fxjc) | **nektos/act** | Git Command Flag Injection in Actions Checkout & Container Mount Handling (`CWE-88` / `CWE-184`) | **High (8.6)** | Patched in `0.2.95` |
| 05 | [`GHSA-r5j2-ghh9-2jqw`](https://github.com/wailsapp/wails/security/advisories/GHSA-r5j2-ghh9-2jqw) | **wailsapp/wails** | Linux WebKitGTK Script Message Bridge Missing Origin & Frame Validation (`CWE-284` / `CWE-346`) | **High (8.3)** | Patched in `2.17.1` |
| 06 | [`GHSA-qr8h-p53p-x564`](https://github.com/ossrs/srs/security/advisories/GHSA-qr8h-p53p-x564) | **ossrs/srs** | RTC Crash & Heap Buffer Overflow from Malformed RTCP Packet in SrsRtcpCompound (`CWE-125` / `CWE-191` / `CWE-835`) | **High (8.2)** | Patched in `6.0.194` |
| 07 | [`GHSA-cr23-59mg-h2rc`](https://github.com/bacnet-stack/bacnet-stack/security/advisories/GHSA-cr23-59mg-h2rc) | **bacnet-stack/bacnet-stack** | Signed Length Negative Infinite Loop & Out-of-Bounds Read/Write in Calendar_Write_Property (`CWE-125` / `CWE-400` / `CWE-787` / `CWE-835`) | **High (8.2)** | Patched in `1.4.7, 1.5.3, 1.6.2, 1.7.0` |
| 08 | [`GHSA-jr85-7366-xrm2`](https://github.com/akitaonrails/ai-memory/security/advisories/GHSA-jr85-7366-xrm2) | **akitaonrails/ai-memory** | Predictable /tmp Symlink Clobbering in Install & Hook Scripts (`CWE-59` / `CWE-377`) | **High (8.2)** | Patched in `3.3.2` |
| 09 | [`GHSA-pvw7-7j8c-qx96`](https://github.com/opensensor/lightNVR/security/advisories/GHSA-pvw7-7j8c-qx96) | **opensensor/lightNVR** | Authorization Bypass via Pre-Decode Query Truncation & Dangling Pointer in HTTP Handler (`CWE-285` / `CWE-416`) | **High (8.1)** | Patched in `0.44.3` |
| 10 | [`GHSA-g52w-56c5-674f`](https://github.com/SalesforceCommerceCloud/b2c-developer-tooling/security/advisories/GHSA-g52w-56c5-674f) | **SalesforceCommerceCloud/b2c-developer-tooling** | Path Containment Omission in B2C DX MCP Server Cartridge Creation Tool (`CWE-22`) | **High (7.1)** | Patched in `3.9.0` |
| 11 | [`GHSA-796w-fvw2-ccmp`](https://github.com/github/gh-aw/security/advisories/GHSA-796w-fvw2-ccmp) | **github/gh-aw** | Insecure World-Writable Shared /tmp/gh-aw Execution Directory & Symlink Clobbering (`CWE-59` / `CWE-377` / `CWE-732`) | **High (7.1)** | Patched in `1.2.0` |
| 12 | [`GHSA-xq9m-mrj7-jv98`](https://github.com/containers/kubernetes-mcp-server/security/advisories/GHSA-xq9m-mrj7-jv98) | **containers/kubernetes-mcp-server** | Unencrypted Bearer Token Transmission over Cleartext HTTP on Redirect or Unvalidated Target URLs (`CWE-319` / `CWE-918`) | **Moderate (6.8)** | Patched in `0.1.2` |
| 13 | [`GHSA-8885-xrq4-j47h`](https://github.com/wekan/wekan/security/advisories/GHSA-8885-xrq4-j47h) | **wekan/wekan** | Cross-Board Checklist Disclosure in Scoped Board Export & Streaming CSV/TSV Policy Bypass (`CWE-359` / `CWE-639` / `CWE-863`) | **Moderate (5.3)** | Patched in `12.78` |
| 14 | [`GHSA-4x7j-8w5q-5f7w`](https://github.com/ntop/nDPI/security/advisories/GHSA-4x7j-8w5q-5f7w) | **ntop/nDPI** | DCE/RPC Fragment Length Validation Bypass & DHCP Packet Offset Clamping Flaw (`CWE-670`) | **Moderate (5.3)** | Patched in `5.1 (commit ff44ed2)` |
| 15 | [`GHSA-hw42-92fr-x9vc`](https://github.com/LTplus-AG/ifc-lite/security/advisories/GHSA-hw42-92fr-x9vc) | **LTplus-AG/ifc-lite** | STEP Record Injection via Unvalidated Entity Type Names in @ifc-lite/export (`CWE-74`) | **Moderate (5.3)** | Patched in `4.13.1 / 27.0.0` |
| 16 | [`GHSA-j7g2-gm7j-mfvm`](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-j7g2-gm7j-mfvm) | **MobSF/Mobile-Security-Framework-MobSF** | Pre-Extraction Symlink Mode Stripping Bypass via EOCD Comment Signature Shadowing (`CWE-59` / `CWE-755`) | **Low (3.1)** | Patched in `4.6.5` |
| 17 | [`GHSA-qm7x-j9xp-x3gv`](https://github.com/czlonkowski/n8n-mcp/security/advisories/GHSA-qm7x-j9xp-x3gv) | **czlonkowski/n8n-mcp** | SSRF Protection Hostname Blocklist Bypass via Trailing-Dot & *.localhost Subdomains (`CWE-918` / `CWE-184`) | **Low (3.1)** | Patched in `2.99.2` |

---

## License & Disclosure Standard

All write-ups and static analysis documentation are published under ISO/IEC 29147 responsible disclosure guidelines after upstream patches are released.
