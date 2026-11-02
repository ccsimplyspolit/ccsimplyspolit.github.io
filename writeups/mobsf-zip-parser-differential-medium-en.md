# Anatomy of a Parser Differential: Breaking MobSF's Pre-Extraction Symlink Neutralizer via PK\x05\x06 EOCD Shadowing (GHSA-j7g2-gm7j-mfvm)

**Author:** Serhii Shunko ([@ccsimplyspolit](https://github.com/ccsimplyspolit) / [@sshunko](https://hackerone.com/sshunko))  
**Advisory:** [GHSA-j7g2-gm7j-mfvm](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-j7g2-gm7j-mfvm)  
**Fixed In:** Mobile Security Framework (MobSF) v4.6.5  
**Severity:** Low (CVSS v3.1: 3.1 / CVSS v4.0: 2.3)  

---

### Introduction

Automated security scanners regularly process untrusted archives. When an engineer or CI workflow uploads an Android APK or iOS IPA to **Mobile Security Framework (MobSF)**, the platform must unpack files before decompilers such as JADX or Ghidra can analyze the code.

Handling archives securely is fraught with edge cases. An earlier vulnerability, [GHSA-mc92-j6mp-x9cp](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-mc92-j6mp-x9cp), demonstrated that an archive containing Unix symbolic links (`S_IFLNK` `0o120000`) could allow subsequent entries to overwrite files outside the extraction sandbox when unpacked with system utilities.

In response, MobSF implemented `neutralize_zip_special_modes()` to strip POSIX special modes from the ZIP Central Directory prior to extraction. However, an incomplete mitigation created a classic **parser differential** coupled with a **fail-open** fallback, allowing the neutralization routine to be bypassed.

In this deep-dive post-mortem, we analyze:
1. The vulnerable archive processing pipeline in MobSF.
2. How End of Central Directory (EOCD) comment shadowing triggers `ValueError` via `rfind`.
3. Why Info-ZIP 6.0's internal safeguards and synchronous cleanup kept the issue at Low severity.
4. The upstream remediation in MobSF 4.6.5.

---

### The Architecture & The Fail-Open Flaw

MobSF uses a two-tier extraction strategy in `mobsf/StaticAnalyzer/views/common/shared_func.py`. It first tries Python's standard `zipfile` module. Because obfuscated malware or packed APKs frequently fail Python's strict header checks, MobSF provides a fallback: `os_unzip()`, invoking the host's `/usr/bin/unzip`.

To prevent Info-ZIP from extracting symlinks, `os_unzip` calls `neutralize_zip_special_modes(app_path, ext_path)`:

```python
# mobsf/StaticAnalyzer/views/common/shared_func.py:400-415 (MobSF <= 4.6.4)
extract_from = app_path
try:
    patched = neutralize_zip_special_modes(app_path, ext_path)
    extract_from = patched
except Exception:
    logger.warning('Could not strip symlink modes before OS unzip')

subprocess.call(
    [unzip_b, '-o', '-q', extract_from, '-d', ext_path])

set_permissions(ext_path)
remove_external_symlinks(ext_path)
```

Notice the flaw:
- `extract_from` starts pointing to `app_path` (the unverified, user-uploaded archive).
- If `neutralize_zip_special_modes()` succeeds, `extract_from` becomes `patched`.
- If `neutralize_zip_special_modes()` throws **any exception**, the exception is swallowed with a warning, and `subprocess.call` proceeds using `extract_from = app_path`!

Meanwhile, inside `neutralize_zip_special_modes()`:
```python
def neutralize_zip_special_modes(src, dest_parent):
    ...
    try:
        shutil.copyfile(src, name)
        with open(name, 'r+b') as handle:
            _rewrite_special_central_directory(handle)
    except Exception:
        os.unlink(name)
        raise
    return name
```
On any error, the temporary file is deleted, the exception is re-raised, caught by `os_unzip`, and the raw original archive is unpacked with all symlink modes intact.

---

### Root Cause: EOCD Shadowing & Parser Differential

The ZIP specification ends with the End of Central Directory (EOCD) record (minimum 22 bytes), followed by an optional comment of up to 65,535 bytes:
```
[Central Directory Headers...]
+-------------------------------------------------------------+
| EOCD Record (22 bytes minimum)                              |
| Signature: 0x06054b50 ("PK\x05\x06")                       |
| Metadata: Disks, entries count, Central Directory offset    |
| Comment Length: 2 bytes                                     |
| Variable Archive Comment (.n bytes)                         |
+-------------------------------------------------------------+
```

MobSF's EOCD locator was implemented as:
```python
def _eocd_offset(handle, size):
    window = min(size, 65535 + 22)
    data = _read_at(handle, size - window, window)
    rel = data.rfind(_EOCD_SIG)
    if rel < 0 or window - rel < 22:
        raise ValueError('EOCD not found')
    return size - window + rel
```

#### Why `data.rfind(_EOCD_SIG)` Fails
`rfind` searches backward from the end of the byte sequence. If an archive comment contains the sequence `PK\x05\x06` in its final 21 bytes:
1. `rfind` matches the signature inside the comment instead of the genuine EOCD record.
2. Because the match is within the last 21 bytes, `window - rel < 22` evaluates to `True`.
3. `_eocd_offset` immediately raises `ValueError('EOCD not found')`.

A similar failure occurred when extra padding existed between the Central Directory and EOCD, causing `_rewrite_special_central_directory` to raise `ValueError('central directory walk did not finish')`.

In all these scenarios, MobSF's sanitizer crashed, deleted the temporary file, and triggered the fail-open fallback to `app_path`.

---

### Why the Severity is Low: Info-ZIP 6.0's Defense in Depth

While bypassing a symlink filter might appear to be a Critical RCE on paper, two architectural barriers mitigated real-world impact:

1. **Info-ZIP 6.0 Deferred Extraction:** Modern Info-ZIP (version 6.0+) defers symlink creation to the final extraction phase and enforces internal path checks (`checkdir()`) to prevent traversal outside the destination root.
2. **Synchronous Post-Extraction Cleanup:** Immediately after `subprocess.call` completes, MobSF executes:
```python
set_permissions(ext_path)
remove_external_symlinks(ext_path)
```
`remove_external_symlinks` performs a synchronous recursive traversal, resolves `os.path.realpath`, and unlinks any external symbolic link before the analysis engine inspects any extracted files.

Because the window for file manipulation was restricted to the brief process lifetime of `unzip`, maintainers and researchers agreed on a **Low** severity rating (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`, Score 3.1).

---

### Upstream Remediation in MobSF 4.6.5

MobSF maintainer Ajin Abraham ([@ajinabraham](https://github.com/ajinabraham)) resolved the vulnerability in version **4.6.5**:

1. **Fail-Closed Strategy:** If `neutralize_zip_special_modes` fails, `os_unzip` refuses to extract the archive and returns an error:
```python
except Exception:
    msg = 'Refusing OS unzip because special modes could not be stripped'
    logger.error(msg)
    append_scan_status(checksum, msg)
    return []
```
2. **Length-Validated Backward Scanning:** The EOCD locator was updated to iterate backward and ensure the candidate header's 16-bit comment length field matches the remaining buffer length.

---

### Defensive Takeaways

- **Never fail open on security preprocessors:** If a security filter cannot validate an input, abort immediately.
- **Validate lengths in variable-tail binary formats:** Avoid naive right-to-left signature searches in formats that allow trailing user-controlled comments.
- **Layered defenses provide resilience:** Info-ZIP's modern internal validation and MobSF's post-extraction cleanup prevented what could have been a Critical exploit from escalating.
