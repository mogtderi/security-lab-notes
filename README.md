# DNN Install Wizard Authentication Bypass — CVE-2015-2794

**Lab test only.** Performed entirely against a DotNetNuke instance I installed myself on a local/isolated VM, with no internet-facing exposure and no third party involved.

## Summary

DotNetNuke (DNN) versions up to 7.4.0 ship an installation wizard at `/Install/InstallWizard.aspx` that is **not disabled after setup** and **does not require authentication**. Visiting it directly lets anyone re-run parts of the installer and, with the database in its default configuration, create a new **SuperUser** account — full administrative access.

| | |
|---|---|
| CVE | CVE-2015-2794 |
| Affected | DotNetNuke ≤ 7.4.0 |
| Fixed in | 7.4.1 (7.4.0.353) |
| CVSS 3.0 | 9.8 (Critical) |
| Type | Broken access control / insecure default configuration (CWE-264) |

## Lab setup

- **Target:** DotNetNuke 7.4.0, installed on a local Windows VM (IIS + SQL Server Express), no network access outside the lab
- **Attacker:** Kali Linux VM on the same isolated virtual network
- **Tools:** Nmap (service discovery), a web browser (manual testing)

## Steps

### 1. Recon
```
nmap -sV -p 80,443 <lab-vm-ip>
```
Confirmed IIS was running and the site responded on port 80. Browsing the site identified it as a DotNetNuke install from page markup and default theme files.

### 2. Checking for the exposed install wizard
The installer is supposed to be removed or locked down after the first setup. I requested the path directly in the browser:
```
http://<lab-vm-ip>/Install/InstallWizard.aspx?__VIEWSTATE=
```
On a patched DNN install this should redirect to the login page or return an error. On the vulnerable 7.4.0 lab instance, the wizard loaded and accepted input with no authentication at all.

### 3. Why it works
The wizard page never checks whether an installation already exists before processing requests, and it trusts the `culture` and `executeinstall` parameters to resume the install flow. Because the default lab database path/credentials were untouched, the wizard could write a new administrative account straight into the existing database.

### 4. Impact
An attacker who can reach this URL on a vulnerable, internet-facing DNN site could gain full **SuperUser** access without any credentials — equivalent to a complete site takeover (content, users, and depending on configuration, the underlying server).

## Fix

- **Upgrade** to DNN 7.4.1 or later (the vendor fix).
- As a mitigation if upgrading isn't immediate: remove or lock down the `/Install/` folder after setup (deny access at the web-server level) and restrict it by IP.
- Review for unexpected SuperUser accounts if the site was ever exposed to the internet on an affected version.

## Tool

`tools/check_dnn_installer.py` checks **one target you specify** for this exact issue: it requests the install wizard path and inspects the response. It never submits the install form, never creates an account, and never scans lists of hosts — it only checks the single target you pass in.

```bash
pip install -r tools/requirements.txt
python3 tools/check_dnn_installer.py https://your-lab-vm.local
```

## References

- [NVD — CVE-2015-2794](https://nvd.nist.gov/vuln/detail/CVE-2015-2794)
- [Exploit-DB 39777 — DotNetNuke 07.04.00 Administration Authentication Bypass](https://www.exploit-db.com/exploits/39777)

## Disclosure note

This CVE and its details are public and have been since 2015/2017. This write-up documents my own lab reproduction and understanding of it; it is not a new discovery.
