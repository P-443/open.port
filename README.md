

# الإصدار :- V-->1.1 

# الأمر الذي ستستخدمه :-
```
bash <(curl -s https://raw.githubusercontent.com/l-s-I-I/speed/main/Run.sh)
```
# Ø£Ùˆ Ù„Ù„ÙˆÙŠÙ†Ø¯ÙˆØ² (Windows) :-
### Ø§ÙØªØ­ **PowerShell ÙƒÙ€ Administrator** ÙˆØ´ØºÙ‘Ù„ Ø§Ù„Ø£Ù…Ø± Ø¯ÙŠ :-
```
[Net.ServicePointManager]::SecurityProtocol='Tls12'; $b='https://raw.githubusercontent.com/P-443/open.port/windows'; $d=Join-Path $env:ProgramData 'open.port'; New-Item $d -ItemType Directory -Force | Out-Null; 'Run.ps1','Tunnel443.ps1','Stop-Tunnel.ps1' | %{ iwr "$b/$_" -OutFile (Join-Path $d $_) -UseBasicParsing }; & (Join-Path $d 'Run.ps1')
```

> ÙƒÙ„ Ù…Ù„ÙØ§Øª Ø§Ù„ÙˆÙŠÙ†Ø¯ÙˆØ² Ù…ÙˆØ¬ÙˆØ¯Ø© ÙÙŠ ÙØ±Ø¹ **`windows`** â€” (Run.ps1 / Tunnel443.ps1 / Stop-Tunnel.ps1).
> Ø§Ù„Ø´Ø±Ø­ Ø§Ù„ÙƒØ§Ù…Ù„: [README ÙØ±Ø¹ ÙˆÙŠÙ†Ø¯ÙˆØ²](https://github.com/P-443/open.port/blob/windows/README.md)

---

### OS Compatibility Table

|    OS System     |       Status      | 
| :--------------: | :---------------: | 
| **AlmaLinux**    |  **Tested** ✅     |
| **Debian**       |  **Tested** ✅     |
| **Rocky Linux**  |  **Tested** ✅     |
| **Ubuntu**       |  **Tested** ✅     |
| **Alpine Linux** |  **Not work** ❌   |
| **Arch Linux**   |  **Tested** ✅     |
| **CentOS**       |  **Tested** ✅     |
| **CloudLinux**   |  **Not work** ❌   |
| **Fedora Cloud** |  **Tested** ✅     |
| **Kali Linux**   |  **- No UDPGW** ✅ |
| **openSUSE**     |  **Tested** ✅     |

