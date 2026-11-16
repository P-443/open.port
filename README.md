# SSH over 443 on Windows — بدون دوكر وبدون أي برامج خارجية

نسخة ويندوز كاملة من سكربت `Run.sh` (تليمجرامول) اللي كان يشتغل على لينكس.
كل حاجة اتعملت بمكوّنات ويندوز الأصلية فقط: **OpenSSH Server المدمج + .NET**.

---

## 1) السكربت الأصلي كان محتاج إيه؟ (تحليل `Run.sh`)

| # | المكوّن في اللينكس | بيعمل إيه | البديل على ويندوز |
|---|--------------------|-----------|--------------------|
| 1 | `apt/dnf/pacman` + تحديث النظام | تنصيب الحزم | `Windows Features` / `Get-WindowsCapability` (مدمج) |
| 2 | `python3.12-dev`, `python3-pip`, `python3.12 -m venv myenv` | بيئة بايثون لتشغيل `udocker` | ❌ مش محتاج أصلاً |
| 3 | `udocker` | تشغيل دوكر بدون روت | ❌ مش محتاج |
| 4 | `dweomer/stunnel` image | **stunnel** يفتح 443 ويوصّل لـ 22 | ✅ `Tunnel443.ps1` — مستمع TLS مكتوب بـ .NET |
| 5 | `openssh-server` + systemd (`systemctl start/enable ssh`) | سيرفر SSH | ✅ `OpenSSH.Server` (ميزة ويندوز مدمجة) + خدمة `sshd` |
| 6 | `adduser` + `chpasswd` | يوزر وباسورد SSH | ✅ `New-LocalUser` / `Set-LocalUser` |
| 7 | `/etc/ssh/sshd_config` + `Banner /etc/mybanner` | بانر SSH | ✅ `C:\ProgramData\ssh\sshd_config` + `banner.txt` |
| 8 | `go1.21.1.linux-amd64.tar.gz` + `git clone udpgw` + `go build` | **badvpn udpgw** (بوابة UDP على 7300) | ✅ `UdpGw` class بـ C# — نفس البروتوكول بالظبط |
| 9 | `Country.sh` (تحميل من GitHub) + `ipinfo.io` | معرفة البلد والعلم | ✅ `Invoke-RestMethod ipinfo.io` + تحويل كود البلد لعلم (مدمج) |
| 10 | `sysctl net.core.rmem_max/wmem_max` | تحسين الشبكة | ✅ `netsh int tcp set global ...` + `Set-NetTCPSetting` |
| 11 | `curl -LO` للتحميلات | تنزيل ملفات خارجية | ❌ مش محتاج أي تحميل |

**النتيجة: مفيش أي مصدر خارجي.** اللي محتاجه بس:

- Windows Server 2016+ / Windows 10+ (تم الاختبار على Server 2025)
- PowerShell 5.1 (مدمج)
- ميزة `OpenSSH.Server` (مدمجة في ويندوز — السكربت ينصبها لوحده)
- صلاحية Administrator
- بورت 443 فاضي (أو أي بورت تختاره)
- .NET Framework 4.x (مدمج)

الملفات اللي بتحتاجها = 4 ملفات في فولدر واحد فقط:

```
open.port\
  ├── Run.ps1          ← التنصيب والتشغيل
  ├── Tunnel443.ps1    ← 443 (stunnel) + 7300 (udpgw)
  ├── Stop-Tunnel.ps1  ← الإيقاف / الحذف
  └── README.md
```

# أو للويندوز (Windows) :-
### افتح **PowerShell كـ Administrator** وشغّل الأمر دي :-
```
[Net.ServicePointManager]::SecurityProtocol='Tls12'; $b='https://raw.githubusercontent.com/P-443/open.port/windows'; $d=Join-Path $env:ProgramData 'open.port'; New-Item $d -ItemType Directory -Force | Out-Null; 'Run.ps1','Tunnel443.ps1','Stop-Tunnel.ps1' | %{ iwr "$b/$_" -OutFile (Join-Path $d $_) -UseBasicParsing }; & (Join-Path $d 'Run.ps1')
```

> كل ملفات الويندوز موجودة في فرع **`windows`** — (Run.ps1 / Tunnel443.ps1 / Stop-Tunnel.ps1).
> الشرح الكامل: [README فرع ويندوز](https://github.com/P-443/open.port/blob/windows/README.md)

---

## 2) التشغيل

### أسرع طريقة — **أمر واحد** (من فرع `windows` في المستودع)

افتح **PowerShell كـ Administrator** والصق السطر ده:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; $b='https://raw.githubusercontent.com/P-443/open.port/windows'; $d=Join-Path $env:ProgramData 'open.port'; New-Item $d -ItemType Directory -Force | Out-Null; 'Run.ps1','Tunnel443.ps1','Stop-Tunnel.ps1' | %{ iwr "$b/$_" -OutFile (Join-Path $d $_) -UseBasicParsing }; & (Join-Path $d 'Run.ps1')
```

ده بينزّل الملفات (3 ملفات) في `C:\ProgramData\open.port` وبيشغّل التنصيب فوراً، ويسألك اليوزر/الباسورد/البورت.

> شغّال على **سيرفر فاضي تماماً**: السكربت يتأكد إن OpenSSH Server موجود وينصّبه لوحده (حتى لو خدمة Windows Update / Modules Installer كانت **معطّلة** — بيصلحها وينصّب تاني، وكحل أخير بينزّل حزمة Win32-OpenSSH الرسمية).

### الطريقة اليدوية

لو الملفات عندك في فولدر، افتح **PowerShell كـ Administrator** ثم:

```powershell
cd C:\ProgramData\open.port
powershell -ExecutionPolicy Bypass -File .\Run.ps1
```

السكربت يسألك 3 أسئلة (زي الأصل بالظبط):

```
Enter User     (default: telegram)   -> telegram
Enter Pass     (default: @d_s_d_c1)  -> @d_s_d_c1
Enter Port     (default: 443)        -> 443
```

أو بدون أسئلة:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run.ps1 -User telegram -Pass '@d_s_d_c1' -Port 443
```

### اللي بيعمله `Run.ps1` بالترتيب

1. يتأكد إن `OpenSSH.Server` منصّب (وينصبه لو مش موجود) ويشغّل خدمة `sshd` تلقائي عند البوت.
2. يظبط `sshd_config`: منفذ SSH، `PasswordAuthentication yes`، `GatewayPorts yes`، `AllowTcpForwarding yes`، حدود اتصالات أعلى.
3. يكتب بانر SSH (نفس `Server_Message` الموجود في `Run.sh` حرفياً) في `C:\ProgramData\ssh\banner.txt`.
4. يعمل اليوزر + الباسورد (ويشيله من مجموعة Administrators عشان يفضل مستخدم عادي زي اللينكس).
5. يفتح بورت 443 في **Windows Firewall**.
6. يعمل شهادة **self-signed** (RSA 2048 / SHA256 / 10 سنين) في مخزن `LocalMachine\My`.
7. يحسّن إعدادات TCP (بديل `sysctl`).
8. يسجّل **Scheduled Task** باسم `SSH443-Tunnel` تعمل Start تلقائي مع البوت كـ `SYSTEM`، ويشغّلها فوراً.
9. يتأكد إن البورت شغّال فعلاً وبيطبع بيانات الحساب.

---

## 3) إعدادات العميل (HTTP Custom / HTTP Injector / v2box)

| الإعداد | القيمة |
|---------|--------|
| Host / IP | IP السيرفر |
| Port | `443` (نفس `-Port`) |
| Protocol | SSH |
| TLS / SSL | **ON** (SNI: أي اسم، مثال `telegram`) |
| SNI Host | أي دومين — الشهادة self-signed، فعّل *Allow insecure / Trust all certificates* |
| Username / Password | اللي كتبته |
| UDPGW / UDP Port | `7300` (لو العميل بيدعم UDP) |

كمان بيشتغل **بدون TLS** على نفس البورت (الفحص تلقائي: لو أول بايت = `0x16` يبقي TLS، غير كده pass-through عادي)
— نفس اللي كان stunnel بيعمله بالضبط.

سطر جاهز بنفس صيغة `Run.sh` (بيطلع في آخر التنصيب):

```
IP:443@USER:PASS —» 🇺🇸
```

---

## 4) بوابة UDP (بديل udpgw / Go)

- البروتوكول: **badvpn udpgw** بالحرف (PacketProto: الطول **little-endian**):
  `[len:2 LE][flags:1][conid:2 BE][addr:4|16][port:2 BE][payload]`
- المستمع الافتراضي: `127.0.0.1:7300` — يعني **مش مفتوح على النت**، للوصول ليه لازم تعبر جوّا نفق SSH (زي `badvpn-udpgw` الأصلي).
- لو عايزه على كل الواجهات: `-UdpGwBind 0.0.0.0` (ووقتها تفتح UDP 7300 في الفايروول).
- لتغيير منفذ/تعطيله: `-UdpGwPort 7300` / `-NoUdpgw`.
- DNS: لو العميل بعت `DNS flag`، السكربت يوجّه الاستعلام لدنز السيرفر (من `Get-DnsClientServerAddress`، ولو مفيش يستخدم `1.1.1.1`) — زي سلوك badvpn مع `/etc/resolv.conf`.
  **كمان**: لو العميل بعت UDP على بورت `53` لعنوان السيرفر مستحيل يوصله (عنوان شبكة داخلية زي `192.168.1.1`
  — ودي عادة موبايلات كتير بتحطها كـDNS)، السكربت بيوجّه الاستعلام لدنز السيرفر ويبعت الرد للعميل بنفس العنوان الأصلي.
- Verbose (طباعة كل باكدج UDP في اللوج): `-UdpGwVerbose` (مقفول افتراضياً — اللوج بيلفّ تلقائي عند 8MB).

---

## 5) إدارة الخدمة

```powershell
# الحالة
Get-ScheduledTask SSH443-Tunnel | Select TaskName, State
Get-NetTCPConnection -LocalPort 443 -State Listen
Get-Content C:\ProgramData\ssh443\tunnel.log -Tail 30 -Wait

# إيقاف
powershell -File .\Stop-Tunnel.ps1

# تشغيل تاني
Start-ScheduledTask SSH443-Tunnel

# حذف كامل (فايروول + شهادة + بانر + التاسك)
powershell -File .\Stop-Tunnel.ps1 -Uninstall

# حذف كامل + حذف اليوزر
powershell -File .\Stop-Tunnel.ps1 -Uninstall -RemoveUser -User telegram
```

اللوجات:
- `C:\ProgramData\ssh443\tunnel.log` — اتصالات النفق (كل open/close/error).
- `C:\ProgramData\ssh443\setup-*.log` — لوج التنصيب.

---

## 6) ملاحظات مهمة

- **بورت 443 مشغول؟** لو في برنامج تاني واخد 443 (مثلاً IIS أو caddy)، لازم توقفه أو تستخدم بورت تاني `-Port 8443`. السكربت بيقولك في الآخر لو مفيش حاجة بتسمع.
- إعادة التشغيل **مش** محتاجة أي إعداد: التاسك بيشتغل مع البوت تلقائي وبيعيد المحاولة كل دقيقة لو وقع.
- النفق **مش** بيعمل أي تخزين للباسورد: الباسورد يتكتب لليوزر الويندوز فقط.
- لو عايز شهادة حقيقية من Let's Encrypt، حول الشهادة لـ PFX وحُط مسارها في `-CertThumbprint` (يقبل مسار `.pfx` كذلك).
- معطل/موقوف ويندوز فايروول؟ لازم تسمح بـ TCP 443.
- كل حاجة run-time في عملية واحدة (`powershell.exe` بتعمل host للمستمع) — مفيش أي خدمة إضافية أو ملف تنفيذي خارجي.

---

## 7) مشاكل اتقابلناها واتحلّت (مهمة لو ركّبت على سيرفر تاني)

| المشكلة | السبب الحقيقي | الحل اللي جوه السكربت |
|---------|----------------|------------------------|
| `Directive 'Port' is not allowed within a Match block` | ملف `sshd_config` الافتراضي في ويندوز بينتهي ببلوك `Match Group administrators`، وأي سطر بعده يعتبر جواه | كل الخيارات بتتكتب **قبل أول `Match`** |
| خدمة sshd بتقف فوراً (`terminated unexpectedly` / `no hostkeys available`) | ملفات مفاتيح السيرفر كان فيها ACE لليوزر اللي عمل `ssh-keygen` — sshd بيرفض أي مفتاح يقدر عليه حد غير SYSTEM/Administrators | `Repair-HostKeyAcl` بتعيد ضبط الـACL على SYSTEM + Administrators بالـSID |
| اليوزر مش قادر يدخل خالص | الملف الافتراضي فيه `AllowGroups administrators "openssh users"` | السكربت ينشئ مجموعة **`openssh users`** ويضيف اليوزر ليها |
| `authorized_keys` بتتنكر (لو استخدمت مفاتيح) | ويندوز بيدوّر عليها في `%USERPROFILE%\.ssh`، واليوزر الجديد ملوش بروفايل فبيرجع لـ `C:\Windows\.ssh` | `AuthorizedKeysFile __PROGRAMDATA__/ssh/authorized_keys/%u` (نفس أسلوب مايكروسوفت) |
| لوج sshd مش موجود في ملف | افتراضياً ويندوز بيكتب في الـEvent Log بس | `SyslogFacility LOCAL0` → اللوج في `C:\ProgramData\ssh\logs\sshd.log` |
| **التطبيق بيقول `This server doesn't support UDP`** رغم إن البوابة شغالة | الطول في أول كل إطار (PacketProto length) كان مكتوب **big-endian**، لكن badvpn وكل العملاء بيكتبوه **little-endian** — فالقراءة كانت بتتلغبط في كل إطار والردود كانت بتوصل للعميل بشكل مش مفهوم | الطول بقى **little-endian** في القراءة والكتابة (الـaddress/port/conid بتخرج وتدخل بنفس البايتات بالظبط) |
| العميل بيبعت DNS (TCP/UDP) لراوتر الشبكة المحلية `192.168.1.1` | العنوان ده موجود في شبكة الموبايل، والسيرفر مش قادر يوصله خالص (بيفضل 21 ثانية ويعمل timeout) | البوابة بتعيد توجيه UDP:53 للعناوين اللي السيرفر مايوصلهاش لدنز السيرفر وترد بنفس العنوان الأصلي |
| **رسالة الترحيب (banner) بتظهر رموز مش مفهومة وعلامة `؟`** | `Run.ps1` كان محفوظ **UTF-8 بدون BOM**، وويندوز PowerShell 5.1 بقرا الملفات اللي ملهاش BOM بـ**صفحة الكود ANSI** بتاعة النظام — فكل الحروف غير الـASCII (`ᅠ`, `⚡`, `—»`, النقطة، …) اتلغبطت قبل ما تتكتب في `banner.txt`، واللي مش قابل للتحويل اتحوّل لـ`?` | الملف كله بقى **ASCII خالص**، والحروف الخاصة بتتبني وقت التشغيل من الـcode points (`.Replace('[Cn]',[string][char]0xXXXX)`) — والملف بقى محفوظ UTF-8 **بـBOM** كمان |
| الفيلر في البانر كان مختلف عن المستودع حرف واحد | نسختنا كانت مستخدمة `U+1160` بينما المستودع بيستخدم `U+3164` (HANGUL FILLER) — شكلهم شبه بعض بس البايتات مختلفة | الفيلر اتظبط على `U+3164`، والبانر بقى **مطابق بايت-بايت** للأصلي (`E3 85 A4`) ومفيهوش أي `0x3F`/`?` |
| **السكربت كان بيقف على أول خطوة على سيرفر جديد** — `Get-WindowsCapability : The service cannot be started, either because it is disabled ...` (كود `0x80070422`) | أول خطوة كانت بتنادي `Get-WindowsCapability -Online` (أمر **DISM**) واللي محتاج خدمة **Windows Update (wuauserv)** و/أو **Windows Modules Installer (TrustedInstaller)** تكون قابلة للتشغيل. على نسخ ويندوز "معدّلة" الخدمة دي بتكون **Disabled** فـDISM بيرمي خطأ COM، وبسبب `$ErrorActionPreference = 'Stop'` الخطأ كان بيوقف السكربت كله قبل ما ينصّب أي حاجة | الخطوة بقت كاملة: **تتخطّى DISM تماماً لو OpenSSH موجود أصلاً**، وكل نداءات DISM جوّه `try/catch` فمستحيل توقف السكربت، ولو فشلت بيعمل **إصلاح لخدمات الـservicing** (يحوّل أي خدمة `Disabled` لـManual) ويعيد المحاولة، وكـ**حل أخير** بينزّل حزمة **Win32-OpenSSH الرسمية من مايكروسوفت** (من غير DISM ولا Windows Update خالص) |
| خطوات تانية معرّضة للفشل على سيرفر جديد | فايروول / شهادة / تسجيل التاسك كانت بدون معالجة أخطاء | كلها بقت جوّه `try/catch` مع رسالة واضحة بدل ما السكربت يتوقف |
| **خدمة sshd مش بتقف/مش بتشتغل على سيرفر جديد** — `sshd did not start - Failed to start service 'OpenSSH SSH Server (sshd)'` (وبعدها العميل يوصل TLS لكن مفيش بانر SSH) | 4 أسباب مجتمعة: (1) المفاتيح كانت بتتعمل بـ`ssh-keygen -A` من غير التأكد إنها اتنشأت فعلاً؛ (2) خدمة sshd قديمة/جزئية ممكن تشاور على مسار `sshd.exe` مش موجود؛ (3) لو بورت 22 محجوز بعملية تانية (وكيل المزوّد مثلاً) sshd بيفشل يعمل bind؛ (4) مجموعة `openssh users` اللي في `AllowGroups` كانت بتتعمل **بعد** ما sshd يحاول يقف — وsshd بيرفض يبدأ لو مجموعة في `AllowGroups` مش موجودة | بقى: **إنشاء المجموعة قبل تشغيل sshd**، **توليد صريح لمفاتيح السيرفر لكل نوع (rsa/ecdsa/ed25519) مع التحقق ورسالة عند الفشل**، **كتابة `HostKey` بمسارات مطلقة في `sshd_config`**، **إنشاء مجلد `logs`**، **إصلاح مسار خدمة sshd لو غلط**، **كشف تعارض البورت الداخلي والانتقال تلقائياً لبورت فاضي** (والنفق + الفايروول يتبعوه)، و**تشغيل بإعادة محاولة + تشخيص** (يشغّل `sshd -d` ويطبع السبب الحقيقي والـEvent Log بدل ما يخفيه) |

**ملاحظة عن الـHome folder:** اليوزر الجديد على ويندوز مبيعملوش مجلد شخصي غير لما يسجّل دخول تفاعلي (RDP مثلاً). ده **مش** بيأثر على النفق ولا على المصادقة — كل الاختبارات نجحت واليوزر ملوش بروفايل (النفق + باسورد + مفاتيح).

---

## 8) نتائج الاختبار الفعلي (على السيرفر اللي ركّبناه: Windows Server 2025 / IP 147.93.55.93)

| الاختبار | النتيجة |
|----------|---------|
| مستمع TLS على 443 يوصّل لـ22 | ✅ `TLS12` ثم بانر `SSH-2.0-OpenSSH_for_Windows_9.5` |
| اتصال SSH عادي (بدون TLS) على 443 | ✅ pass-through شغال |
| دخول بالباسورد على 443 | ✅ `teddysun\telegram` |
| دخول بالمفتاح على 443 | ✅ `teddysun\telegram` |
| نقل 1MB والتكامل | ✅ 100% مطابق |
| بوابة UDP 7300 جوّه النفق | ✅ استعلام DNS لـ 8.8.8.8 رجع بـ answer |
| الـUDPGW من بره (أمنياً) | ✅ مستمع على 127.0.0.1 فقط |
| إعادة التشغيل التلقائي | ✅ Scheduled Task `SSH443-Tunnel` (SYSTEM / AtStartup) |
| عميل حقيقي (تلفون) | ✅ ظهر في اللوج: عميل TLS + فتح جلسة UDPGW |
| **UDP مع عميل حقيقي (HTTP Injector)** | ✅ **تحذير `doesn't support UDP` اختفى**، والباكدجات UDP/QUIC (مثال: `142.251.97.94:443`) بتروح وترجع فعلاً |
| تأطير little-endian | ✅ الـkeepalive بيقرأ صح (`len=3`)، وارتداد الـNTP رجع بطول `39 00` (57 little-endian) |
| بانر الترحيب | ✅ مطابق **بايت-بايت** للـ`Server_Message` في المستودع (4428 حرف)، وفيه `U+3164` (`E3 85 A4`) وبدون أي `?` |
| وصول البانر لعميل SSH حقيقي | ✅ اتبعت للعميل بنجاح (`banner received: True`) وبدون علامات `?` |
| شاشة النهاية (النتيجة) | ✅ **v1.5** — نفس شكل المستودع: `• CHANNEL URL:- D_S_D_C1.T.ME` / `• VPS Country:- FR 🇫🇷` / `147.93.55.93:443@telegram:@d_s_d_c1 —» 🇫🇷` / `# DEV:- l_s_I_I.T.ME` / `# Script V ==> 1.5 √` وكل الرموز ظاهرة صح |

> **الاصدار النهائي:** `1.5` — بيطابق المستودع (`Run.sh` + `neofetch` + `Country.sh`) في: شكل بانر الترحيب المحفوظ في `banner.txt`، وشاشة الملخص الأخيرة، واسم/نسخة السكربت.

---

## 9) على السيرفر الحالي: بورت 443 كان واخده caddy

قبل التركيب كنا وقفنا `caddy.exe` بتاع مشروع `API-hCaptcha` (كان واخد 443). لترجيعه لاحقاً:

```powershell
# لازم توقّف النفق الأول عشان يفضى 443
powershell -File C:\Users\Administrator\Desktop\ssh443-win\Stop-Tunnel.ps1
Start-ScheduledTask -TaskName 'hCaptcha-API'
```

(الـAPI بتاع hCaptcha نفسه على `127.0.0.1:9000` ولم يتأثر — اللي وقف هو واجهة HTTPS بس.)

