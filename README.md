# Installer WSL2 sur Windows 10

## Prérequis

Etre en version de Windows 10 Pro 1903 (Mars 2019) minimum
Démarrer / Exécuter : appwiz.cpl
Activer ou désactiver des fonctionnalités de Windows
Cocher "Plateforme d'ordinateur virtuel" et "Sous-système Windows pour Linux"
Redémarrer le PC pour installer les composants

Se rendre sur le site de microsoft pour Télécharger le package de mise à jour en WSL2
Étapes d’installation manuelle pour les versions antérieures de WSL | Microsoft Docs
[WSL2 UPDATE](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi "WSL2 Update")


### Activation Hyper-V
`C:\>bcdedit /set hypervisorlaunchtype auto`

L’opération a réussi.


## Configuration WSL2

Ouvrir ensuite un CMD en tant qu'administrateur

### Définir la version 2 par défaut pour les nouvelles machines
`C:\>wsl --set-default-version 2`

Pour plus d’informations sur les différences de clés avec WSL 2, visitez https://aka.ms/wsl2
L’opération a réussi.

### Lister les images disponibles
`C:\>wsl --list --online`
Voici la liste des distributions valides qui peuvent être installées.
Installer à l’aide de « wsl --install -d <Distribution> ».

NAME            FRIENDLY NAME
Ubuntu          Ubuntu
Debian          Debian GNU/Linux
**kali-linux      Kali Linux Rolling**
openSUSE-42     openSUSE Leap 42
SLES-12         SUSE Linux Enterprise Server v12
Ubuntu-16.04    Ubuntu 16.04 LTS
Ubuntu-18.04    Ubuntu 18.04 LTS
Ubuntu-20.04    Ubuntu 20.04 LTS


## Installation de Kali Linux

### Lancement de l'installation
`C:\>wsl --install -d kali-linux`
Kali Linux Rolling est déjà installé.
Lancement de Kali Linux Rolling...


### Une fois lancé, renseigner le nom d'utilisateur et le mot de passe souhaité
Installing, this may take a few minutes...
Please create a default UNIX user account. The username does not need to match your Windows username.
For more information visit: https://aka.ms/wslusers
Enter new UNIX username: **kali**
New password:
Retype new password:
passwd: password updated successfully
Installation successful!

### Vérifier qu'on est bien en WSL2
`kali@HOST:~$ uname -a
Linux HOST 5.10.16.3-microsoft-standard-WSL2 #1 SMP Fri Apr 2 22:23:49 UTC 2021 x86_64 GNU/Linux`

### Dans le CMD, vérifier qu'on est bien en WSL2
C:\>**wsl --list -v**
  NAME          STATE           VERSION
* kali-linux    Running         2

### Afin de faire fonctionner les mises à jour correctement, j'ai du effectuer les actions suivantes :
root@HOST:/tmp# **wget --no-check-certificate https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2020.2_all.deb**
root@HOST:/tmp# **dpkg -i kali-archive-keyring_2020.2_all.deb**
root@HOST:~# **apt update**

### S'il y a une erreur par rapport à libcrypt, procéder comme suit :
root@HOST:~# **cd /tmp**
root@HOST:~# **chmod 1777 /tmp**
root@HOST:~# **apt -y download libcrypt1**
root@HOST:~# **dpkg-deb -x libcrypt1_1%3a4.4.25-2_amd64.deb  .**
root@HOST:~# **cp -av lib/x86_64-linux-gnu/* /lib/x86_64-linux-gnu/**
root@HOST:~# **apt -y --fix-broken install**


## Accès en graphique

2 solutions simples s'offrent à nous

###Installation d'un serveur TSE dans WSL2
sudo apt install xfce4
sudo apt install xrdp
sudo /etc/init.d/xrdp start

Il ne reste plus qu'à se connecter en terminal server sur notre Kali.


Autre option :

### Installation d'un serveur X

Téléchargement de VcXsrv Windows X Server - [VCXSRV](https://sourceforge.net/projects/vcxsrv)

#### Installer le serveur X
Lancer ensuite XLaunch

Choisir "Multiple Windows" puis "Start no client"
Ensuite, bien cocher "Disable access control"
Suivant, puis Terminer


## Paramétrage Kali

Si on a choisi l'option Serveur X

### On export notre variable display vers le serveur X de notre machine windows et on test en lançant Firefox
root@HOST:/# **vi ~/.bashrc**

Ajouter les 2 lignes suivantes à la fin du fichier
**export DISPLAY="$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf 2>/dev/null):0"**
**export LIBGL_ALWAYS_INDIRECT=1**

### Ajout d'un alias pour afficher son adresse IP
alias my="ip addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'"

### Appliquer les modifications
root@HOST:/# **source ~/.bashrc**



## Installation des packages pour passer d'une Kali de base à une CTF War Machine !
root@HOST:/# **apt-get install -y binwalk bloodhound burpsuite crackmapexec default-mysql-client dirb dirbuster dnsrecon enum4linux exploitdb exploitdb ffuf firefox-esr ftp-ssl gedit git gobuster hashcat hydra john joomscan libjenkins-htmlunit-core-js-java lightdm-remote-session-freerdp2 mariadb-client metasploit-framework netcat-traditional netdiscover nfs-common nikto nmap openvpn powershell-empire python3-pip python3-scapy python3-shodan seclists smbclient smbmap smtp-user-enum sqlite3 sqlmap sslscan sublist3r traceroute webext-foxyproxy wireshark wordlists wpscan wpscan zaproxy zsh **

### Installation des modules Python de base
root@HOST:/# pip3 install keyboard pyfiglet paramiko git-dumper

### Création d'une arborescence dédiée
sudo mkdir -p /opt/recon
sudo mkdir -p /opt/linux
sudo mkdir -p /opt/web
sudo mkdir -p /opt/windows
sudo mkdir -p /opt/impacket

### Installation de la suite Impacket
cd /opt
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/
pip3 install -r requirements.txt
python3 ./setup.py install

### Installation de evil-winrm
gem install evil-winrm winrm-fs stringio

### Installation de pywsus
git clone https://github.com/GoSecure/pywsus
virtualenv -p /usr/bin/python3 ./venv
source ./venv/bin/activate
pip install -r ./requirements.txt


### Téléchargement de procdump
wget https://live.sysinternals.com/procdump.exe
wget https://live.sysinternals.com/procdump64.exe


### Téléchargement de wordlists
wget https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Dictionary-Style/Technical_and_Default/Password_Default_ProbWL.txt
wget https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Dictionary-Style/Technical_and_Default/Username_Default_ProbWL.txt
apt install wordlists

cd /usr/share/wordlists
sudo wget https://gist.githubusercontent.com/TylerRockwell/1f24a4b237627811b449db9f90804e84/raw/6371edc42c0b8ce77552b8ff995d858629f38ddd/100_common_passwords
sudo wget https://gist.githubusercontent.com/TylerRockwell/e66bb76374aba34ed430dab2617e9d4a/raw/9733e873326835ed91fe63cc269d69b0cb559160/1000_common_passwords
sudo wget https://gist.githubusercontent.com/TylerRockwell/ab97b16045c3993edf528f8012b8fffa/raw/8c28863bc8361c14903ba11b99122473ed05ec0a/10000_common_passwords

### Récupération de Rubeus
mkdir /opt/windows
cd /opt/windows
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe

### Récupération de WinPeas
cd /opt/windows
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x86/Release/winPEASx86.exe
wget https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe

### Téléchargement de psexec
cd /opt/windows
wget https://download.sysinternals.com/files/PSTools.zip
wget https://live.sysinternals.com/PsExec.exe
wget https://live.sysinternals.com/PsExec64.exe

### Téléchargement de Mimikatz
cd /opt/windows
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip
unzip mimikatz_trunk.zip -d mimikatz

### Téléchargement de Powerview
cd /opt/windows
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1

### Récupération de LinPeas
mkdir /opt/linux
cd /opt/linux
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh

### Récupération de PowerUp
cd /opt/windows
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

### Réccupération du repo de scripts Powershell Nishang
cd /opt
git clone https://github.com/samratashok/nishang.git

### Installation de CMSMap
mkdir /opt/web
cd /opt/web
git clone https://github.com/Dionach/CMSmap
cd CMSmap
pip3 install .

### Récupération de JoomBlah
cd /opt/web
wget https://raw.githubusercontent.com/XiphosResearch/exploits/master/Joomblah/joomblah.py

### Récupération du PrintSpoofer (élévation de privilèges) et CVE-2017-0213_x64
mkdir /opt/windows/privesc
cd /opt/windows/privesc/
wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/CVE-2017-0213/CVE-2017-0213_x64.zip

### Récupération de Kerbrute
cd /opt/windows
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64

### Récupération du script Kerberoast
cd /opt/windows
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1

### Installation de Weevely
cd /opt/web
git clone https://github.com/epinna/weevely3.git
cd weevely3/
pip3 install -r requirements.txt --upgrade


### Installation de NMAP Automator
mkdir /opt/recon
cd /opt/recon
wget https://raw.githubusercontent.com/21y4d/nmapAutomator/master/nmapAutomator.sh
chmod u+x ./nmapAutomator.sh

### SQLi Dictionary
wget https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/xplatform.txt

### Burp Suite Jython
cd /opt/web
wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar

### Installation de Nessus
Enregistrement sur le site : https://www.tenable.com/products/nessus/nessus-essentials
Téléchargement du package pour Kali : Nessus-10.0.2-debian6_amd64.deb 
Création d'un répertoire de travail : mkdir /opt/nessus && cd /opt/nessus
Installation du package : sudo dpkg -i Nessus-10.0.2-debian6_amd64.deb
Comme Kali en WSL2 n'utilise pas systemd, on a une erreur pour démarrer Nessus

┌──(root💀HOST)-[/opt/nessus]
└─# dpkg -i Nessus-10.0.2-debian6_amd64.deb
Selecting previously unselected package nessus.
(Reading database ... 225268 files and directories currently installed.)
Preparing to unpack Nessus-10.0.2-debian6_amd64.deb ...
Unpacking nessus (10.0.2) ...
Setting up nessus (10.0.2) ...
Unpacking Nessus Scanner Core Components...
System has not been booted with systemd as init system (PID 1). Can't operate.
Failed to connect to bus: Host is down

 - You can start Nessus Scanner by typing /bin/systemctl start nessusd.service
 - Then go to https://HOST:8834/ to configure your scanner

Il faut lancer Nessus à la main : /opt/nessus/sbin/nessus-service &

Ensuite, on lance Firefox : firefox https://localhost:8834/
On crée son compte en ligne en choisissant un nickname et on continue
Nessus télécharge alors tous les fichiers nécessaires (plugins)









## DNAT depuis Windows
On peut si besoin, configurer une règle de DNAT sur Windows pour accéder directement à la VM Kali depuis le reste du réseau
PS C:\> netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=4444 connectaddress=<IP KALI>

On créé ensuite l'autorisation firewall associée
PS C:\> netsh advfirewall firewall add rule name="WSL2 4444" dir=in action=allow protocol=tcp localip=any remoteip=any localport=4444
Ok.

Si besoin de désactiver le firewall
PS C:\> netsh advfirewall set allprofiles state off
Ok.
Ou 
PS C:\> Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Script pour automatiser l'action avec le changement d'IP à chaque démarrage

