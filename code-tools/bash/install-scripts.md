# Install Scripts

## Install Powershell on Linux

```
apt-get install libunwind8
wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb7u3_amd64.deb
dpkg -i libssl1.0.0_1.0.1t-1+deb7u3_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7ubuntu0.3_amd64.deb
dpkg -i libicu55_55.1-7ubuntu0.3_amd64.deb
wget https://github/com/Powershell/Powershell/releases/download/v6.0.2/powershell_6.0.2-1.ubuntu.16.04_amd64.deb
dpkg -i powershell_6.0.2-1.ubuntu.16.04_amd64.deb
```

## Install PenTesters Framework

```
sudo su -
apt-get update
apt-get install python
git clone https://github.com/trustedsec/ptf/opt/ptf
cd /opt/ptf && ./ptf
use modules/exploitation/install_update_all
use modules/intelligence-gathering/install_update_all
use modules/post-exploitation/install_update_all
use modules/powershell/install_update_all
use modules/vulnerability-analysis/install_update_all
cd /pentest
```
