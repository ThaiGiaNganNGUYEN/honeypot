#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y python3 python3-venv python3-pip ufw

if ! id honeypot >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin honeypot
fi

install -d -o honeypot -g honeypot /var/log/honeypot /var/lib/honeypot/keys
python3 -m venv /opt/honeypot/venv
/opt/honeypot/venv/bin/pip install --upgrade pip
/opt/honeypot/venv/bin/pip install -r /vagrant/requirements.txt

rm -rf /opt/honeypot/app
mkdir -p /opt/honeypot/app
cp -a /vagrant/honeypot /vagrant/config /vagrant/requirements.txt /opt/honeypot/app/
chown -R root:root /opt/honeypot/app
chmod -R a+rX /opt/honeypot/app

cp /vagrant/deploy/honeypot.service /etc/systemd/system/honeypot.service
systemctl daemon-reload
systemctl enable honeypot.service
systemctl restart honeypot.service

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "vagrant ssh"
for port in 2222 8080 2121 8090; do
  ufw allow from 192.168.56.0/24 to any port "$port" proto tcp
  ufw allow from 10.0.2.0/24 to any port "$port" proto tcp
done
ufw --force enable
