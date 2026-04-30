# Argus Rails Deployment Notes (RHEL / STIG-style)

## Architecture Overview

User → HTTPS (443)
      ↓
Apache ([httpd + mod_ssl + optional mod_auth_openidc])
      ↓ (Unix socket)
Puma (/run/argus/puma/puma.sock)
      ↓
Rails app
      ↓
PostgreSQL (peer auth, Unix socket)
      ↓
Redis (Unix socket)

---

## Security Model

- Only port 443 exposed
- No Password for local PostgreSQL
- No TCP access to:
  - Puma
  - PostgreSQL
  - Redis
- Unix sockets used internally
- Rails runs as non-login user
- Apache is the only public entry point

---

## Service User

useradd --system --home /var/lib/argus --shell /usr/sbin/nologin argus
passwd -l argus

---

## PostgreSQL Setup

postgresql-setup --initdb
systemctl enable --now postgresql

pg_hba.conf:

local   argus   argus   peer
host    argus   argus   127.0.0.1/32   reject
host    argus   argus   ::1/128        reject

postgresql.conf:

listen_addresses = ''
unix_socket_directories = '/var/run/postgresql'

sudo -u postgres createuser --no-superuser --no-createdb --no-createrole argus
sudo -u postgres createdb --owner=argus argus

---

## Redis Setup

/etc/redis/redis.conf:

port 0
protected-mode yes

unixsocket /run/redis/redis.sock
unixsocketperm 770

supervised systemd

usermod -aG redis argus

echo "vm.overcommit_memory = 1" > /etc/sysctl.d/99-argus-redis.conf
sysctl --system

---

## Puma Config

environment ENV.fetch("RAILS_ENV") { "production" }

directory "/var/lib/argus"

bind "unix:///run/argus/puma/puma.sock?umask=0007"

pidfile "/run/argus/puma/puma.pid"
state_path "/run/argus/puma/puma.state"

workers 2
threads 1, 5

preload_app!

---

## systemd Service

/etc/systemd/system/argus.service:

[Unit]
After=network-online.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
User=argus
Group=argus
SupplementaryGroups=redis

WorkingDirectory=/var/lib/argus

Environment=RAILS_ENV=production
Environment=REDIS_URL=unix:///run/redis/redis.sock

RuntimeDirectory=argus/puma
RuntimeDirectoryMode=0750

ExecStartPre=/usr/bin/pg_isready -h /var/run/postgresql -U argus -d argus
ExecStart=/usr/bin/bash -lc 'bundle exec puma -C config/puma.rb'

Restart=on-failure

ReadWritePaths=/var/lib/argus/tmp /var/lib/argus/log /run/argus/puma /run/redis /var/run/postgresql

---

## Apache Config

/etc/httpd/conf.d/argus.conf:

<VirtualHost *:443>
    ServerName argus.example.com

    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/argus.crt
    SSLCertificateKeyFile /etc/pki/tls/private/argus.key

    ProxyRequests Off
    ProxyPreserveHost On

    RequestHeader set X-Forwarded-Proto "https"

    RequestHeader unset X-Authenticated-User
    RequestHeader unset X-Authenticated-Email
    RequestHeader unset X-Authenticated-Groups

    ProxyPass        / unix:/run/argus/puma/puma.sock|http://localhost/
    ProxyPassReverse / unix:/run/argus/puma/puma.sock|http://localhost/
</VirtualHost>

---

## TLS (Dev)

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/pki/tls/private/argus.key \
  -out /etc/pki/tls/certs/argus.crt \
  -days 365 \
  -subj "/CN=argus.example.com"

---

## Firewall

firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --remove-service=http
firewall-cmd --reload

---

## Debugging

systemctl status argus
journalctl -u argus -n 100

ls -l /run/argus/puma

tail -f /var/log/httpd/error_log

sudo -u argus psql -h /var/run/postgresql -d argus
sudo -u argus redis-cli -s /run/redis/redis.sock ping

---

## Common Issues

503:
Apache cannot reach Puma socket

Fix:
- Ensure /run/argus/puma exists
- Check permissions
- Check SELinux

systemd failure:
RuntimeDirectory wrong

Fix:
RuntimeDirectory=argus/puma

Puma failure:
Missing Gemfile

Fix:
Ensure Rails app exists in /var/lib/argus

---

## Final Summary

- No DB passwords (peer auth)
- No Redis TCP
- No Puma exposure
- Only HTTPS exposed
- Rails handles users/roles
- Apache handles TLS/auth
EOF