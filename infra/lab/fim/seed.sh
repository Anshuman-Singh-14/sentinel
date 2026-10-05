#!/bin/sh
# Seeds the FIM demo volume (compose profile "lab", ADR 0015) with a tiny fake
# filesystem, then idles. The worker mounts the same volume read-only at
# /data/fim/demo as the FIM root "demo".
#
#   docker compose exec lab-fim sh /opt/fim/tamper.sh   # make changes to detect
#   docker compose exec lab-fim sh /opt/fim/seed.sh --reset   # back to the original
#
# Nothing here is real: no account, key or hash is valid anywhere.
set -eu
ROOT=/srv/fim

seed() {
    mkdir -p "$ROOT/etc/ssh" "$ROOT/etc/nginx" "$ROOT/etc/cron.d" "$ROOT/usr/local/bin" \
             "$ROOT/var/www/html" "$ROOT/home/app/.ssh" "$ROOT/tmp"
    printf 'root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:App:/home/app:/bin/sh\n' > "$ROOT/etc/passwd"
    printf 'root:!:19000:0:99999:7:::\napp:!:19000:0:99999:7:::\n' > "$ROOT/etc/shadow"
    printf 'root ALL=(ALL:ALL) ALL\n' > "$ROOT/etc/sudoers"
    printf 'Port 22\nPermitRootLogin no\nPasswordAuthentication no\n' > "$ROOT/etc/ssh/sshd_config"
    printf 'server {\n    listen 80;\n    root /var/www/html;\n}\n' > "$ROOT/etc/nginx/nginx.conf"
    printf '0 3 * * * root /usr/local/bin/backup.sh\n' > "$ROOT/etc/cron.d/backup"
    printf '#!/bin/sh\ntar czf /tmp/backup.tgz /var/www\n' > "$ROOT/usr/local/bin/backup.sh"
    printf '<h1>Welcome</h1>\n' > "$ROOT/var/www/html/index.html"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMODEMODEMODEMODEMODEMODEMODEMO app@laptop\n' \
        > "$ROOT/home/app/.ssh/authorized_keys"
    chmod 0644 "$ROOT/etc/passwd" "$ROOT/etc/ssh/sshd_config" "$ROOT/etc/nginx/nginx.conf" \
               "$ROOT/etc/cron.d/backup" "$ROOT/var/www/html/index.html" \
               "$ROOT/home/app/.ssh/authorized_keys"
    chmod 0640 "$ROOT/etc/shadow"      # unreadable by the monitor: metadata only
    chmod 0440 "$ROOT/etc/sudoers"
    chmod 0755 "$ROOT/usr/local/bin/backup.sh"
    chmod 1777 "$ROOT/tmp"             # sticky and world-writable, like /tmp: normal
    echo "lab-fim: demo filesystem seeded"
}

if [ "${1:-}" = "--reset" ]; then
    find "$ROOT" -mindepth 1 -delete
    seed
    exit 0
fi

[ -e "$ROOT/etc/passwd" ] || seed
# Idle until stopped; `exec` makes the shell PID 1 receive SIGTERM directly.
exec sleep infinity
