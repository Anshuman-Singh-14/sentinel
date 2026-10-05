#!/bin/sh
# Makes the changes a File Integrity Check should find (ADR 0015). Run it after
# creating a baseline of the "demo" root:
#   docker compose exec lab-fim sh /opt/fim/tamper.sh
set -eu
ROOT=/srv/fim

# MODIFIED, HIGH: SSH now allows root logins with passwords.
printf 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n' > "$ROOT/etc/ssh/sshd_config"
# MODIFIED, CRITICAL: an extra key that can log in as "app".
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKERATTACKERATTACKERATTACKER x@evil\n' \
    >> "$ROOT/home/app/.ssh/authorized_keys"
# ADDED, MEDIUM: a web shell in the web root.
printf '<?php /* demo web shell, inert */ ?>\n' > "$ROOT/var/www/html/shell.php"
# ADDED with setuid, CRITICAL: a root-owned helper anyone can run as root.
printf '#!/bin/sh\necho demo\n' > "$ROOT/usr/local/bin/helper"
chmod 4755 "$ROOT/usr/local/bin/helper"
# METADATA_CHANGED escalated to HIGH: the backup script becomes world-writable.
chmod 0777 "$ROOT/usr/local/bin/backup.sh"
# REMOVED, HIGH: a scheduled job disappears.
rm -f "$ROOT/etc/cron.d/backup"
# Touched only (same content, new mtime): counted, not reported.
touch "$ROOT/var/www/html/index.html"
echo "lab-fim: 7 changes made (6 reported, 1 timestamp-only)"
