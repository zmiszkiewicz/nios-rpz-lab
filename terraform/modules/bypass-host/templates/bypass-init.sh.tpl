#!/bin/bash
# ---------------------------------------------------------------------------
# Unmanaged "shadow IT" host for the NIOS RPZ lab.
#
# Deliberately configured NOT to use the corporate Grid Master. It points at a
# public DNS service instead, which is exactly how a contractor laptop or an
# unmanaged cloud workload sidesteps a DNS-layer policy: the appliance never
# receives the query, so the RPZ has nothing to act on.
#
# Modelled on the Linux workload host in the genai lab
# (secure-ai-infoblox/scripts/aws-user-data.sh), trimmed to what this
# demonstration needs.
#
# Terraform substitutes three variables into this file: public_resolver,
# fallback_resolver and gm_ip. Those are the only single-dollar brace
# expressions allowed here; anything bash needs to expand itself must use a
# doubled dollar.
# ---------------------------------------------------------------------------
set -x
exec > /var/log/bypass-init.log 2>&1

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y dnsutils curl net-tools

# --- Pin the resolver to a public service ----------------------------------
# systemd-resolved is switched off rather than reconfigured: a lab host with a
# single flat /etc/resolv.conf is far easier to reason about, and the file is
# made immutable so DHCP cannot quietly restore the VPC resolver.
systemctl disable --now systemd-resolved || true
rm -f /etc/resolv.conf
cat > /etc/resolv.conf <<RESOLV
# Unmanaged host — talks straight to a public resolver, bypassing NIOS.
nameserver ${public_resolver}
nameserver ${fallback_resolver}
RESOLV
chattr +i /etc/resolv.conf || true

# --- Helper: report the current resolver and test a few names --------------
cat > /home/ubuntu/show-dns.sh <<'SHOWDNS'
#!/bin/bash
echo "=== Current resolver ==="
grep -E '^nameserver' /etc/resolv.conf | awk '{print "  " $2}'
echo
echo "=== Lookups using that resolver ==="
for d in claude.ai chatgpt.com www.infoblox.com; do
    out=$(dig +short +timeout=3 +tries=1 "$d" A 2>/dev/null | grep -E '^[0-9]' | head -3 | tr '\n' ' ')
    status=$(dig +timeout=3 +tries=1 "$d" A 2>/dev/null | awk '/^;; ->>HEADER<<-/ {print $6}' | tr -d ',')
    if [ -n "$out" ]; then
        printf "  %-22s RESOLVED  %s\n" "$d" "$out"
    else
        # Doubled dollar below so templatefile leaves the brace expansion for
        # bash instead of evaluating it. Never write a single-dollar brace
        # expression in this file, not even inside a comment.
        printf "  %-22s %-9s (no answer)\n" "$d" "$${status:-TIMEOUT}"
    fi
done
SHOWDNS

# --- Helper: switch to the corporate Grid Master ---------------------------
cat > /home/ubuntu/use-corporate-dns.sh <<CORPDNS
#!/bin/bash
sudo chattr -i /etc/resolv.conf
sudo tee /etc/resolv.conf >/dev/null <<RESOLV
# Managed host — resolving through the corporate Grid Master.
nameserver ${gm_ip}
RESOLV
sudo chattr +i /etc/resolv.conf
echo "Resolver is now ${gm_ip} — the corporate Grid Master."
echo "Re-run ./show-dns.sh to see the policy apply."
CORPDNS

# --- Helper: switch back to the public resolver ----------------------------
cat > /home/ubuntu/use-public-dns.sh <<PUBDNS
#!/bin/bash
sudo chattr -i /etc/resolv.conf
sudo tee /etc/resolv.conf >/dev/null <<RESOLV
# Unmanaged host — talks straight to a public resolver, bypassing NIOS.
nameserver ${public_resolver}
nameserver ${fallback_resolver}
RESOLV
sudo chattr +i /etc/resolv.conf
echo "Resolver is back to ${public_resolver} — outside corporate policy."
PUBDNS

chmod +x /home/ubuntu/show-dns.sh /home/ubuntu/use-corporate-dns.sh /home/ubuntu/use-public-dns.sh
chown ubuntu:ubuntu /home/ubuntu/show-dns.sh /home/ubuntu/use-corporate-dns.sh /home/ubuntu/use-public-dns.sh

hostnamectl set-hostname unmanaged-host

echo "bypass host ready"
