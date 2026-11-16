#!/usr/bin/env bash
#
# create a WireGuard peer locked to ONE target.
#
# Run on the gateway, after gateway-setup.sh:
#   sudo ./add-student.sh <N> <TARGET_IP>
#     N         = student number 2-254 (their VPN IP becomes 10.8.0.<N>)
#     TARGET_IP = their target's PRIVATE IP in the lab subnet (e.g. 10.0.1.7)
#
# Prints a client config to hand to the student. (For a real rollout the student
# should generate their own key and send you only the public half; generating it
# here is fine for testing.)
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
N="${1:?usage: add-student.sh <N> <TARGET_IP>}"
TARGET="${2:?usage: add-student.sh <N> <TARGET_IP>}"
VPN_IP="10.8.0.${N}"

SRV_PUB="$(cat /etc/wireguard/server.pub)"

# The gateway's public address (for the student's Endpoint). IMDSv2 token call.
TOKEN="$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \
          -H 'X-aws-ec2-metadata-token-ttl-seconds: 120' || true)"
ENDPOINT="$(curl -s -H "X-aws-ec2-metadata-token: ${TOKEN}" \
             http://169.254.169.254/latest/meta-data/public-ipv4 || echo CHANGE_ME)"

umask 077
mkdir -p /etc/wireguard/clients
wg genkey | tee "/etc/wireguard/clients/student${N}.key" \
          | wg pubkey > "/etc/wireguard/clients/student${N}.pub"
CLI_PRIV="$(cat "/etc/wireguard/clients/student${N}.key")"
CLI_PUB="$(cat "/etc/wireguard/clients/student${N}.pub")"

# Register the peer on the live server and persist it in wg0.conf.
wg set wg0 peer "${CLI_PUB}" allowed-ips "${VPN_IP}/32"
cat >>/etc/wireguard/wg0.conf <<EOF

[Peer]
# student ${N} -> target ${TARGET}
PublicKey = ${CLI_PUB}
AllowedIPs = ${VPN_IP}/32
EOF

# ISOLATION: this student's VPN IP may reach ONLY their target. Everything else
# stays denied by the default-DROP policy set in gateway-setup.sh.
iptables -A FORWARD -s "${VPN_IP}" -d "${TARGET}" -j ACCEPT

cat <<EOF

===== give this to student ${N}  (save as student${N}.conf) =====
[Interface]
PrivateKey = ${CLI_PRIV}
Address = ${VPN_IP}/32

[Peer]
PublicKey = ${SRV_PUB}
Endpoint = ${ENDPOINT}:51820
AllowedIPs = ${TARGET}/32
PersistentKeepalive = 25
================================================================
 Student ${N} is now allowed to reach ${TARGET} and nothing else.
 (Firewall rule is live now; it is not reboot-persistent yet — fine for testing.)
EOF