#!/usr/bin/env bash
#
# PM-02 gateway setup — WireGuard server + per-student isolation base.
#
# Run ONCE on the gateway (the t3.micro in the public subnet):
#   sudo ./gateway-setup.sh
#
# After this, use add-student.sh to add each student peer + their lock-down rule.
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

WG_SUBNET="10.8.0.0/24"     # the VPN network students get an address on
WG_ADDR="10.8.0.1/24"       # the gateway's address inside the VPN
WG_PORT="51820"
WAN="$(ip route | awk '/default/{print $5; exit}')"   # the gateway's internet-facing NIC

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard

# Turn on IP forwarding (the gateway relays student traffic to the targets).
sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Server key pair (only generated once).
umask 077
mkdir -p /etc/wireguard
if [[ ! -f /etc/wireguard/server.key ]]; then
  wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
fi
SRV_PRIV="$(cat /etc/wireguard/server.key)"

# Server config. The firewall default is DROP for forwarded traffic; the only
# thing allowed is return traffic and whatever add-student.sh explicitly permits.
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SRV_PRIV}

# Base firewall: deny all forwarding by default, allow replies, NAT out ${WAN}.
# Per-student "allow to own target" rules are added by add-student.sh.
PostUp = iptables -P FORWARD DROP
PostUp = iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s ${WG_SUBNET} -o ${WAN} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${WG_SUBNET} -o ${WAN} -j MASQUERADE
PostDown = iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -P FORWARD ACCEPT
EOF

systemctl enable --now wg-quick@wg0

echo
echo "=============================================================="
echo " Gateway is up."
echo "   WAN interface : ${WAN}"
echo "   VPN subnet    : ${WG_SUBNET}   (gateway = 10.8.0.1)"
echo "   Listen port   : UDP ${WG_PORT}"
echo "   Server pubkey : $(cat /etc/wireguard/server.pub)"
echo
echo " Next: sudo ./add-student.sh <N> <TARGET_IP>"
echo "       e.g. sudo ./add-student.sh 7 10.0.1.7"
echo "=============================================================="