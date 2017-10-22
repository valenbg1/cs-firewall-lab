#!/bin/sh

### Firewall lab ###

OUT_IFACE=eth0
DMZ_IFACE=eth1
DC_IFACE=eth2
IN_IFACE=eth3
ADM_IFACE=eth4

LAMP_SERVER=192.168.1.20

DMZ_NET=192.168.1.0/24
DC_NET=10.0.2.0/24
IN_NET=10.0.3.0/24
ADM_NET=10.0.4.0/24

# Flushes.
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD

iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING

iptables -t raw -F PREROUTING

# Default policies.
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP


### Milestone 1 ###

# Comented OUTPUT rules, since default policy is ACCEPT.

# Open SSH and HTTP ports for the ADM subnet.
iptables -A INPUT -i $ADM_IFACE -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i $ADM_IFACE -p tcp --dport 80 -j ACCEPT
#iptables -A OUTPUT -o $ADM_IFACE -p tcp --sport 22 -j ACCEPT
#iptables -A OUTPUT -o $ADM_IFACE -p tcp --sport 80 -j ACCEPT

# Open DHCP port for the IN subnet.
iptables -A INPUT -i $IN_IFACE -p udp --dport 67 --sport 68 -j ACCEPT
#iptables -A OUTPUT -o $IN_IFACE -p udp --dport 68 --sport 67 -j ACCEPT

# Allow all hosts to ping the firewall.
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
#iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow the firewall to ping the hosts.
#iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow the firewall to traceroute.
#iptables -A OUTPUT -p udp -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 11 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 3 -j ACCEPT


### Challenge 1 ###
iptables -A INPUT -p udp -j REJECT


### Challenge 3 ###

iptables -A FORWARD -i $DMZ_IFACE ! -s $DMZ_NET -j DROP
iptables -A FORWARD -i $DC_IFACE ! -s $DC_NET -j DROP
iptables -A FORWARD -i $IN_IFACE ! -s $IN_NET -j DROP
iptables -A FORWARD -i $ADM_IFACE ! -s $ADM_NET -j DROP

iptables -A FORWARD -i $OUT_IFACE -s $DMZ_NET,$DC_NET,$IN_NET,$ADM_NET -j DROP


### Milestone 2 ###

# Allow RELATED and ESTABLISHED traffic from OUT.
iptables -A FORWARD -i $OUT_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow HTTP and SSH connections to LAMP server.
iptables -A FORWARD -i $OUT_IFACE -d $LAMP_SERVER -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i $DMZ_IFACE -s $LAMP_SERVER -p tcp --sport 80 -j ACCEPT
iptables -A FORWARD ! -i $ADM_IFACE -d $LAMP_SERVER -p tcp --dport 22 -j DROP

# Allow DMZ, DC, ADM and IN to exchange traffic.
iptables -A FORWARD -i $DMZ_IFACE -o $OUT_IFACE -j DROP
iptables -A FORWARD -i $DC_IFACE -o $OUT_IFACE -j DROP

iptables -A FORWARD -i $DMZ_IFACE -j ACCEPT
iptables -A FORWARD -i $DC_IFACE -j ACCEPT
iptables -A FORWARD -i $ADM_IFACE -j ACCEPT
iptables -A FORWARD -i $IN_IFACE -j ACCEPT


### Challenge 2 (should be commented for milestone 3) ###
iptables -A PREROUTING -t raw -i $OUT_IFACE -d $LAMP_SERVER -p tcp --dport 80 -j NOTRACK
iptables -A PREROUTING -t raw -i $DMZ_IFACE -s $LAMP_SERVER -p tcp --sport 80 -j NOTRACK


### Milestone 3 ###

iptables -t nat -A POSTROUTING -o $OUT_IFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $OUT_IFACE -p tcp --dport 80 -j DNAT --to-destination ${LAMP_SERVER}:80

# Already allowed.
#iptables -A FORWARD -i $OUT_IFACE -p tcp --dport 80 -j ACCEPT