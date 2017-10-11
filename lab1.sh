#!/bin/sh

### Firewall lab ###

OUT_IFACE=eth0
DMZ_IFACE=eth1
IN_IFACE=eth3
ADM_IFACE=eth4

LAMP_SERVER=192.168.1.20

# Flush and policies.
iptables -F INPUT
iptables -F OUTPUT
iptables -F FORWARD
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

### Milestone 1 ###

# Open SSH and HTTP ports from the ADM subnet.
iptables -A INPUT -i $ADM_IFACE -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i $ADM_IFACE -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -o $ADM_IFACE -p tcp --sport 22 -j ACCEPT
iptables -A OUTPUT -o $ADM_IFACE -p tcp --sport 80 -j ACCEPT

# Open DHCP ports from the IN subnet.
iptables -A INPUT -i $IN_IFACE -p udp --dport 67 --sport 68 -j ACCEPT
iptables -A OUTPUT -o $IN_IFACE -p udp --dport 68 --sport 67 -j ACCEPT

# Allow all hosts to ping the firewall.
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow the firewall to ping the hosts.
iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT

# Allow traceroute from the firewall.
iptables -A OUTPUT -p udp -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 11 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 3 -j ACCEPT


### Milestone 2 ###

# Allow traffic between internal nets.
# Allow connections from ADM and IN to OUT.
iptables -A FORWARD -i $ADM_IFACE -j ACCEPT
iptables -A FORWARD -i $IN_IFACE -j ACCEPT
iptables -A FORWARD -i $DMZ_IFACE -j ACCEPT
iptables -A FORWARD -i $OUT_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow HTTP connections to LAMP server.
iptables -A FORWARD -i $OUT_IFACE -d $LAMP_SERVER -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD ! -i $ADM_IFACE -d $LAMP_SERVER -p tcp --dport 22 -j DROP


### Milestone 3 ###

iptables -t nat -A POSTROUTING -o $OUT_IFACE -j MASQUERADE
iptables -t nat -A PREROUTING -i $OUT_IFACE -p tcp --dport 80 -j DNAT --to-destination ${LAMP_SERVER}:80
iptables -A FORWARD -i $OUT_IFACE -p tcp --dport 80 -j ACCEPT