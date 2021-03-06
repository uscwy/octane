#!/bin/sh

IP_OF_ETH0=10.0.2.15

sudo ifconfig eth1 192.168.201.2/24 up
sudo ifconfig eth2 192.168.202.2/24 up
sudo ifconfig eth3 192.168.203.2/24 up
sudo ifconfig eth4 192.168.204.2/24 up

sudo ip tuntap add dev tun1 mode tun
sudo ifconfig tun1 10.5.51.2/24 up
sudo ip route add table 9 to 128.52/16 dev tun1

sudo ip rule add from $IP_OF_ETH0 table 9 priority 8
sudo ip route add table 9 to 18/8 dev tun1
sudo ip route add table 9 to 128.30/16 dev tun1

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -t nat -A OUTPUT -s 192.168.201.2 -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080


