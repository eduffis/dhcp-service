#!/usr/bin/env python
"""
Autor: erickduffis@gmail.com
This file generates DHCP so that clients can connect.
This process already exists in Linux and other programs, but if you want control, 
I'll give you the power here, so you can study how communication between server and client works. Happy hacking!!
"""
from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import subprocess, sys

# Setting IP range to assign (DHCP)
dhcp_ip_pool = ["192.168.50.%d" % i for i in range(10, 101)]
leased_ips = {}

def send_dhcp_offer(mac_addr, ip_to_assign, transaction_id):
	gateway_ip = "192.168.0.251"  
	dns_ip = "208.67.220.220"     
	subnet_mask = "255.255.255.0" 

	print("Enviando DHCP Offer a:", mac_addr)
	mac = ''.join([chr(int(b, 16)) for b in mac_addr.split(":")]) + '\x00' * 10

	dhcp_offer = (
		Ether(dst=mac_addr) /
		IP(src="192.168.0.16", dst="255.255.255.255") /
		UDP(sport=67, dport=68) /
		BOOTP(op=2, yiaddr=ip_to_assign, siaddr=gateway_ip, chaddr=mac, xid=transaction_id) /
		DHCP(options=[
			("message-type", "offer"),
			("server_id", "192.168.0.16"),
			("subnet_mask", subnet_mask),
			("router", gateway_ip),           
			("lease_time", 3600),
			"end"
		])
	)
	sendp(dhcp_offer, iface="eth0", verbose=False)

def send_dhcp_ack(mac_addr, ip_to_assign, transaction_id):
	gateway_ip = "192.168.0.251"  # Puerta de enlace
	dns_ip = "208.67.220.220"     # Servidor DNS
	subnet_mask = "255.255.255.0" # Mascara de subred

	print("Enviando DHCP ACK a:", mac_addr)
	mac = ''.join([chr(int(b, 16)) for b in mac_addr.split(":")]) + '\x00' * 10
	dhcp_ack = (
		Ether(dst=mac_addr) /
		IP(src="192.168.0.16", dst="255.255.255.255") /
		UDP(sport=67, dport=68) /
		BOOTP(op=5, yiaddr=ip_to_assign, siaddr=gateway_ip, chaddr=mac, xid=transaction_id) /
		DHCP(options=[
			("message-type", "ack"),
			("server_id", "192.168.0.16"),
			("subnet_mask", subnet_mask),
			("router", gateway_ip),            
			("lease_time", 3600),
			"end"
		])
	)
	sendp(dhcp_ack, iface="eth0", verbose=False)

def handle_dhcp(packet):
	if DHCP in packet:
		mac_addr = packet[Ether].src
		dhcp_type = packet[DHCP].options[0][1]
		transaction_id = packet[BOOTP].xid	#This is essential to make the connection, I spent several hours suffering so without the transaction_id the client does not accept the connection
		
		print("dhcp_type: %d"  %dhcp_type)		
		if dhcp_type == 1:  # DHCP Discover
			print("DHCP Discover from %s" % mac_addr)
			if mac_addr not in leased_ips:
				leased_ips[mac_addr] = dhcp_ip_pool.pop(0) if dhcp_ip_pool else None
			ip_to_assign = leased_ips[mac_addr]
			if ip_to_assign:
				send_dhcp_offer(mac_addr, ip_to_assign, transaction_id)
			else:
				print("No IPs available")
		
		elif dhcp_type == 3:  # DHCP Request/ Client receives offer then I send the ack
			print("DHCP Request from %s" % mac_addr)
			ip_to_assign = leased_ips.get(mac_addr)
			if ip_to_assign:
				print("[+] Client acepta la conxion")
				send_dhcp_ack(mac_addr, ip_to_assign, transaction_id)
		
# Configuring NAT to allow WAN access through the machine's current IP (Linux)
def enable_nat():
    subprocess.call("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", shell=True)
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

enable_nat()

# Escuchar solicitudes DHCP
sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp)
