# -*- coding: utf-8 -*-

"""
This file contains API calls and Data
"""

import six

from sys import path
from termcolor import colored
from os import geteuid
from os import path

from .data import *

__version__ = "1.0.0"
__all__ = ["run_console", "run", "GlobalParameters"]


# --------------------------------------------------------------------------
#
# Command line options
#
# --------------------------------------------------------------------------
def run_console(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))

    #six.print_(colored("[*]", "blue"), "Starting NetPyntest execution")
    run(config)
    #six.print_(colored("[*]", "blue"), "Done!")


# ----------------------------------------------------------------------
#
# API call
#
# ----------------------------------------------------------------------
def run(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))



    # --------------------------------------------------------------------------
    #   CHECK ROOT USER
    # --------------------------------------------------------------------------
    if geteuid():
        six.print_(colored("[!] ERROR - Please run NetPyntest as root.", "red"))
        exit()

    # --------------------------------------------------------------------------
    #   CHECK CONFIG FILE
    # --------------------------------------------------------------------------
    if  not path.isfile("control_file"):
        six.print_("Creating config_file")
        control_file = open("control_file", "w")
        data = {'mac_flooding_pid': 0, 'port_stealing_pid': 0}
        control_file.write(str(data))
        control_file.close()

    # --------------------------------------------------------------------------
    #   SELECT & LAUNCH ATTACK
    # --------------------------------------------------------------------------

    attack = config.attack[0]
    action = config.action[0]
    if config.interface != None:
        iface = config.interface[0]
        #TODO valid interface and introduce interface in calls
    else:
        iface = "eth0"

    ################    MAC FLOODING    ##############

    if attack == "mac_flooding":
        from .libs.plugins.mac_flooding import start
        from .libs.plugins.mac_flooding import stop
        from .libs.plugins.mac_flooding import generate_pcap

        if action == "start":#TODO This is not working for Python 2
            from sys import version_info
            if version_info[0] >=3:
                if config.file != None:
                    file = config.file[0]
                    if path.isfile(file):
                        six.print_("[*] Starting MAC Flooding with file '{}'...".format(file))
                        from scapy.error import Scapy_Exception
                        try:
                            start(file, iface)
                        except Scapy_Exception:
                            six.print_(colored("[!] ERROR - File '{}' is not a valid PCAP file".format(file), "red"))
                    else:
                        six.print_(colored("[!] ERROR - File '{}' doesn't exist.".format(file), "red"))
                else:
                    six.print_(colored("[!] ERROR - You must specify a PCAP file. You can generate one with 'sudo python netpyntest.py mac_flooding generate_pcap'", "red"))
            else:
                six.print_(colored("[!] ERROR - Sorry, currently this feature is only supported in Python 3 or higher", "red"))

        elif action == "stop":
            stop()


        elif action == "generate_pcap":
            if config.size == None:
                six.print_("[*] Generating PCAP file with default size of 10000 packets")
                generate_pcap(10000)
            else:
                size = config.size[0]
                six.print_("[*] Generating PCAP file with size of {} packets".format(size))
                generate_pcap(size)

            six.print_(colored("[*] PCAP file generated", "green"))
        else:
            six.print_(colored("[!] ERROR - Action {} doesn't exist for MAC Flooding attack".format(action), "red"))


    ################    PORT STEALING    ##############

    elif attack == "port_stealing":
        if action == "start":

            if config.target != None:
                target = config.target[0]

                if validate_ip(target):

                    if config.output != None:
                        output = config.output[0]
                        from .libs.plugins.port_stealing import start
                        six.print_("[*] Starting Port Stealing...")
                        start(target, output, iface)

                    else:
                        six.print_(colored("[!] ERROR - No output file specified (-o)", "red"))

                else:
                    six.print_(colored("[!] ERROR - IP isn't valid. Enter valid IPv4 address (-t)", "red"))

            else:
                six.print_(colored("[!] ERROR - You must specify a target (-t)", "red"))


        elif action == "stop":
            from .libs.plugins.port_stealing import stop
            six.print_("[*] Stopping Port Stealing...")
            stop()

        else:
            six.print_(colored("[!] ERROR - Action {} doesn't exist for Port Stealing attack".format(action), "red"))

    ################    SNMP    ##############



    elif attack == "snmp":




        if action == "sniff":
            from .libs.plugins.snmp import sniff_snmp
            six.print_("[*] Starting SNMP sniffing...")
            sniff_snmp(iface)

        elif action == "get":

            if config.com != None:
                com = config.com[0]
            else:
                com = "public"

            if config.target != None:
                target = config.target[0]

                if validate_ip(target):

                        if config.oid != None:
                            oid = config.oid[0]
                            from .libs.plugins.snmp import snmp_get
                            six.print_("[*] Performing SNMP GET request against host {} and OID {}...".format(target, oid))
                            snmp_get(target, oid, iface, com)

                        else:
                            six.print_(colored("[!] ERROR - No OID specified (-oid)", "red"))
                else:
                    six.print_(colored("[!] ERROR - IP isn't valid. Enter valid IPv4 address.", "red"))
            else:
                six.print_(colored("[!] ERROR - You must specify a target (-t)", "red"))


        elif action =="set":

            if config.com != None:
                com = config.com[0]
            else:
                com = "private"

            if config.target != None:
                target = config.target[0]

                if validate_ip(target):

                    if config.oid != None:
                        oid = config.oid[0]

                        if config.value != None:
                            val = config.value[0]

                            from .libs.plugins.snmp import snmp_set
                            six.print_("[*] Performing SNMP SET request against host {}. Trying to set value {} in object {}...".format(target, val, oid))
                            snmp_set(target, oid, iface, com, val)

                        else:
                            six.print_(colored("[!] ERROR - No value specified (-v)", "red"))
                    else:
                        six.print_(colored("[!] ERROR - No OID specified (-oid)", "red"))
                else:
                    six.print_(colored("[!] ERROR - IP isn't valid. Enter valid IPv4 address (-t)", "red"))
            else:
                six.print_(colored("[!] ERROR - You must specify a target (-t)", "red"))


        elif action == "dictionary_attack":
            if config.target != None:
                target = config.target[0]
                if validate_ip(target):
                    if config.dict != None:
                        dict = config.dict[0]
                        if path.isfile(dict):
                            from .libs.plugins.snmp import dictionary_attack
                            six.print_("[*] Starting SNMP dictionary attack...")
                            dictionary_attack(dict, target, iface)
                        else:
                            six.print_(colored("[!] ERROR - File '{}' doesn't exist.".format(dict), "red"))
                    else:
                        six.print_(colored("[!] ERROR - You must specify a dictionary file (-d)", "red"))
                else:
                    six.print_(colored("[!] ERROR - IP isn't valid. Enter valid IPv4 address (-t)", "red"))
            else:
                six.print_(colored("[!] ERROR - You must specify a target (-t, --target)", "red"))


        elif action == "dos":

            if config.com != None:
                com = config.com[0]
            else:
                com = "private"

            if config.target != None:
                target = config.target[0]

                if validate_ip(target):
                    from .libs.plugins.snmp import snmp_DoS
                    six.print_("[*] Starting DoS attack to host {} with RW community {}...".format(target, com))
                    snmp_DoS(target, iface, com)

                else:
                    six.print_(colored("[!] ERROR - IP isn't valid. Enter valid IPv4 address (-t, --target)", "red"))
            else:
                six.print_(colored("[!] ERROR - You must specify a target (-t)", "red"))
        else:
            six.print_(colored("[!] ERROR - Action {} doesn't exist for SNMP".format(action), "red"))

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True
