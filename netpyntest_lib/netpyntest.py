# -*- coding: utf-8 -*-

import argparse
import logging
import six

logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger(__name__)

# ----------------------------------------------------------------------
def discover_plugins():
    """
    This function try to discover installed plugins dinamically
    :return: a list with plugins names
    :rtype: list(str)
    """
    from os import listdir
    from os.path import join, abspath, dirname

    path = join(abspath(dirname(__file__)), "libs", "plugins")

    plugin_list = []

    for f in listdir(path):
        if not f.startswith("__") and f.endswith(".py"):
            plugin_list.append(f.replace(".py", ""))

    return plugin_list

# ----------------------------------------------------------------------
def main():
    plugins = discover_plugins()

    try:
        from .api import run_console, GlobalParameters
    except ImportError as e:
        six.print_("\n[!] You need to install dependency: '%s'\n" % str(e).replace("No module named ", ""))

        six.print_("To install missing dependencies doing: \n")
        six.print_("# pip install scapy termcolor six sphinx\n")#Dependencies!


    examples = '''
Usage examples:

  Use START commands with & to keep the prompt!

  python %(tool_name)s.py mac_flooding   start -f PCAP_FILE [-i INTERFACE] &
                                      stop
                                      generate_pcap [-s SIZE]
  python %(tool_name)s.py port_stealing  start -t TARGET -o OUTPUT [-i INTERFACE] &
                                      stop

  python %(tool_name)s.py snmp           sniff [-i INTERFACE]
                                      get -t TARGET -oid OID [-c COMMUNITY] [-i INTERFACE]
                                      set -t TARGET -oid OID -v VALUE [-c COMMUNITY] [-i INTERFACE]
                                      dictionary_attack -t TARGET -d DICTIONARY_FILE [-i INTERFACE]
                                      dos -t TARGET -c COMMUNITY [-i INTERFACE]

  (C) Alejandro Espinosa Alvarez - UCLM
  LICENSED AS FreeBSD
  USE AT YOUR OWN RISK
    ''' % dict(tool_name="netpyntest")
    
    #########################################
    #    ARGUMENTS PARSER
    ##########################################

    parser = argparse.ArgumentParser(description='##########################################\n'
                                                 '############    NetPyntest    ############\n'
                                                 '##########################################\n',
                                     epilog=examples,
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    #parser.add_argument("target", metavar="TARGET", nargs="*")
    #parser.add_argument("-a", required=True, help="Choose attack", nargs=1, dest="attack", metavar="ATTACK_TYPE", choices=plugins)
    parser.add_argument("attack", help="Choose attack: {}".format(", ".join(plugins)), nargs=1, metavar="ATTACK_TYPE", choices=plugins)
    parser.add_argument("action", help="Action to perform (check usage examples)", nargs=1, metavar="ACTION")
    parser.add_argument("-i", help="Interface to be used (default: eth0)", nargs=1, dest="interface", metavar="INTERFACE")


    #MAC Flooding
    parser.add_argument("-f", help="MAC Flooding - PCAP File", nargs=1, dest="file", metavar="PCAP_FILE")
    parser.add_argument("-s", help="MAC Flooding - Size of the PCAP file to generate (default 10.000 packets)", nargs=1, dest="size", metavar="PCAP_FILE_SIZE", type=int)

    #Port stealing
    parser.add_argument("-o", help="Port Stealing - Output PCAP file where save captured packets", nargs=1, dest="output", metavar="OUTPUT_FILE")
    parser.add_argument("-t", help="Port Stealing / SNMP - target IP", nargs=1, dest="target", metavar="TARGET")

    #SNMP
    parser.add_argument("-oid", help="SNMP - OID", nargs=1, dest="oid", metavar="OID")
    parser.add_argument("-c", help="SNMP - Community string (default: 'public' for get, 'private' for set)", nargs=1, dest="com", metavar="COMMUNIY")
    parser.add_argument("-d", help="SNMP - Dictionary file for attack by brute force", nargs=1, dest="dict", metavar="DICTIONARY_FILE")
    parser.add_argument("-v", help="SNMP - Value to set", nargs=1, dest="value", metavar="VALUE")

    #parser.add_argument("-v", "--verbosity", dest="verbose", action="count", help="verbosity level: -v, -vv, -vvv.", default=1)

    parsed_args = parser.parse_args()

    # Configure global log
    #log.setLevel(abs(5 - parsed_args.verbose) % 5)

    # Set Global Config
    config = GlobalParameters(parsed_args)

    try:
        run_console(config)
    except KeyboardInterrupt:
        log.warning("[*] CTRL+C caught. Exiting...")
    #except Exception as e:
    #    log.critical("[!] Unhandled exception: %s" % str(e))

if __name__ == "__main__" and __package__ is None:
    # --------------------------------------------------------------------------
    #
    # INTERNAL USE: DO NOT MODIFY THIS SECTION!!!!!
    #
    # --------------------------------------------------------------------------
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import netpyntest_lib
    __package__ = str("netpyntest_lib")
    # Checks Python version
    #if sys.version_info < 3:
    #    print("\n[!] You need a version of Python 3 or greater!\n")
    #    exit(1)

    del sys, os

    main()
