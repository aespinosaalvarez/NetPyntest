NetPyntest
====


![Logo](https://raw.githubusercontent.com/abirtone/STB/master/stb_lib/doc/images/logo.png)

*NetPyntest: Network Pentesting Tool*

Code | https://github.com/aespinosaalvarez/NetPyntest
---- | ----------------------------------------------
Issues | https://github.com/aespinosaalvarez/NetPyntest/issues/
Python versions | Python 2 & 3

What's NetPyntest
-----------

NetPyntest is a network pentesting tool that allows to perform some attacks.

What's new?
-----------

This NetPyntest version 1.0.0, is the first release:

Version 1.0.0
+++++++++++++

- First version released

You can read entire list in CHANGELOG file.

Quick start
-----------

You can display inline help writing:

```bash

python netpyntest.py -h
```
Usage examples:
--------------

  Use START commands with & to keep the prompt!
```bash
  python netpyntest.py mac_flooding   start -f PCAP_FILE [-i INTERFACE] &
                                      stop
                                      generate_pcap [-s SIZE]
                                      
  python netpyntest.py port_stealing  start -t TARGET -o OUTPUT [-i INTERFACE] &
                                      stop

  python netpyntest.py snmp           sniff [-i INTERFACE]
                                      get -t TARGET -oid OID [-c COMMUNITY] [-i INTERFACE]
                                      set -t TARGET -oid OID -v VALUE [-c COMMUNITY] [-i INTERFACE]
                                      dictionary_attack -t TARGET -d DICTIONARY_FILE [-i INTERFACE]
                                      dos -t TARGET -c COMMUNITY [-i INTERFACE]
```

References
----------

* OMSTD (Open Methodology for Security Tool Developers): http://omstd.readthedocs.org
* STB (Security Tool Builder): https://github.com/abirtone/STB 
