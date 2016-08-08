#Returns host MAC as string
from uuid import getnode as get_mac
import random

def getHostMAC():
	mac = str(hex(get_mac()))
	mac = [mac[i:i+2] for i in range(0, len(mac), 2)]
	mac = ":".join(mac[1:])
	return mac

def getRandomMAC():
	mac = [
		str(hex(random.randint(0x00, 0xff))), 
		str(hex(random.randint(0x00, 0xff))), 
		str(hex(random.randint(0x00, 0xff))), 
		str(hex(random.randint(0x00, 0xff))), 
		str(hex(random.randint(0x00, 0xff))), 
		str(hex(random.randint(0x00, 0xff))), 
		]

	for i in range(0,6):
		mac[i] = mac[i].replace("0x", "")
		if len(mac[i]) < 2:
			mac[i] = "0" + mac[i]

	mac = ":".join(mac)
	return mac
