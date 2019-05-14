#! /usr/bin/env python3
import os
import sys
import glob
import time
import random
import netifaces
from scapy.all import sniff

version = 0.1
unique_macs = []
providers_location = "lib/macs"
wait_for_ip = 6

def logF(msg,type):
	print(msg)

def LearnMacs(pkt):
	smac = pkt.src
	if smac not in unique_macs:
		unique_macs.append(smac)
		logF("Learned new mac (%s)" % (smac),"info")

def checkRequirements():
	isok = True
	files = ["/usr/bin/macchanger","/usr/sbin/ifconfig"]
	for file in files:
		if not os.path.isfile(file):
			isok = False
			logF("Requirement is missing (%s)" % file,"error")
	return isok


def loadProviders():
	# Bring all providers prefix that are stored inside lib
	location = "%s/*.txt" % providers_location
	return glob.glob(location)

def checkProvider(u_provider):
	provider_list = False
	installed_providers = loadProviders()
	for provider in installed_providers:
		if u_provider in provider:
			provider_list = provider
	return provider_list

def generateRandom(prefix,value):
	macs = []
	for x in range(0,value):
		try:
			mac = "%s:%02x:%02x:%02x" % (prefix,random.randint(0, 255),random.randint(0, 255),random.randint(0, 255))
			macs.append(mac)
		except:
			logF(("Error issuing random MAC for %s" % prefix),"error")
	return macs

def is_interface_up(interface):
	time.sleep(wait_for_ip)
	addr = netifaces.ifaddresses(interface)
	ipv4 = netifaces.AF_INET in addr
	ipv6 = netifaces.AF_INET6 in addr
	# for debug purposes
	if ipv6:
		logF("IPV6 assigned!","info")
	if ipv4 or ipv6:
		return True
	return False

def tryMAC(mac,iface):
	logF("Testing %s on %s" % (mac,iface),"info")
	os.system("ifconfig %s down" % iface)
	time.sleep(1) # Give network card some time
	os.system("macchanger --mac %s %s > /dev/null" % (mac,iface))
	os.system("ifconfig %s up" % iface)
	if(is_interface_up(iface)):
		return mac
	return False

def startTest(provider,max_macs,iface):

	logF("Starting test with %s" % provider,"info")
	rs = False
	prefixs = (open(provider,'r').read()).splitlines()

	found = False

	if unique_macs:
		logF("Starting test with macs learned from network","info")
		for mac in unique_macs:
			rs = tryMAC(mac,iface)
			if rs:
				logF("Valid IP for: %s (%s)" % (rs,provider),"info")
				found = True
				break

	if not found:
		for prefix in prefixs:
			test_macs = generateRandom(prefix,max_macs)
			for test_mac in test_macs:
				rs = tryMAC(test_mac,iface)
			if rs:
				logF("Valid IP for: %s (%s)" % (rs,provider),"info")
				break

def main():

	iface = "eth0"
	u_learn = True
	u_provider = "cisco"
	u_max_macs = 1

	if not checkRequirements():
		sys.exit()

	if u_learn:
		sniff(prn=LearnMacs,count=1)
		print(unique_macs)

	provider = checkProvider(u_provider)
	if provider:
		startTest(provider,u_max_macs,iface)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit()