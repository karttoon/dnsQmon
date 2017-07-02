#!/usr/bin/python
"""
Name:           dnsQmon (DNS Query Monitor)
Version:        1.6
Date:           05/25/2014
Author:         karttoon (Jeff White)
Contact:        karttoon@gmail.com @noottrak

Description:    dnsQmon.py was written to monitor A/AAAA/PTR DNS queries from a socket without additional third-party Python libraries; however, if the Python Scapy module is available, it will use this over the Python Socket module as it can provide more functionality, such as listening on promiscous interfaces. It's end goal is to identify domains of interest, provide some visibility into DNS queries for network forensics, host-profiling, and general DNS analysis.
"""
from threading import Thread
from time import sleep,strftime,time
from struct import *
from os import geteuid,path
from platform import system,python_version
from subprocess import call,check_output
import sys,socket,sqlite3,argparse,binascii

# Test for scapy. If it exists, it will allow for more functionality.
try:
	from scapy.all import *
	has_scapy = 1
except ImportError:
	has_scapy = 0

# Check Python version and warn if not 2.7.X
py_version = python_version().split(".")
if py_version[0] != "2" and py_version[1] != "7":
	print "\n[+] WARNING: dnsQmon.py was written to work with Python 2.7.X. Other versions may cause issues."

# Flip to 1 to enable application troubleshooting. It will display additional information as it progresses.
ts_flag = 0
if ts_flag == 1:
	has_scapy = int(raw_input("[*] TS - Enter a 0 to disable Scapy or a 1 to enable: "))

# Command line arguments:
argument_parser = argparse.ArgumentParser(description="dnsQmon was written to monitor A/AAAA/PTR DNS queries on a network to assist in digital forensics.")
argument_parser.add_argument("-i", "--interface", help="Specify the interface name to monitor (e.g. eth0) or specify 'any' to monitor all interfaces. If the Python Scapy module is not insalled, an IP address must be bound to the monitored interface, even if it's just listening.", metavar="<interface>")
argument_parser.add_argument("-w", "--write", help="Write output to a CSV file or a  SQLite3 DB.", choices=["csv", "sql"], metavar="<csv|sql>")
argument_parser.add_argument("-r", "--read", help="Read in a PCAP file for processing instead of listening to network traffic. This option requires the Python Scapy module to be installed.", metavar="<pcap file>")
argument_parser.add_argument("-f", "--filename", help="File name for the CSV or SQLite3 DB.", metavar="<file name>")
argument_parser.add_argument("-t", "--time", help="Specify a time interval for writing data to a file. Default is 15 seconds but higher DNS traffic volumes should be adjusted up.", metavar="<seconds>", type=int)
argument_parser.add_argument("-d", "--display", help="Display domain queries. The default is off as high-volume networks can flood the screen.", action="store_true")
argument_parser.add_argument("-n", "--name", help="Set a name for this node to be stored with the logs. Default is hostname but can be changed to be more specific.", metavar="<host name>")
argument_parser.add_argument("--watchlist", help="Add a list of domains which you feel are suspicious, malicious, or of interest for watch - used for scoring purposes only. Place each domain on a newline.", metavar="<file name>")
argument_parser.add_argument("--commonlist", help="Add a list of domains which you feel are common, benign, or safe - used for scoring purposes only. Place each domain on a newline.", metavar="<file name>")
argument_parser.add_argument("--serverlist", help="Add a list of DNS server IP addresses you expect queries from. These will be flagged in the written data. Place each IP on a newline.", metavar="<file name>")
argument_parser.add_argument("--client", help="Make the program run as a client and send data to another system running the program as a server.", metavar="<server ip>")
argument_parser.add_argument("--server", help="Make the program run as a server and listen for data from clients running the program. Should be used in conjunction with -w or -d.", metavar="<listening ip>")
argument_parser.add_argument("-p", "--port", help="UDP port to listen on if running as a server or UDP port to communicate over if running as a client. Default is UDP/54321.", type=int, metavar="<port number>")
argument_parser.add_argument("--syslog", help="Send queries as Syslog to a remote server.", metavar="<syslog server IP>")
user_arguments = argument_parser.parse_args()

# Check for root so the application can monitor the traffic.
if geteuid() != 0:
        print "\n[+] ERROR: This program requires root priviledges to function properly.\n"
        exit()
# Check for Linux.
if system() != "Linux":
	print "\n[+] ERROR: This program is designed to run on Linux systems.\n"
	exit()

# Program initialization function. Set a number of default variables based on command line arguments and prepare others used throughout the program.
def prog_init():
        global file_name, read_file, ipmon_source, commondomain_list, watchdomain_list, newdomain_list, dnsserver_list, server_ip, server_port, pri_value, host_name, total_packets, dns_packets, domain_list, time_interval
	if ts_flag == 1:
		print "[*] TS - Program init function started."
		print "[*] TS - System is", system(), "."
		if has_scapy == 1:
			print "[*] TS - Scapy enabled."
		else:
			print "[*] TS - Scapy disabled."
	# Define variables used throughout program.
	total_packets = 0
        dns_packets = 0
	server_port = 54321
	pri_value = 14 # PRI value for syslog. PRI is the facility number multiplied by 8 with the severity number then added. 14 = 1(x8) user facility and 6 informational severity.
	newdomain_list = []
        domain_list = []
	watchdomain_list = []
	commondomain_list = []
	dnsserver_list = []
	# Begin processing arguments.
	if user_arguments.interface:
        	ipmon_source = user_arguments.interface
	else:
        	ipmon_source = None
	if user_arguments.write:
        	file_type = user_arguments.write
	else:
        	file_type = None
	if user_arguments.filename:
        	file_name = user_arguments.filename
	else:
        	file_name = None
	if user_arguments.time:
        	time_interval = user_arguments.time
	else:
        	time_interval = 15
	if user_arguments.display:
        	display_onscreen = 1
	else:
		display_onscreen = 0
        	print "\n[+] WARNING: Query display is turned off. Enable it with the \"-d\" flag when launching the program. Only status updates will be displayed."
	if user_arguments.port:
		server_port = user_arguments.port
	if user_arguments.client:
	        server_ip = user_arguments.client
	# This is not currently used but the variable can be called later if you need to know the sending IP address. Add it back to the global variable list.
	#if user_arguments.syslog:
	#	sending_ip = ([(s.connect((user_arguments.syslog, 514)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
	# Don't allow server and client mode at the same time/
	if user_arguments.client and user_arguments.server:
		argument_parser.error("[+] ERROR: Program cannot be run as a client and a server.")
	# Define default file names for writing.
        if file_type == "csv" and file_name == None:
                file_name = "queries.csv"
        elif file_type == "sql" and file_name == None:
                file_name = "queries.db"
	# Create files or database if they do not already exist.
        if file_type == "csv" and path.exists(file_name) == False:
                with open(file_name,"a") as csv_file:
                        print "\n[+] Creating CSV " + file_name + "."
                        csv_file.write("Date,Time,Hostname,SrcAddr,SrcPort,DstAddr,DstPort,RecordType,Domain,TLD,SLD,Levels,Score,Flags\n")
        if file_type == "sql" and path.exists(file_name) == False:
                print "\n[+] Creating database " + file_name + "."
                db_connection = sqlite3.connect(file_name)
                db_command = db_connection.cursor()
                db_command.execute("""CREATE TABLE Queries (Date numeric, Time numeric, Hostname text, SrcAddr text, SrcPort numeric, DstAddr text, DstPort numeric, RecordType text, Domain text, TLD text, SLD text, Levels numeric, Score numeric, Flags text)""")
                db_connection.commit()
                db_connection.close	
	if user_arguments.read:
		read_file = user_arguments.read
		if has_scapy == 0:
			argument_parser.error("[+] ERROR: Scapy cannot be imported - PCAP Read functionality will not work.")
	# Setup future socket or scapy sniff commands based on interface input. Socket requires interfaces to have an IP address.
        if ipmon_source == "any" or ipmon_source == None:
                ipmon_source = ""
        else:
                if has_scapy == 0:
			try:
				ipmon_source = check_output(["ip", "addr", "show", "dev", ipmon_source]).split()
	        		ipmon_source = ipmon_source[16].split("/")[0]
			except:
				print "\n[+] ERROR: Please verify the interface has an IPv4 address assigned and exists before proceeding, or specify \"any\" for all interfaces with IPv4 addresses. To monitor promiscuous interfaces, install Scapy and relaunch the program."
				exit()
	# Build watched domain list from supplied file. Ignore # as comment and convert/clean everything.
        if user_arguments.watchlist:
                with open(user_arguments.watchlist,"r") as watch_domains:
                        for wdomain in watch_domains:
				if wdomain[0] != "#" and wdomain[0].isalnum() == True:
					wdomain = wdomain.lower()
					watchdomain_list.append(wdomain.strip())
				
	# Build common domain list from supplied file. Ignore # as comment and convert/clean everything.
        if user_arguments.commonlist:
                with open(user_arguments.commonlist,"r") as common_domains:
                        for cdomain in common_domains:
				if cdomain[0] != "#" and cdomain[0].isalnum() == True:
					cdomain = cdomain.lower()
					commondomain_list.append(cdomain.strip())
	# Build domain server list from supplied file. Ignore # as comment and convert/clean everything.
	if user_arguments.serverlist:
		with open(user_arguments.serverlist,"r") as dns_servers:
			for dserver in dns_servers:
				if dserver[0] != "#" and dserver[0].isdigit() == True:
					dnsserver_list.append(dserver.strip())		
        if user_arguments.name:
                host_name = user_arguments.name
	else:
		host_name = socket.gethostname()
	# Error if no data being sent, written, or displayed.
	if display_onscreen == 0 and not user_arguments.write and not user_arguments.client and not user_arguments.syslog:
		argument_parser.error("[+] ERROR: You must either turn on query display, write to a file, send to syslog or a dnsQmon server to proceed.")
	# Error if not reading a PCAP and not monitoring an interface.
	if not user_arguments.interface:
		if user_arguments.read:
			pass
		else:
			argument_parser.error("[+] ERROR: You must specify an interface unless reading from a PCAP file.")
	# Error if read and monitoring selected.
	if user_arguments.read and user_arguments.interface:
		argument_parser.error("[+] ERROR: You must either listen on an interface or read from a packet; not both.")
	if ts_flag == 1:
		print "[*] TS - Program init function finished."


def sniff_traffic(ipmon_source):
        global total_packets, dns_packets
	if ts_flag == 1:
		print "[*] TS - Started thread for sniffing traffic."
	# Check for scapy and launch scapy sniff if present.
	if has_scapy == 1:
		if ts_flag == 1:
			print "[*] TS - Starting Scapy sniffing."
		# Launch scapy sniff on all interfaces.
		if ipmon_source == "":
			while True:
				sniff(prn=scapy_strip, filter="udp port 53", store=0)
		# Launch scapy sniff on specific interface or error.
		else:
			try:
				while True:
					sniff(prn=scapy_strip, iface=ipmon_source, filter="udp port 53", store=0)
			except:
				print "\n[+] ERROR: Please verify the interface exists before proceeding, or specify \"any\" for all interfaces.\n"
				exit()
	# Launch socket if scapy not present.
	else:
		if ts_flag == 1:
			print "[*] TS - Starting Socket sniffing."
	        while True:
        	        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	                udp_socket.bind((ipmon_source,53))
        	        raw_packet = udp_socket.recvfrom(4096)
                	total_packets += 1
	                if ts_flag == 1:
				print "[*] TS - Raw packet start."
				print raw_packet
				print "[*] TS - Raw packet end."
	                raw_packet = raw_packet[0]
        	        # Determine if bit is set for a query. Also helps verify DNS packet structure before proceeding.
                	query_flag = raw_packet[30]
	                query_mask = 0b10000000
        	        query_flag = int(query_flag.encode("hex"),16)
                	query_flag = query_mask & query_flag
	                if query_flag == 0:
				dns_valid = 0
				# Strip IP/Protocol information.
                		ip_len, src_addr, dst_addr, src_port, dst_port = ip_strip(raw_packet)
				# Determine DNS record type. Also helps verify DNS packet structure before proceeding. Additional record types that may be of interest would be \x00\x0f for MX and \x00\x02 for NS.
	                        dns_type = raw_packet[ip_len - 4:ip_len - 2]
				# Based on the record type, gather the domain name and update display/append to buffer for writing to file.
                	        if dns_type == "\x00\x01":
                        	        record_type = "A"
					dns_packets += 1
					dns_valid = 1
	                        elif dns_type == "\x00\x0c":
        	                        record_type = "PTR"
					dns_packets += 1
					dns_valid = 1
        	                elif dns_type == "\x00\x1c":
                	                record_type = "AAAA"
					dns_packets += 1
					dns_valid = 1
				if dns_valid == 1:
					# Build string for writing/display.
                        		domain_name = dns_strip(raw_packet,record_type, ip_len)
					domain_score, domain_flags, tld_name, sld_name, domain_levels = scored_domain(domain_name, src_addr)
					dns_update(dns_packets, host_name, src_addr, src_port, dst_addr, dst_port, record_type, domain_name, tld_name, sld_name, domain_levels, domain_score, domain_flags)
				if ts_flag == 1:
					print "[*] TS - Packet processing finished."

def server_traffic(server_ip):
	global domain_list, total_packets, dns_packets
	# Build listening socket.
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_socket.bind((server_ip, server_port))
	if ts_flag == 1:
		print "[*] TS - Server thread started to receive client packets."
	while True:
		dns_data = server_socket.recv(4096)
		total_packets += 1
		# Check for "dnsQmon-packet" to verify packet was actually sent from a client and isn't unintended data.
		packet_split = dns_data.split(",")
		if packet_split[0] == "dnsQmon-packet":
			# Strip out the check and append to buffer.
			domain_list.append(dns_data[15:])
                	dns_packets += 1
			# Print a displayed update if specified.
			if user_arguments.display:
				print "[-] DNS Packet:", str(dns_packets), "-", packet_split[3], "-", packet_split[1], packet_split[2], "-", packet_split[4] + ":" + packet_split[5], ">", packet_split[6] + ":" + packet_split[7], "-", packet_split[8], "Record - Score:", packet_split[14], "Flags:", packet_split[15], "-", packet_split[9]
	if ts_flag == 1:
		print "[*] TS - Server packet processing finished."

def dns_update(dns_packets, host_name, src_addr, src_port, dst_addr, dst_port, record_type, domain_name, tld_name, sld_name, domain_levels, domain_score, domain_flags):
        global domain_list
	if ts_flag == 1:
		print "[*] TS - DNS update function running."
	# Print a displayed update if specified.
        if user_arguments.display:
               	print "[-] DNS Packet:", str(dns_packets), "-", strftime("%m/%d/%Y %H:%M:%S -"), src_addr + ":" + str(src_port), ">", dst_addr + ":" + str(dst_port), "-", record_type, "Record - Score:", str(domain_score), "Flags:", domain_flags, "-", domain_name
	# Append string to list for later writing.
        if user_arguments.write:
               	domain_list.append(strftime("%m/%d/%Y") + "," + strftime("%H:%M:%S") + "," + host_name + "," + src_addr + "," + str(src_port) + "," + dst_addr + "," + str(dst_port) + "," + record_type + "," + domain_name + "," + tld_name + "," + sld_name + "," + str(domain_levels) + "," + str(domain_score) + "," + domain_flags)
	# Send string to dnsQmon server.
        if user_arguments.client:
               	client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
               	client_socket.sendto("dnsQmon-packet" + "," + (strftime("%m/%d/%Y") + "," + strftime("%H:%M:%S") + "," + host_name + "," + src_addr + "," + str(src_port) + "," + dst_addr + "," + str(dst_port) + "," + record_type + "," + domain_name + "," + tld_name + "," + sld_name + "," + str(domain_levels) + "," + str(domain_score) + "," + domain_flags),(server_ip,server_port))
	# Send string to syslog server.
	if user_arguments.syslog:
               	syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
               	syslog_socket.sendto(("<" + str(pri_value) + "> " + (strftime("%m/%d/%Y") + "," + strftime("%H:%M:%S") + "," + host_name + "," + src_addr + "," + str(src_port) + "," + dst_addr + "," + str(dst_port) + "," + record_type + "," + domain_name + "," + tld_name + "," + sld_name + "," + str(domain_levels) + "," + str(domain_score) + "," + domain_flags)),(user_arguments.syslog,514))
	if ts_flag == 1:
		print "[*] TS - DNS update function finished."	
								
def ip_strip(raw_packet):
        """	IPv4 Header Reference
		-----------------------------------------------------------------------------------------
                |Version (4 bits) | IHL (4 bits) | DSCP (6 bits) | ECN (2 bits) | Total Length (2 bytes)|
                |Identification (2 bytes) | Flags (3 bits) | Fragment Offset (13 bits)			|
                |Time To Live (1 byte) | Protocol (1 byte) | Header Checksum (2 bytes)			|
                |Source IP Address (4 bytes)								|
                |Destination IP Address (4 bytes)							|
                |Options										|
		-----------------------------------------------------------------------------------------
        """
	if ts_flag == 1:
		print "[*] TS - Stripping IP/Protocol information from received packet."
        ip_header = raw_packet[0:20]
	# Build variables based on header reference.
        ip_pack = unpack('!BBHHHBBH4s4s', ip_header)
        ip_len = ip_pack[2]
        src_addr = socket.inet_ntoa(ip_pack[8])
        dst_addr = socket.inet_ntoa(ip_pack[9])
        """	UDP Header Reference
		---------------------------------------------------------
                |Source Port (2 bytes)	| Destination port (2 bytes)	|
                |Length (2 bytes)	| Checksum (2 bytes)		|
		---------------------------------------------------------
        """
        udp_header = raw_packet[20:28]
	# Build variables based on header reference.
        udp_pack = unpack('!HHHH', udp_header)
        src_port = udp_pack[0]
        dst_port = udp_pack[1]
	if ts_flag == 1:
	        print "[*] TS - SrcAddr", src_addr + ":" + str(src_port), "DstAddr", dst_addr + ":" + str(dst_port)
	return ip_len, src_addr, dst_addr, src_port, dst_port

def dns_strip(raw_packet,record_type,ip_len):
        """	DNS Query Structure Reference
		-----------------------------------------------------------------------------------------
                |ID (2 bytes) | Query/Response Flag (1 bit) | Opcode (4 bits) | Truncation Flag (1 bit)	|
                |Recursion Desired (1 bit) | Zero (3 bits) | Response Code (4 bits)			|
                |Question Count (2 bytes) | Answer Record Count (2 bytes)				|
                |Authority Record Count (2 bytes) | Additional Record Count (2 bytes)			|
                |Query (varied length) | Type (2 bytes) | Class (2 bytes)				|
		-----------------------------------------------------------------------------------------
        """
	if ts_flag == 1:
		print "[*] TS - Stripping domain from received DNS query packet."
        domain_name = []
        dns_query = raw_packet[40:ip_len - 4]
        # Each domain level is preceeded by the length of the string. Examples below for reference and index.
	# ['\x04', 'p', 'l', 'u', 's', '\x06', 'g', 'o', 'o', 'g', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00']
        # www.google.com = (0=3)(1=w)(2=w)(3=w)(4=6)(5=g)(6=o)(7=o)(8=g)(9=l)(10=e)(11=3)(12=c)(13=o)(14=m)(15=end)
        # Below code will step through each level until it reaches the end byte (\x00) to build FQDN.
	domain_part_start = 0
        domain_part_end = ord(dns_query[0]) + 1
        domain_end = dns_query[domain_part_end]
        domain_name.append(dns_query[domain_part_start + 1:domain_part_end])
        while domain_end != "\x00":
                domain_part_start = domain_part_end
                domain_part_end = domain_part_end + ord(dns_query[domain_part_end]) + 1
                domain_name.append(dns_query[domain_part_start + 1:domain_part_end])
                domain_end = dns_query[domain_part_end]
	domain_name = ".".join(domain_name)
	if ts_flag == 1:
		print "[*] TS - Stripped domain:", domain_name.lower()
	return domain_name.lower()

def scapy_strip(scapy_packet):
	global total_packets, dns_packets
	if ts_flag == 1:
		print "[*] TS - Scapy strip started."
	scapy_valid = 0
	total_packets += 1
	# Verify DNS layer exists.
	if scapy_packet.haslayer(DNS):
		try:
			# Verify it's a DNS query.
			if scapy_packet[DNS].qr == 0:
				if scapy_packet[DNS].qdcount == 0:
					scapy_valid = 0
				else:
					if scapy_packet[DNS].qd.qtype == 1:
						dns_packets += 1
						scapy_valid = 1
						record_type = "A"
					if scapy_packet[DNS].qd.qtype == 12:
						dns_packets += 1
						scapy_valid = 1
						record_type = "PTR"
					if scapy_packet[DNS].qd.qtype == 28:
						dns_packets += 1
						scapy_valid = 1
						record_type = "AAAA"
		except:
			scapy_valid = 0
	if scapy_valid == 1:
		# Check for IPv4 or IPv6.
		if scapy_packet.haslayer(IP):
			src_addr = scapy_packet[IP].src
			dst_addr = scapy_packet[IP].dst
		if scapy_packet.haslayer(IPv6):
			src_addr = scapy_packet[IPv6].src
			dst_addr = scapy_packet[IPv6].dst
		src_port = scapy_packet[UDP].sport
		dst_port = scapy_packet[UDP].dport
		# Build string for writing/display.
		domain_name = scapy_packet[DNS].qd.qname[0:(len(scapy_packet[DNS].qd.qname) - 1)]
		domain_score, domain_flags, tld_name, sld_name, domain_levels = scored_domain(domain_name, src_addr)
		dns_update(dns_packets, host_name, src_addr, src_port, dst_addr, dst_port, record_type, domain_name, tld_name, sld_name, domain_levels, domain_score, domain_flags)
	if ts_flag == 1:
		print scapy_packet.show()
		print "[*] TS - Scapy strip finished."
		

def scored_domain(domain_name, src_addr):
        global newdomain_list
	'''
	TLD Count/Length Reference
	TLD Counter({'com': 19114, 'ru': 3766, 'net': 3292, 'info': 3253, 'cn': 3068, 'in': 2583, 'cc': 2028, 'org': 1818, 'biz': 801, 'tk': 648, 'br': 580, 'de': 423, 'eu': 361, 'be': 285, 'tv': 251, 'pl': 238, 'us': 210, 'uk': 196, 'kr': 189, 'name': 167, 'ua': 156, 'it': 154, 'nl': 142, 'fr': 116, 'co': 104, 'ms': 90, 'nu': 89, 'ws': 87, 'su': 86, 'es': 80, 'au': 74, 'tw': 73, 'cz': 71, 'ar': 71, 'ro': 69, 'pro': 54, 'asia': 52, 'at': 50, 'me': 48, 'ca': 43, 'dk': 40, 'th': 38, 'hu': 37, 'jp': 36, 'mx': 36, 'tr': 35, 'ch': 35, 'cl': 35, 'kz': 34, 'za': 32, 'se': 32, 'im': 31, 'mobi': 30, 'ai': 27, 'ir': 27, 'my': 26, 'sk': 25, 'gr': 23, 'id': 21, 'ee': 20, 'bz': 20, 'li': 19, 'pt': 19, 'vg': 19, 'lt': 18, 'il': 18, 'sg': 16, 'cm': 15, 'lv': 14, 'tc': 14, 'nz': 14, 'by': 13, 'vn': 12, 'to': 11, 'cx': 11, 'hk': 11, 'ma': 10, 'bg': 9, 'no': 9, 'la': 8, 'tm': 8, 'tl': 7, 'si': 7, 'tf': 6, 'vu': 6, 'rs': 6, 'ph': 6, 'vc': 6, 'pe': 5, 'pk': 5, 'pn': 5, 'uz': 5, 'ie': 5, 'ge': 4, 'ec': 4, 'mk': 4, 'jo': 4, 'cr': 4, 'mn': 4, 'ae': 4, 've': 4, 'nf': 4, 'py': 3, 'is': 3, 'hn': 3, 'md': 3, 'am': 3, 'pa': 3, 'fi': 3, 'fm': 3, 'fo': 3, 'sh': 3, 'xn--p1ai': 3, 'gd': 2, 'edu': 2, 'bo': 2, 'bs': 2, 'ci': 2, 'pw': 2, 'lu': 2, 'hr': 2, 'cat': 2, 'ag': 2, 'as': 2, 'kg': 2, 'ke': 2, 'so': 2, 'sd': 2, '': 1, 'gt': 1, 'gs': 1, 'gp': 1, 'gg': 1, 'gi': 1, 'tz': 1, 'tt': 1, 'tg': 1, 'dm': 1, 'gov': 1, 'ba': 1, 'af': 1, 'al': 1, 'hm': 1, 'mu': 1, 'ug': 1, 'io': 1, 'az': 1, 'ng': 1, 'np': 1, 'kw': 1, 'nr': 1, 'sc': 1, 'sa': 1})
	Length Counter({14: 3892, 13: 3708, 15: 3487, 16: 3241, 17: 2993, 12: 2951, 18: 2712, 11: 2630, 19: 2561, 10: 2340, 20: 2206, 21: 2115, 22: 1542, 9: 1302, 23: 1240, 24: 1203, 8: 976, 25: 873, 26: 708, 27: 533, 28: 456, 29: 366, 7: 283, 30: 255, 31: 186, 32: 185, 33: 131, 34: 93, 6: 81, 35: 45, 38: 45, 52: 43, 53: 43, 36: 38, 37: 38, 54: 37, 48: 31, 49: 31, 51: 31, 39: 30, 46: 30, 47: 28, 45: 27, 50: 27, 57: 27, 56: 26, 58: 25, 59: 22, 40: 20, 42: 20, 55: 19, 43: 16, 44: 14, 61: 14, 41: 13, 62: 13, 64: 12, 60: 10, 67: 8, 63: 7, 122: 4, 5: 3, 65: 3, 66: 3, 69: 3, 70: 3, 71: 3, 73: 3, 68: 2, 78: 2, 85: 2, 89: 2, 74: 1, 75: 1, 76: 1, 77: 1, 80: 1, 81: 1, 82: 1, 88: 1, 90: 1})
	Weighted mean average = 17
	'''
	if ts_flag == 1:
		print "[*] TS - Scoring domain."
	# Score domains based on various attributes. This is extremely subjective and by no way means something is malicious. Take it with a grain of salt and use it to compliment your own analysis of the query in question.
	domain_score = 0
	domain_flags = []
        split_name = domain_name.split(".")
	# Top level domain, e.g. - "com".
        tld_name = ".".join(split_name[len(split_name)-1:len(split_name)])
	# Down to second level of domain, e.g. - "google.com".
        sld_name = ".".join(split_name[len(split_name)-2:len(split_name)])
	domain_levels = len(split_name)
	# Flag "b" - Domain name  was identified in the watched domain list. Higher level of confidence due to the exact nature.
        flag_b = 35
        # Flag "u" - SLD is not in the common list and is marked uncommon.
        flag_u = 5
        # Flag "l" - Domain length is abornamlly long. Set to 35 based on when bulk of malicious domains from analyzed list fell off.
        flag_l = 5
        # Flag "s" - Domain length is abnormally short. Set to 7 based on when bulk of malicious domains began ramping up.
        flag_s = 5
        # Flag "t" - The TLD is commonly found in malicious sites (does not include com, net, org). Score is varied based on domain.
	tld_list = {5:["af","al","az","ba","dm","gg","gi","gov","gp","gs","gt","hm","io","kw","mu","ng","np","nr","sa","sc","tg","tt","tz","ug","ag","as","bo","bs","cat","ci","edu","gd","hr","ke","kg","lu","pw","sd","so","am","fi","fm","fo","hn","is","md","pa","py","sh","ae","cr","ec","ge","jo","mk","mn","nf","ve","ie","pe","pk","pn","uz","ph","rs","tf","vc","vu","si","tl","la","tm","bg","no","ma"],10:["cx","hk","to","vn","by","lv","nz","tc","cm","sg","il","lt","li","pt","vg","bz","ee","id","gr","sk","my","ai","ir","mobi","im","se","za","kz","ch","cl","tr","jp","mx","hu","th","dk","ca","me"],15:["at","asia","pro","ro","ar","cz","tw","au","es","su","ws","nu","ms"],20:["co","fr","nl","it","ua","name","kr","uk","us","pl","tv","be","eu","de","br","tk","biz"],25:["cc","in","cn","info"],35:["ru"]}
	tld_ok = ["com", "org", "net", "arpa"]
        # Flag "d" - A DNS server. Flagged so you can identify the source as a DNS server instead of a host (e.g. recursive query from authorized server). No score added, just a flag.
        # Flag "f" - First occurence of this domain SLD since program launch.
        flag_f = 5
	if ts_flag == 1:
        	start_time = time.time()
	# Check in common domain list.
        if user_arguments.commonlist:
                if sld_name not in commondomain_list:
                        domain_score += flag_s
                        domain_flags.append("u")
	# Check in watched domain list.
        if user_arguments.watchlist:
                if domain_name in watchdomain_list:
                        domain_score += flag_b
                        domain_flags.append("b")
	# Check if this domain has been seen yet since program execution.
        if sld_name not in newdomain_list:
                domain_score += flag_f
                domain_flags.append("f")
                newdomain_list.append(sld_name)
	# Check length of domain name (includes periods).
	if len(domain_name) > 35:
		domain_score += flag_l
		domain_flags.append("l")
	elif len(domain_name) < 7:
		domain_score += flag_s
		domain_flags.append("s")
	# Check if source IP is in the known DNS server list.
	if user_arguments.serverlist:
		if src_addr in dnsserver_list:
			domain_flags.append("d")
	# Check and score TLD.
	for tld_list_key, tld_list_value in tld_list.iteritems():
		if tld_name in tld_list_value:
			domain_score += tld_list_key
			domain_flags.append("t")
			break
		elif tld_name not in tld_ok:
			domain_score += 1
			domain_flags.append("t")
			break
	# Replace empty flag list with value indicating nothing detected.
	if domain_flags == []:
		domain_flags = "None"
	else:
		domain_flags = "".join(domain_flags)
	if ts_flag == 1: 
        	end_time = time.time()
        	run_time = end_time - start_time
        	print "[*] TS - Scoring finished in " + str("%.2f" % run_time) + " seconds. Score", str(domain_score) + "."
	return domain_score, domain_flags, tld_name, sld_name, domain_levels

def display_screen():
	if ts_flag == 1:
		print "[*] TS - Running display screen function."
	# Can't divide a float by 0 so added a line to avoid issues.
	if dns_packets == 0:
               	print "\n[+] Total packets received:", str(total_packets), "- Inspected DNS Queries: 0. Next update in", str("%.2f" % time_interval), "seconds."
	else:
		# Based on whether writing to a file, reading from a file, or receiving packets in server mode - change displayed message.
		if user_arguments.write == "csv" or user_arguments.write == "sql":
			if user_arguments.read:
	        		print "\n[+] Total packets read:", str(total_packets), "- Inspected DNS Queries:", str(dns_packets), "(" + "%.1f" % (float(dns_packets)/float(total_packets) * 100.0) + "%) -", str(len(domain_list)), "new records written to", file_name + ".\n"
			else:
	        		print "\n[+] Total packets received:", str(total_packets), "- Inspected DNS Queries:", str(dns_packets), "(" + "%.1f" % (float(dns_packets)/float(total_packets) * 100.0) + "%) -", str(len(domain_list)), "new records written to", file_name + ". Next update in", str("%.2f" % time_interval), "seconds."
		else:
                	if user_arguments.read:
				print "\n[+] Total packets read:", str(total_packets), "- Inspected DNS Queries:", str(dns_packets), "(" + "%.1f" % (float(dns_packets)/float(total_packets) * 100.0) + "%).\n"
			else:	
				print "\n[+] Total packets received:", str(total_packets), "- Inspected DNS Queries:", str(dns_packets), "(" + "%.1f" % (float(dns_packets)/float(total_packets) * 100.0) + "%). Next update in", str("%.2f" % time_interval), "seconds."
	if ts_flag == 1:
		print "[*] TS - Finished display screen function."

def write_file():
        global domain_list, time_interval
	if ts_flag == 1:
		print "[*] TS - Writing data to a file.\n"
        # Transfer current domains in list to a new list and wipe the old one. This way if it takes a long time to write the list there aren't any issues with it being updated while being written.
        list_transfer = domain_list
        domain_list = []
        # Write the updates to the CSV file.
        if user_arguments.write == "csv":
                # Check how long it took the write to run in seconds and compare to the active time interval. If less, auto-adjust for the user.
		start_time = time.time()
                with open(file_name,"a") as csv_file:
                        for line in list_transfer:
                                csv_file.write("%s\n" % line)
                end_time = time.time()
                run_time = end_time - start_time
		if ts_flag == 1:
			print "[*] TS - It took", str(run_time), "seconds to write to", file_name + "."
		# Adjust run time if it's taking too long to write.
                if run_time > time_interval:
                        print "\n[+] WARNING: Writing to the files is taking longer than the", str("%.2f" % time_interval), "second time interval. Adjusting by", "%.2f" % (run_time + 5), "seconds."
                        time_interval += run_time + 5
                list_transfer = []
        # Write the updates to the SQLite3 DB.
        elif user_arguments.write == "sql":
                db_connection = sqlite3.connect(file_name)
                db_command = db_connection.cursor()
                # Check how long it took the write to run in seconds and compare to the active time interval. If less, auto-adjust for the user.
                start_time = time.time()
                for line in list_transfer:
                        line = line.split(",")
			try:
                        	db_command.execute("INSERT INTO queries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", line)
			except:
				pass
                db_connection.commit()
                db_connection.close
                end_time = time.time()
                run_time = end_time - start_time
		if ts_flag == 1:
			print "[*] TS - It took", str("%.2f" % run_time), "seconds to write to", file_name + "."
		# Adjust run time if it's taking too long to write.
                if run_time > time_interval:
                        print "\n[+] WARNING: Writing to the files is taking longer than the", str("%.2f" % time_interval), "second time interval. Adjusting by", "%.2f" % (run_time + 5), "seconds."
                        time_interval += run_time + 5.0
		#Clear list_transfer list for the next set of domains.
                list_transfer = []
	if ts_flag == 1:
		print "[*] TS - Finished writing data to file."

def main():
	if ts_flag == 1:
		print "[*] TS - Main function started."
	# Initialize program variables and parse user arguments.
        prog_init()
	# Start reading from a PCAP file.
	if user_arguments.read and has_scapy == 1:
		print "\n[+] Reading packets from PCAP file.\n"
		pcap_packets = rdpcap(read_file)
		for packet in pcap_packets:
			scapy_strip(packet)
		display_screen()
		if user_arguments.write:
			write_file()
	# Start listening for traffic from a client.
        elif user_arguments.server:
		print "\n[+] Starting server and waiting to receive DNS data from clients."
                server_thread = Thread(target=server_traffic, args=(user_arguments.server,))
                server_thread.daemon = True
                server_thread.start()
                while True:
                        sleep(float(time_interval))
                        display_screen()
                        if user_arguments.write:
                                write_file()
	# Start monitoring DNS network traffic.
        else:
                print "\n[+] Monitoring DNS packets."
		sniffer_thread = Thread(target=sniff_traffic, args=(ipmon_source,))
        	sniffer_thread.daemon = True
                sniffer_thread.start()
                if user_arguments.write:
                        print "[-] Writing data every", str("%.2f" % time_interval), "seconds to", str(file_name) + "."
                while True:
                        sleep(float(time_interval))
                        display_screen()
                        if user_arguments.write:
                                write_file()

if __name__ == "__main__":
        try:
                main()
        except KeyboardInterrupt:
		# Close out of threads and exit.
                print "\n[+] Shutting down the program.\n"
                sys.exit()
