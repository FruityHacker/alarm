#!/usr/bin/python3
#alarm.py written by Max Morningstar

from scapy.all import *
import argparse
import re
import base64


incident = 1
username = ""

def packetcallback(packet):
  try:
    global incident
    global username

    #Null scan - check to see if flags are set to 0 (Null)
    if packet[TCP].flags == 0:
      print( "ALERT #" + str( incident ) + ": Null scan is detected from " + str( packet[IP].src ) + " (" + str( socket.getservbyport(packet[TCP].dport) ) + ")!" )
      incident += 1

    #FIN/XMAS scan - check to see if the FIN ('F') bit is set. If yes, also check PSH and URG flags to see if it is an XMAS scan
    if packet[TCP].flags.F:
      if packet[TCP].flags.P and packet[TCP].flags.U:
        print( "ALERT #" + str( incident ) + ": XMAS scan is detected from " + str( packet[IP].src ) + " (" + str( socket.getservbyport(packet[TCP].dport) ) + ")!" )
        incident += 1
      else:
        print( "ALERT #" + str( incident ) + ": FIN scan is detected from " + str( packet[IP].src ) + " (" + str( socket.getservbyport(packet[TCP].dport) ) + ")!" )
        incident += 1

    #SMB scan - check if packet is using an SMB port (135-139 or 445)
    if ((packet[TCP].dport >= 139) and (packet[TCP].dport <= 135)) or (packet[TCP].dport == 445):
        print( "ALERT #" + str( incident ) + ": SMB scan is detected from " + str( packet[IP].src ) + " (" + str( socket.getservbyport(packet[TCP].dport) ) + ")!" )
        incident += 1


    #puts raw info into a string so it can be parsed for Nikto mentions or usernames/passwords, either in the clear or in base64
    raw_info = str(packet[Raw].load)

    #Nikto scan - check packet for any mention of 'Nikto'. Searching for 'nikto' as well appeared to yield false positives in smb.pcap
    if "Nikto" in raw_info:
        print( "ALERT #" + str( incident ) + ": Nikto scan is detected from " + str( packet[IP].src ) + " (" + str( socket.getservbyport(packet[TCP].dport) ) + ")!" )
        incident += 1

    #Check for IMAP passwords
    if "LOGIN " in raw_info:
       user_string = re.search("LOGIN (.+?) ", raw_info)
       user = user_string.group(1)
       pass_string = re.search('"(.+?)"', raw_info)
       password = pass_string.group(1)
       print( "ALERT #" + str( incident ) + ": Usernames and passwords sent in-the-clear (" + str( socket.getservbyport(packet[TCP].dport) ) + ") (username:" + user+ ", password:" + password + ")")
       incident += 1

    #Check for FTP passwords
    if "USER" in raw_info:
       raw_info = raw_info.replace("\\r\\n'","")
       username = raw_info[7:]

    if "PASS" in raw_info:
       raw_info = raw_info.replace("\\r\\n'","")
       password = raw_info[7:]
       print( "ALERT #" + str( incident ) + ": Usernames and passwords sent in-the-clear (" + str( socket.getservbyport(packet[TCP].dport) ) + ") (username:" + username + ", password:" + password + ")")
       incident += 1

    #Check for HTTP passwords
    if packet[TCP].dport == 80:
      packet_data = packet[Raw].load.decode("ascii").strip()
      string_data = str( packet_data )
      if "Authorization: Basic" in packet_data:
        matched_lines = [line for line in string_data.split('\n') if "Authorization" in line]
        matched_strings = str(matched_lines)
        matched_strings = matched_strings[23:-2]
        base64_bytes = matched_strings.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')
        cred_list = list( message.split(":") )
        print( "ALERT #" + str( incident ) + ": Usernames and passwords sent in-the-clear (" + str( socket.getservbyport(packet[TCP].dport) ) + ") (username:" + cred_list[0] + ", password:" + cred_list[1]+ ")")
        incident += 1
      

  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
