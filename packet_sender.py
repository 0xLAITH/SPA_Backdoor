#!/usr/bin/env python
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
import os
import subprocess

if (len(sys.argv) != 6):
	sys.exit("Usage: "+sys.argv[0]+" [ip] [port] [secret] [ip_destination] [port_destination]")


epoch_time = str(int(time.time()))
ip = sys.argv[1]
port = sys.argv[2]
secret = sys.argv[3]
ip_dest = sys.argv[4]
port_dest = sys.argv[5]

iv = get_random_bytes(16)
plaintext = ";"+epoch_time+";"+ip+";"+port+";"

args = ("./encrypter", secret, iv, plaintext)
popen = subprocess.Popen(args, stdout=subprocess.PIPE)
popen.wait()
encrypted = iv + popen.stdout.read()

print("Payload in plaintext:\n" + plaintext)
print("Payload sent in ciphertext:\n" + encrypted)
print("Payload length (bytes): " + str(len(encrypted)))

send(IP(dst=ip_dest)/TCP(dport=port_dest, flags='S')/encrypted)

