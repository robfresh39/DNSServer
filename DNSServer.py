import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
import dns.rrset
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key


# Fernet API: https://cryptography.io/en/latest/fernet/
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


salt = b'Tandon'
password = 'rn2836@nyu.edu'
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)  # exfil function
# Sanity check only, so you can confirm the round trip works locally.
# Do NOT put the decrypted value in the DNS record.
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function


# For future use
def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },

    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },

    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },

    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },

    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },

    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # TXT is a string-cast version of the encrypted secret data
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        # Same address as 2001:0db8:85a3:0000:0000:8a2e:0373:7312, compressed per RFC 5952
        dns.rdatatype.AAAA: '2001:db8:85a3::8a2e:373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}


def run_dns_server():
    # Bind to localhost on the standard DNS port.
    # Port 53 usually needs root/sudo. If it fails, use 5353 and query with dig -p 5353.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)

            # Parse the request
            request = dns.message.from_wire(data)

            # Create a response based on the request
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(
                            MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, dns.name.from_text(server))
                        )

                elif qtype == dns.rdatatype.SOA:
                    # Format: (mname, rname, serial, refresh, retry, expire, minimum)
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata_list.append(
                        SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
                            dns.name.from_text(mname), dns.name.from_text(rname),
                            serial, refresh, retry, expire, minimum)
                    )

                elif qtype == dns.rdatatype.TXT:
                    # Build the TXT rdata directly so the encrypted string is stored as-is
                    strings = [s.encode('utf-8') for s in answer_data]
                    rdata_list.append(TXT(dns.rdataclass.IN, dns.rdatatype.TXT, strings))

                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, d) for d in answer_data]

                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            # Set the AA (Authoritative Answer) flag: bit 10 of the flags field
            response.flags |= 1 << 10

            # Send the response back to the client
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
    # print("Encrypted Value:", encrypted_value)
    # print("Decrypted Value:", decrypted_value)
