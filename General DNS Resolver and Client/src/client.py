#!/usr/bin/env python3

# ##############################
# Author:Neil
# Description:A general DNS query client, like dig. Send query to any DNS resolver and parse the binary reply
# Date:18/07/2023
# Usage: python3 client.py <resolver_ip> <resolver_port> <domain name> [+enhanced args]
# ##############################

import sys
import socket
import struct
import random
import time
from datetime import datetime,timezone
# timezone
import pytz
import json
# import my dns lib
from lib_dns import *
# debug mode (True/False)

def send_query(server, port, query):
    # create UDP socket
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(1)
    sock.sendto(query, (server, port))
    response, _ = sock.recvfrom(4096)

    if DEBUG:
        print("response: " , response)
    return response

class Client:
    def __init__(self,resolver_ip, resolver_port, name, timeout = 5, type = "A"):
        self.resolver_ip = resolver_ip
        self.resolver_port = resolver_port
        self.name = name
        self.type = type
        self.timeout = timeout
        self.query = ""
        self.query_time=0
        self.res_time=""
        self.response = None
        self.parsed_response = None
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.settimeout(self.timeout)

    def send_query(self):
        # create query
        query_id = random.randint(1000, 9999)
        qtype = type_to_num(self.type)
        if qtype == 12:
            self.name = get_ptr_name(self.name)
        self.query = create_query(self.name, qtype = qtype, qclass = 1, id = query_id)
        # create UDP socket
        try:
            start_time = time.time()
            self.socket.sendto(self.query, (self.resolver_ip, self.resolver_port))
            self.response, _ = self.socket.recvfrom(1024)

            end_time = time.time()
            aest_timezone = pytz.timezone('Australia/Sydney')
            self.res_time = datetime.now(aest_timezone).strftime("%a %b %d %H:%M:%S %Z %Y")
            self.query_time = end_time - start_time
            self.parsed_response = parse_response(self.response)
            rcode = self.parsed_response["header"]["flags"]["rcode"]
            # check error code
            error_code_check(rcode)
            # print("\nClient:\nresponse: " , json.dumps(self.parsed_response,indent = 4))
            if DEBUG:
                print("\nClient:\nresponse: " , json.dumps(self.parsed_response,indent = 4))
            return self.parsed_response

        except socket.timeout:
            print("Error:", "Time Out")
            #print("Message:", "The server timed out and did not respond")
            exit(-1)
        except socket.error as e:
            print(f"Socket error: {e}")
            exit(-2)

    def set_timeout(self,arg):
        if arg !="":
            self.timeout = int(arg)
            self.socket.settimeout(self.timeout)

    def set_type(self,arg):
        if arg != "":
            self.type = arg
    
if __name__ == '__main__':
    usage = "Usage:", "python3 client.py <resolver_ip> <resolver_port> <domain name> [timeout = 5] [type = A]"
    #  python3 client.py <resolver_ip> <resolver_port> <domain name>
    client_arg_check(sys.argv)
    # if len(sys.argv) < 4:
    #     print()
    #     print(usage) 
    #     exit(1)
    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    name = sys.argv[3]
    # check advanced args
    type = ""
    timeout = ""
    # advanced arg could be in any sequence
    for arg in sys.argv[4:]:
        if is_timeout(arg):
            timeout = arg
        elif is_dns_type(arg):
            type = arg.upper()
    # load debug config
    config_path = "config.json"
    DEBUG = load_config(config_path)
    # todo 
    # multiple type
    client = Client(resolver_ip, resolver_port, name)
    # set advanced args
    client.set_timeout(timeout)
    client.set_type(type)
    # send query
    client.send_query()
    other_info = {
        "query_time":client.query_time,
        "server":client.resolver_ip,
        "port":client.resolver_port,
        "res_time":client.res_time,
        "msg_size":len(client.response)
    }
    show_result(client.parsed_response,other_info)
    
    #show_query_time(client.query_time)



