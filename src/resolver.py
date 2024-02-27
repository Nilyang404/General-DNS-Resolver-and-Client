#!/usr/bin/env python3

# ##############################
# Author:Neil
# Description:A general DNS resolver
# Date:18/07/2023
# Usage: python3 resolver.py <resolver_port> 
# ##############################

import sys
import socket
import threading
import struct
import random
import time
import json
import re
# import my dns lib
from lib_dns import *

class Resolver:
    def __init__(self,port):
        self.port = port
        self.named_root_path = "named.root"
        self.root_servers = []
        self.load_nameed_root(self.named_root_path)
        # UDP socket
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        # use 0.0.0.0 here
        self.socket.bind(("0.0.0.0",self.port))

    # load root server name and ip from file
    def load_nameed_root(self, path):
        with open(path,"r") as file:
            for line in file.readlines():
                 if not line.startswith(";"):
                    name, ttl, type, ip = line.split()
                    if type == "A":
                        self.root_servers.append(
                            {
                                "name":name,
                                "ttl":ttl,
                                "type":type,
                                "ip":ip
                            }
                        )
    # resolve a dns query
    def resolve(self, name, type, id):
        #print(threading.current_thread().getName(), "started")
        # # todo query everyone until got answer
        start_time = time.time()
        flag = 0
        for root_record in self.root_servers:
            if flag == 1:
                break
            dns_server_ip = root_record["ip"]
            final_response = None
            while True:
                if time.time() - start_time > 5:
                    print("Error: Time out")
                    return None, None
                print("Query DNS server: ", dns_server_ip, name, type)
                query = create_query(name, qtype = type, qclass = 1, id = id)
                response, parsed_response = self.send_query(self.socket, query, dns_server_ip)
                #print("res: ",json.dumps(parsed_response, indent = 4))\
                # check error code 
                rcode = parsed_response["header"]["flags"]["rcode"]
                if error_code_check_server(rcode):
                    # error 1 or 3
                    return response, parsed_response
                # answer
                if parsed_response["header"]["ancount"] != 0 or parsed_response["header"]["flags"]["aa"] == 1 :
                    # if parsed_response["header"]["ancount"] != 0 and 
                    final_response = parsed_response
                    answer = parsed_response["answers"]
                    print("Final Answer: ",json.dumps(parsed_response["answers"], indent = 4))
                    # return response to client
                    flag = 1
                    break
                # authority
                if parsed_response["header"]["nscount"] != 0:
                    for i in range(parsed_response["header"]["nscount"]):
                        authority_record = parsed_response["authority"][i]
                        # NS type
                        if authority_record["type"] == 2:
                            dns_server_ip = authority_record["rdata"]
                            break
        return response,parsed_response
    # if all answer are cname
    def get_real_record_by_cname(self,cname,type,id):
        # find read ip 
        response,parsed_response = self.resolve(cname,type,id)
        answers = parsed_response["answers"]
        for answer in answers:
            rdata = answer["rdata"]
            if answer["type"] == 5:
                response,parsed_response = self.get_real_record_by_cname(rdata.rstrip('.'),type,id)
                return response,parsed_response
            else:
                return response,parsed_response

    # send query to server           
    # return response of query      
    def send_query(self, sock, query, dns_server_ip):
        sock.sendto(query,(dns_server_ip, 53))
        response, _ = self.socket.recvfrom(4096)
        parsed_response = parse_response(response)
        return response, parsed_response

    # check if the mes is a dns query
    def isquery(self,msg):
        parsed_msg = parse_response(msg)
        if parsed_msg["header"]["flags"]["qr"] == 0:
            return True
        else:
            return False

    def start(self):
        while True:
            print("waiting for query...")
            # get request from client
            client_request, client_addr = self.socket.recvfrom(4096)
            parsed_request = parse_response(client_request)
            if parsed_request is None:
                print("Error: Bad request")
                print("Message: query can not be parsed")
                continue
            name = parsed_request["query"]["qname"]
            type = parsed_request["query"]["qtype"]
            id = parsed_request["header"]["id"]
            try:
                response, parsed_response = self.resolve(name, type, id)
                if response is None:
                    continue
            except socket.timeout:
                print("Error: Time Out")
                print("Message: The server timed out and did not respond")
                continue
            except socket.error as e:
                print(f"Socket error: {e}")
                continue
            # handle issue: cname answer while not cname query
            # for answer in parsed_response["answers"]:
            #     if answer["type"] == 5 and type != 5:
            #         response, parsed_response = self.get_real_record_by_cname(answer["rdata"].rstrip('.'),type,id)
            print("response to ",client_addr)
            self.socket.sendto(response,client_addr)
        # TODO:
        # Try Multiplexing
        # while True:
        #     print("waiting...")
        #     # receive query request from client
        #     client_request, client_addr = self.socket.recvfrom(4096)
        #     print(client_addr)
        #     if self.isquery(client_request):
        #         #self.resolve(client_request, client_addr)
        #         thread = threading.Thread(target = self.resolve, args = (client_request, client_addr))
        #         #thread.setDaemon(True)
        #         thread.start()

    def start_2(self):
        while True:
            print("waiting for query...")
            # get request from client
            client_request, client_addr = self.socket.recvfrom(4096)

            # Create a new thread to handle the incoming request
            thread = threading.Thread(target=self.handle_query, args=(client_request, client_addr))
            thread.start()

    def handle_query(self, client_request, client_addr):
        parsed_request = parse_response(client_request)
        if parsed_request is None:
            print("Error: Bad request")
            print("Message: query can not be parsed")
            return 1
        name = parsed_request["query"]["qname"]
        type = parsed_request["query"]["qtype"]
        id = parsed_request["header"]["id"]
        try:
            response, parsed_response = self.resolve(name, type, id)
        except socket.timeout:
            print("Error: Time Out")
            print("Message: The server timed out and did not respond")
            exit(-1)
        except socket.error as e:
            print(f"Socket error: {e}")
            exit(-2)
        print("response to ",client_addr)
        if response is not None:
            self.socket.sendto(response,client_addr)
            return 0
        return -1


if __name__ == '__main__':
    usage = "Usage: python3 resolver.py <resolver_port>"
    #  Usage: python3 resolver.py <resolver_port>
    server_arg_check(sys.argv)
    if len(sys.argv) <2:
        print(usage)
        exit(1)
    resolver_port = int(sys.argv[1])
    # load debug config
    config_path = "config.json"
    DEBUG = load_config(config_path)
    
    # todo 
    # multiple type
    resolver = Resolver(resolver_port)
    resolver.start()
    #resolver.start_2()

