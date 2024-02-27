#!/usr/bin/env python3

# ##############################
# Author:Neil
# Description:A DNS query and parse lib
# Date:18/07/2023
# Usage: import lib_dns in python
# ##############################

import sys
import socket
import struct
import random
import time
import argparse
import json
import enum
import re


def load_config(config_path):
    with open(config_path,"r") as file:
        config_data = json.load(file)
        debug = config_data.get('debug')
        if debug == "True":
            return True
        else:
            return False

DEBUG = load_config("config.json")

# check_client args
def server_arg_check(args):
    usage = "Usage: python3 resolver.py port"
    if len(args) != 2:
        print("Error:","invalid arguments")
        print(usage)
        exit(-3)
    port = sys.argv[1]
    if not is_valid_server_port(port):
        print("Error:","invalid arguments")
        print(usage)
        exit(-3)

    

# check_client args
def client_arg_check(args):
    usage = "Usage: python3 client.py <resolver_ip> <resolver_port> <name> [timeout = 5] [type = A]"
    if len(args) < 4:
        print("Error:","invalid arguments")
        print(usage)
        exit(-3)
    if len(args)>= 4:
        resolver_ip = sys.argv[1]
        resolver_port = sys.argv[2]
        name = sys.argv[3]
        if is_valid_dns_resolver(resolver_ip) and is_valid_client_port(resolver_port):
            pass
        else:
            print("Error:","invalid arguments")
            print(usage)
            exit(-3)

        if len(args) > 6:
            print("Error:","invalid arguments")
            print(usage)
            exit(-3)
        if len(args) == 5:
            if not (is_timeout(args[4]) or is_dns_type(args[4])):
                print("Error:","invalid arguments")
                print(usage)
                exit(-3)
        if len(args) == 6:
            if not (is_timeout(args[4]) or is_dns_type(args[4])):
                print("Error:","invalid arguments")
                print(usage)
                exit(-3)
            if not (is_timeout(args[5]) or is_dns_type(args[5])):
                print("Error:","invalid arguments")
                print(usage)
                exit(-3)  

def is_valid_dns_resolver(ip):
    if ip =="localhost" or is_valid_ipv4(ip) or is_valid_ipv6(ip):
        return True
    else:
        return False

def is_valid_server_port(port):
    if port.isdigit() and (1024 <= int(port) <= 65535):
        return True
    else:
        return False
        
def is_valid_client_port(port):
    if port.isdigit():
        if int(port) >= 0 and int(port) <= 65535:
            return True
        else:
            return False
    else:
        return False

# regex check for ipv4
# Reference: https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
def is_valid_ipv4(ip):
    ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(ipv4_pattern, ip) is not None
# regex check for ipv6
# Reference: https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
def is_valid_ipv6(ip):
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return re.match(ipv6_pattern, ip) is not None

# handle erorr code
def error_to_msg(code):
    error_dict= {
        "0":"No Error",
        "1":"Format Error",
        "2":"Server Failure",
        "3":"Name Error",
        "4":"Not Implemented",
        "5":"Refused"
    }
    return error_dict[str(code)]
# error check 
def error_code_check(code):
    if code != 0:
        if code == 1:
            print("Error: Format Error")
        elif code == 2:
            print("Error: Server Failure")
        elif code == 3:
            print("Error: Name Error, can't find the name")
        else:
            print(f"Error: Code {code}")
        exit(-4)
# error_ code check for server       
def error_code_check_server(code):
    # code 0, 2 5: don't need response, iter next one
    # code 4 , won't happen, will check on client side
    if code == 1:
        print("Error: Format Error")
        return True
    elif code == 3:
        print("Error: Name Error, can't find the name")
        return True
    else:
        return False

    

# create a binary query 
def create_query(domain, qtype = 1, qclass = 1, id = 9331):
    header = create_query_header(id)
    payload = create_query_payload(domain, qtype, qclass)
    query = header + payload

    if DEBUG:
        print("header: ",header)
        print("payload: ",payload,len(payload))
    
    return query
# Reference: RFC1035
# url: https://datatracker.ietf.org/doc/html/rfc1035
# Section 3.2
# create the header part
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def create_query_header(id):
    # generate id
    id = id

    # flags:
    # QR (Query/Response) flag: Set to 0 for queries
    qr = 0
    # 4 bits Opcode: 0 for standard query
    opcode = 0
    # AA (Authoritative Answer) flag: Set to 0 for queries set 0 for queries
    aa = 0
    # TC (Truncated) flag: Set to 0
    tc = 0
    # RD (Recursion Desired) flag: Set to 1 to enable recursive query
    rd = 0
    # RA (Recursion Available) flag: Set to 0 for queries
    ra = 0
    #  3 bits Z (Reserved) flags: Set to 0
    z = 0
    # 4 bits RCODE (Response Code) flags: Set to 0 for queries
    rcode = 0
    # put into 2 bytes flag
    # 0 - 15 , use <<  and | to build bit
    flags = (qr<<15)|(opcode<<11)|(aa<<10)|(tc<<9)|(rd<<8)|(ra<<7)|(z<<4)|(rcode<<0)

    # number of question
    qdcount = 1
    # number of answer
    ancount = 0
    # number of ahthority
    nscount = 0
    # number of additional
    arcount = 0
 
    # combine
    header = struct.pack("!HHHHHH", id, flags, qdcount, ancount, nscount, arcount)
    return header

def create_query_payload(domain, qtype = 1, qclass = 1):
    # build question part
    name_parts = domain.split(".")
    qname = b""
    for part in name_parts:
        length = len(part)
        qname += bytes([length]) + part.encode('utf-8')
    # add an extra byte at the end of domain name
    qname += b"\x00"
    qtype = struct.pack("!H",qtype)
    qclass = struct.pack("!H",qclass)
    question = qname + qtype + qclass
    payload = question

    return payload

def send_query(server, port, query):
    # create UDP socket
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, (server, port))
    response, _ = sock.recvfrom(4096)

    if DEBUG:
        print("response: " , response)
    return response

# parse the whole response
def parse_response(response):
    try:
        header = response[:12]
        id, flags, qdcount, ancount, nscount, arcount = parse_header(header)
        # use mask code to get the flag

        payload = response[12:]
        qname, qtype, qclass, query_len= parse_query(payload)
        answers = response[12 + query_len:]
        index = 12 + query_len
        # return a list
        answers_content, index = parse_answers(response, ancount, index)
        authority, index = parse_answers(response, nscount, index)
        additional, index = parse_answers(response, arcount, index)
        parsed_response = {
            "header":{
                "id":id,
                "flags": flags,
                "qdcount": qdcount,
                "ancount": ancount,
                "nscount": nscount,
                "arcount": arcount,
            },
            "query":{
                "qname": qname,
                "qtype": qtype,
                "qclass": qclass
            },
            "answers": answers_content,
            "authority": authority,
            "additional": additional
        }
        if DEBUG:
            print("parsed_response: ", parsed_response)
        return parsed_response
    except Exception as e:
        return None
def parse_header(header):
    (id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('!HHHHHH', header)
    # may need to parse flag
    # use mask code
    # 0b1000 0000 0000 0000
    qr = (flags & 0x8000) >> 15
    # 0b0111 1000 0000 0000
    opcode = (flags & 0x7800) >> 11
    # 0b0000 0100 0000 0000
    aa = (flags & 0x0400) >> 10
    # 0b0000 0010 0000 0000
    tc = (flags & 0x0200) >> 9
    # 0b0000 0001 0000 0000
    rd = (flags & 0x0100) >> 8
    # 0b0000 0000 1000 0000
    ra = (flags & 0x0080) >> 7
    # 0b0000 0000 0111 0000
    z = (flags & 0x0070) >> 4
    # 0b0000 0000 0000 1111
    rcode = flags & 0x000F

    parsed_flags = {
        "qr":qr,
        "opcode":opcode,
        "aa":aa,
        "tc":tc,
        "rd":rd,
        "ra":ra,
        "z":z,
        "rcode":rcode
    }
    return id, parsed_flags, qdcount, ancount, nscount, arcount
# assume there is one query
# TODO:
# multiple query
def parse_query(payload):
    qname = ""
    qtype = 0
    qclass = 0
    index = 0
    length =  payload[index]
    while True:
        length = payload[index]
        if length == 0:
            index += 1
            break
        if index != 0:
            qname += "."
        index += 1
        qname += payload[index:index+length].decode("utf-8")
        index += length
    # have an \x00 at the end of domain name 
    # take 2 bytes for each
    qtype, qclass = struct.unpack("!HH",payload[index:index + 4])
    query_len = index + 4

    if DEBUG:
        print("qname:", qname)
        print("qtype:", qtype)
        print("qclass:", qclass)
        print("query_len",query_len)

    return qname,qtype,qclass,query_len

def parse_answers(response, ancount, index):
    """
    struct of answers_content:
    [
        {
            "name": name,
            "type": qtype,
            "class": qclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata": parsed_rdata
        }
        {
            ..
        }
    ]
    """
    answers_content = []
    for i in range(ancount):
        #name, qtype, qclass, ttl, rdlength = struct.unpack('!HHHLH', answers[:12])
        name, index = parse_name(response,index)
        qtype, qclass, ttl, rdlength = struct.unpack('!HHLH', response[index: index + 10])
        index += 10
        rdata = response[index: index + rdlength]
        parsed_rdata = parse_rdata(rdata , qtype, response, index)
        answers_content.append({
            "name": name,
            "type": qtype,
            "class": qclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata": parsed_rdata
        })
        index += rdlength
        
    if DEBUG:
        print("answers_content: ", answers_content)
        # for e in answers_content:
        #     for key, value in e.items():
        #         print(f"{key}: {value}")
    return answers_content,index

def parse_name(response, index):
    name = ""
    while True:
        length = response[index]
        if length == 0:
            index += 1
            return name,index
        # if not a pointer, take the name
        elif (length & 0xC0) != 0xC0:
            index += 1
            name += response[index:index+length].decode("utf-8") + "."
            index += length
         # 0b1100 a pointer
        elif (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) + response[index+1]
            index += 2
            _name, _ = parse_name(response, ptr)
            name += _name
            break
    return name,index

def parse_rdata(rdata,type, response, index):
    parsed_rdata = ""
    # could be A, NS , .. MX ..
    # 1:A
    # 2:NS
    # 5:CNAME
    # 6:SOA
    # 12:PTR
    # 15:MX
    # 16:TXT
    # 28:AAAA
    if type == 1:
        # A
        parsed_rdata = ".".join(str(byte) for byte in rdata)
    elif type == 2:
        # NS
        parsed_rdata, _ = parse_name(response,index)
    elif type == 5:
        # CNAME
        parsed_rdata, _ = parse_name(response,index)
    elif type == 6:
        # SOA
        # will exit() if there is an error
        # does not work now
        parsed_rdata = str(rdata)
        pass
        # mname, rname, serial, refresh, retry, expire, minimum = struct.unpack('!HHIIIII', data)
        # serial = f"{serial:08d}"
        # parsed_rdata = {
        #     'Primary Server': mname.decode(),
        #     'Responsible Person': rname.decode(),
        #     'Serial Number': serial,
        #     'Refresh Interval': refresh,
        #     'Retry Interval': retry,
        #     'Expire Limit': expire,
        #     'Minimum TTL': minimum,
        # }
    elif type == 12:
        # PTR
        parsed_rdata, _ = parse_name(response,index)
    elif type == 15:
        # MX
        priority, mail_server = struct.unpack('!H', rdata[:2])[0], rdata[2:]
        mail_server, _ = parsed_rdata, _ = parse_name(response,index + 2)
        parsed_rdata = {
                 "priority":priority,
                 "name":mail_server
        }
                   
    elif type == 16:
        # TXT
        parsed_rdata, _ = parse_name(response,index)
    elif type == 28:
        # AAAA
        parsed_rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    else:
        # other unknown
        parsed_rdata = rdata

    return parsed_rdata

# check interger
# may return True for  000001
# check arg type
def is_timeout(arg):
    return arg.isdigit()
# check arg type
def is_dns_type(arg):
    return arg.upper() in ["A","NS","CNAME","PTR","MX","AAAA"]

def type_to_num(type):
    type_dict = {
        "A":1,
        "NS":2,
        "CNAME":5,
        "PTR":12,
        "MX":15,
        "AAAA":28
    }
    return type_dict[type]

def num_to_type(num):
    type_dict = {
        "1":"A",
        "2":"NS",
        "5":"CNAME",
        "12":"PTR",
        "15":"MX",
        "28":"AAAA"
    }
    return type_dict[str(num)]

# build a ptr type name
# reverse and add ".in-addr.arpa"
def get_ptr_name(domain):
    temp = reversed(domain.split("."))
    reversed_domain = ".".join(temp)
    ptr_name = reversed_domain + ".in-addr.arpa"
    return ptr_name

# add a answer record to raw response 
def add_answer_to_response(response):
    header = response[:12]
    id, flags, qdcount, ancount, nscount, arcount = parse_header(header)
    # use mask code to get the flag

    payload = response[12:]
    qname, qtype, qclass, query_len= parse_query(payload)
    answers = response[12 + query_len:]
    index = 12 + query_len
    # return a list
    answers_content, index = parse_answers(response, ancount, index)
    authority, index = parse_answers(response, nscount, index)
    additional, index = parse_answers(response, arcount, index)
    parsed_response = {
        "header":{
            "id":id,
            "flags": flags,
            "qdcount": qdcount,
            "ancount": ancount,
            "nscount": nscount,
            "arcount": arcount,
        },
        "query":{
            "qname": qname,
            "qtype": qtype,
            "qclass": qclass
        },
        "answers": answers_content,
        "authority": authority,
        "additional": additional
    }
    if DEBUG:
        print("parsed_response: ", parsed_response)
    return parsed_response

# handle output format
def show_query_time(query_time):
    print(query_time * 1000)

def show_result(parsed_response, other_info = None):
    qdcount = parsed_response["header"]["qdcount"]
    ancount = parsed_response["header"]["ancount"]
    nscount = parsed_response["header"]["nscount"]
    arcount = parsed_response["header"]["arcount"]
    temp = []
    for key, value in parsed_response["header"]["flags"].items():
        if value == 1:
            temp.append(key)
    flags = " ".join(temp)
    opcode = parsed_response['header']['flags']['opcode']
    rcode = parsed_response['header']['flags']['rcode']
    query =  parsed_response['query']
    asnwers = parsed_response['answers']
    authority = parsed_response['authority']
    additional = parsed_response['additional']
    print("\n; <<>> My DNS Client <<>>",parsed_response["query"]["qname"],num_to_type(parsed_response["query"]["qtype"]))
    print(";; Got answer:")
    print(f";; ->>HEADER<<- opcode: {opcode}, rcode: {error_to_msg(rcode)}, id: {parsed_response['header']['id']}")
    print(f";; flags: {flags}; QUERY: {qdcount}, ANSWER: {ancount}, AUTHORITY: {nscount}, ADDITIONAL: {arcount}")
    print("\n;; QUESTION SECTION:")
    # assume all class are IN
    print(f";{query['qname']}\t\t IN\t {num_to_type(query['qtype'])}\t")
    print("\n;; ANSWER SECTION:")

    for record in asnwers:
        rdata = record['rdata']
        # if type = MX
        if isinstance(rdata, dict):
            rdata = str(rdata["priority"]) + " " + rdata["name"]
        print(f"{record['name']} \t {record['ttl']} \t IN \t {num_to_type(record['type'])} \t {rdata}")

    if len(authority) > 0:
        print("\n;; AUTHORITY SECTION:")
        for record in authority:
            rdata = record['rdata']
            # if type = MX
            if isinstance(rdata, dict):
                rdata = str(rdata["priority"]) + " " + rdata["name"]
            print(f"{record['name']} \t {record['ttl']} \t IN \t {num_to_type(record['type'])} \t {rdata}")

    if len(additional) > 0:
        print("\n;; ADDITIONAL SECTION:")
        for record in authority:
            rdata = record['rdata']
            # if type = MX
            if isinstance(rdata, dict):
                rdata = str(rdata["priority"]) + " " + rdata["name"]
            print(f"{record['name']} \t {record['ttl']} \t IN \t {num_to_type(record['type'])} \t {rdata}")
    if other_info is not None:
        # ms
        query_time = round(other_info["query_time"] * 1000)
        server = other_info["server"]
        port = other_info["port"]
        res_time = other_info["res_time"]
        msg_size = other_info["msg_size"]
        print("")
        print(f";; Query time: {query_time} msec")
        print(f";; SERVER: {server}#{port}({server})")
        print(f";; WHEN: {res_time}")
        print(f";; MSG SIZE  rcvd: {msg_size}")


