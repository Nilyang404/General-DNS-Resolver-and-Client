# Universal DNS Resolver and Client

### Description

The DNS resolver is implemented in accordance with IEEE standards, which is able to accept, parse and respond to multiple types of DNS queries from clients.
Since some functions require querying the root DNS server, they should be used with an Internet connection.
![image](https://github.com/Nilyang404/General-DNS-Resolver-and-Client/assets/63556313/8cac07dc-cc91-482c-9f4d-22288b688fd1)

The client can send query requests to any DNS server according to IEEE standards, parse them, and display information.

### Usage

DNS Resolver

```shell
python3 resolver.py <resolver_port> 
```

DNS query client

```shell
python3 client.py <resolver_ip> <resolver_port> <domain name> [+enhanced args]
```
