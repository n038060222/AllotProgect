# Sniffer

Sniffer to detect SYN flood attack.

## Description

The sniffer sits on a network device selected by the user, receives the packets, detects dDoS attacks in the TCP protocol and blocks them.
The detection is done by mapping packets and blocking IP addresses that sent many initial handshake calls in a short period of time.
Each packet is captured by the PCAP and the relevant data is saved in the SQLIT DB.
If the packet comes from a previously blocked IP address, it is ignored. The packet is then checked to see if it is an initial handshake (SYN=1). If so, it is inserted into a hash table that stores all the IP addresses of the sources of the packets that are initial handshakes together with the amount of clicks from each IP.
If the amount of requests from that IP exceeds a certain amount, the address is blocked using the IPTABLE command and is saved in a hash table of blocked IP addresses and in the table of blocked IP addresses in the DB.
The hash table is reset every period of time in order to detect an increased amount of requests at a certain time.
We have enabled a user interface using the ^C signal that presents the user with an opportunity to get a glimpse of the program's operation.
