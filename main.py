import socket

# Goal emulate a network with 1 router and 3 LANs
# Router has 3 interfaces R1,R2,R3
# IP and MAC address pairs, (0x11,R1), (0x21,R2), (0x31,R3)
# LAN1 is attached to R1, LAN2 is attached to R2, LAN3 is attached to R3
# LAN 1 has 1 nodes, N1 and N2, with IP and MAC address pairs (0x1A,N1)
# LAN 2 has 2 node, N2 and N3 with IP and MAC address pair (0x2B,N2) and (0x2A,N3)
# LAN 3 has 2 nodes, N4 and N5, with IP and MAC address pairs (0x3A,N4) and (0x3B,N5)
# Ethernet emulation: Use python sockets to emulate Ethernet broadcast
    # Then emulate the MAC behavior so that those not the intended recipient would drop the datagram
    # Format the Ethernet frame: [Destination MAC][Source MAC][Data Length][Payload]
    #                            2 bytes         2 bytes       1 bytes     up to 256 bytes
#IP emulation: The emulated IP addresses for Node1, Node2 and Node3 are 0x1A,0x2A,0X2B
    #Emulated IP addresses for Router are R1 (0x11) and R2 (0x21) and R3 (0x31)
    #Emulated IP datagram format: [Destination IP][Source IP][Protocol][Data Length][Payload]
    #                              1 byte         1 byte     1 byte    1 byte      up to 256 bytes
# Packet forwarding emulation: No need to implement routing protocols unless doing so for Open Category
# Entry point and firewall configuration point is the nodes
# Write function to demonstrate IP spoofing on Node 1. Accepts User input to impersonate selected node to send to another node
# Write function to demonstrate sniffing. Accept User input at Node 1 to sniff Node 2's communications
# Firewall: On Node 3 implement a packet filter. User can add and remove rules to the filter, demonstrate by blocking packets from Node2 and accept all others

#Implementation:
    # Create a socket for each node and one for the router
    # Sending would involve creating the MAC to socket table
    # IP to MAC translation would be using a device's ARP table, if no entry then send to default Gateway the router interface in the LAN
    # For the router, it would have a routing table to determine which interface to forward the packet to and a broadcast table to send to all devices at once

# For Open Category, Design and Implement other security functions or attacks on the network then demo it

def main():
    host = "127.0.0.1" # Loopback interface address (localhost)
