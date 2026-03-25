import threading, sys
from classes import Interface, Router, Node, arp_table, mac_port_table

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

# Unicast table for MAC to port
# R1: 1000
# R2: 1001
# R3: 1002
# N1: 1001
# N2: 1002
# N3: 1003
# N4: 1004

# Broadcast table for MAC to port
# R1: 1001, 1002
# R2: 1003
# R3: 1004

# ARP table for Router
# 0x12: N1
# 0x13: N2
# 0x22: N3
# 0x32: N4
# 0x11: R1
# 0x21: R2
# 0x31: R3

def setup():
    # Create Router and nodes
    host = "127.0.0.1" # Loopback interface address (localhost)
    router = setup_router(host)
    nodes = setup_nodes(host)
    # Start router listener in background thread
    threading.Thread(target=router.listen, daemon=True).start()

    # Start each node's listener in background thread
    for node in nodes.values():
        threading.Thread(target=node.listen, daemon=True).start()
    
    return nodes

def setup_router(host):
    R1 = Interface("R1", 0x11, "R1")
    R2 = Interface("R2", 0x21, "R2")
    R3 = Interface("R3", 0x31, "R3")

    Router_Interfaces = [R1, R2, R3]

    Router_broadcast_table = {"R1": [(host,1001),(host,1002)], "R2": [(host,1003)], "R3": [(host,1004)]}

    Router_ARP_table = arp_table()
    Router_ARP_table.add(0x11, "R1")
    Router_ARP_table.add(0x21, "R2")
    Router_ARP_table.add(0x31, "R3")
    Router_ARP_table.add(0x12, "N1")
    Router_ARP_table.add(0x13, "N2")
    Router_ARP_table.add(0x22, "N3")
    Router_ARP_table.add(0x32, "N4")

    Router_routing_table = {0x1: R1, 0x2: R2, 0x3: R3}

    return Router(Router_routing_table, Router_broadcast_table, Router_ARP_table, Router_Interfaces, 1000, host)

def setup_nodes(host):
    N1_ARP_table = arp_table()
    N1_ARP_table.add(0x11, "R1")
    N1_ARP_table.add(0x12, "N1")
    N1_ARP_table.add(0x13, "N2")
    N1_MAC_Port_table = mac_port_table()
    N1_MAC_Port_table.add("R1", 1000)
    N1_MAC_Port_table.add("N1", 1001)
    N1_MAC_Port_table.add("N2", 1002)

    N1 = Node("N1", 0x12, "N1", N1_ARP_table, N1_MAC_Port_table, "R1", 1001, host)

    N2_ARP_table = arp_table()
    N2_ARP_table.add(0x11, "R1")
    N2_ARP_table.add(0x12, "N1")
    N2_ARP_table.add(0x13, "N2")
    N2_MAC_Port_table = mac_port_table()
    N2_MAC_Port_table.add("R1", 1000)
    N2_MAC_Port_table.add("N1", 1001)
    N2_MAC_Port_table.add("N2", 1002)

    N2 = Node("N2", 0x13, "N2", N2_ARP_table, N2_MAC_Port_table, "R1", 1002, host)

    N3_ARP_table = arp_table()
    N3_ARP_table.add(0x21, "R2")
    N3_ARP_table.add(0x22, "N3")
    N3_MAC_Port_table = mac_port_table()
    N3_MAC_Port_table.add("R2", 1000)
    N3_MAC_Port_table.add("N3", 1003)
    N3 = Node("N3", 0x22, "N3", N3_ARP_table, N3_MAC_Port_table, "R2", 1003, host)

    N4_ARP_table = arp_table()
    N4_ARP_table.add(0x31, "R3")
    N4_ARP_table.add(0x32, "N4")
    N4_MAC_Port_table = mac_port_table()
    N4_MAC_Port_table.add("R3", 1000)
    N4_MAC_Port_table.add("N4", 1004)
    N4 = Node("N4", 0x32, "N4", N4_ARP_table, N4_MAC_Port_table, "R3", 1004, host)
    return {"N1":N1, "N2":N2, "N3":N3, "N4":N4}

def main():
    nodes = setup()
    print("Network setup complete. Available nodes: N1, N2, N3, N4")
    while (True):
        try:
            node_enter = input("State Node name to enter CLI or exit to quit: ")
            if node_enter == "exit" or node_enter == "quit":
                print("Exiting...")
                sys.exit(0)
            nodes[node_enter].cli()
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()



