import pandas as pd
import sklearn 
import pyshark as pys
import re

clean_cap_30m = pys.FileCapture(".\\captures\\captures1_v2\\clean\\eth2dump-clean-0,5h_1.pcap")
# clean_cap_1h = pys.FileCapture("captures\\captures1_v2\\clean\\eth2dump-clean-1h_1.pcap")

"""malic_cap_modbus_1m_30m_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding1m-0,5h_1.pcap")
malic_cap_modbus_5m_30m_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding5m-0,5h_1.pcap")
malic_cap_modbus_15m_30m_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding15m-0,5h_1.pcap")"""

"""malic_cap_modbus_1m_1h_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding1m-1h_1.pcap")
malic_cap_modbus_5m_1h_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding5m-1h_1.pcap")
malic_cap_modbus_15m_1h_2 = pys.FileCapture("captures\\captures1_v2\\modbusQuery2Flooding\\eth2dump-modbusQuery2Flooding15m-1h_1.pcap")"""

"""malic_cap_modbus_1m_30m_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding1m-0,5h_1.pcap")
malic_cap_modbus_5m_30m_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding5m-0,5h_1.pcap")
malic_cap_modbus_15m_30m_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding15m-0,5h_1.pcap")"""

"""malic_cap_modbus_1m_1h_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding1m-1h_1.pcap")
malic_cap_modbus_5m_1h_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding5m-1h_1.pcap")
malic_cap_modbus_15m_1h_1 = pys.FileCapture("captures\\captures1_v2\\modbusQueryFlooding\\eth2dump-modbusQueryFlooding15m-1h_1.pcap")"""

"""malic_cap_ping_1m_30m_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS1m-0,5h_1.pcap")
malic_cap_ping_5m_30m_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS5m-0,5h_1.pcap")
malic_cap_ping_15m_30m_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS15m-0,5h_1.pcap")"""

"""malic_cap_ping_1m_1h_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS1m-1h_1.pcap")
malic_cap_ping_5m_1h_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS5m-1h_1.pcap")
malic_cap_ping_15m_1h_1 = pys.FileCapture("captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS15m-1h_1.pcap")"""

"""malic_cap_tcp_1m_30m_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS1m-0,5h_1.pcap")
malic_cap_tcp_5m_30m_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS5m-0,5h_1.pcap")
malic_cap_tcp_15m_30m_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS15m-0,5h_1.pcap")"""

"""malic_cap_tcp_1m_1h_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS1m-1h_1.pcap")
malic_cap_tcp_5m_1h_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS5m-1h_1.pcap")
malic_cap_tcp_15m_1h_1 = pys.FileCapture("captures\\captures3\\tcpSYNFloodDDoS\\eth2dump-tcpSYNFloodDDoS15m-1h_1.pcap")"""

"""packets_data = []
for packet in clean_cap_30m:
    if "IP" in packet and "TCP" in packet:
        packet_info = {
            "src_ip": packet.ip.src,
            "dst_ip": packet.ip.dst,
            "src_port": packet.tcp.srcport,
            "dst_port": packet.tcp.dstport,
            "length": packet.length
        }
        packets_data.append(packet_info)"""
"""for packet in clean_cap_30m:
    print(f'Pacchetto numero {packet.number}:')
    
    # Itera attraverso ogni layer nel pacchetto
    for layer in packet.layers:
        print(f'  Layer: {layer.layer_name}')
        
        # Ottieni tutti i campi di questo layer
        for field_name in layer.field_names:
            # Stampa il nome del campo e il suo valore
            print(f'    Campo: {field_name}, Valore: {layer.get(field_name)}')

    print('\\n')"""

packets_field_values = []
interesting_layers = ["eth", "arp", "ip", "tcp", "mbtcp", "udp", "icmp"]
eth_not_interesting_fields = []
not_interesting_fields = ["tcp._ws_expert_message", "tcp._ws_expert_group", "eth._ws_expert_severity"]
packet_number = 0
pattern = re.compile(r"\.\_")
test = "eth._sddklsl"
fields=["tcp.flags_fin", "tcp.completeness_rst", "arp.hw_type", "tcp.flags_push",
    "tcp.analysis_push_bytes_sent", "tcp.completeness_syn_ack", "eth.dst_resolved",
    "eth.dst_ig", "tcp.options", "eth.len", "tcp.completeness_syn", "tcp.checksum",
    "eth.addr_resolved", "tcp.flags_cwr", "tcp.analysis", "ip.src_host",
    "tcp.flags_str", "eth.dst_lg", "tcp.flags_ece", "ip.flags_mf", "eth.trailer",
    "tcp.window_size_value", "tcp.flags_reset", "tcp.options_sack_perm_absent",
    "tcp.analysis_initial_rtt", "eth.src_oui", "tcp.analysis_acks_frame", "eth.dst_oui",
    "mbtcp.prot_id", "ip.dst", "ip.ttl", "tcp.connection_fin_active", "arp.dst_hw_mac", "tcp.pdu_size", "tcp.dstport", "ip.hdr_len", "eth.fcs",
    "tcp.completeness_data", "ip.version", "arp.proto_size", "eth.lg", "ip.dst_host",
    "ip.checksum", "ip.host", "eth.src_resolved", "eth.src_lg", "ip.dsfield",
    "arp.hw_size", "tcp.completeness_ack", "tcp.completeness_fin", "arp.src_hw_mac",
    "tcp.ack", "arp.src_proto_ipv4", "eth.addr",
    "tcp.stream", "tcp.window_size", "ip.frag_offset", "eth.padding", "arp.dst_proto_ipv4",
    "eth.ig", "tcp.len", "tcp.flags_ack", "arp.opcode", "tcp.seq_raw", "tcp.connection_synack",
    "tcp.nxtseq", "tcp.connection_fin_passive"]
fields_splitted = []
for field in fields:
     fields_splitted.append(field.split('.', 1)[1])


for packet in clean_cap_30m:
    temp_pkt=[]
    if packet_number>50:
        break
    packet_number+=1
    for layer in packet.layers:
        
            if layer.layer_name in interesting_layers:        
                
                
                
                
                for field_name in layer.field_names:
                         
                    if field_name in fields_splitted:
                        temp_pkt.append(layer.get(field_name))
                    for field in fields_splitted:
                        if field not in layer.field_names:
                             
                                                   
                            
    packets_field_values.append(temp_pkt)


print(len(packets_field_values[1]))

"""for layer in clean_cap_30m[2]:
        
        if layer.layer_name in interesting_layers:
            print(layer.field_names)
            for field in layer.field_names:
                field_names_set.add(field)"""


"""for element in field_names_set:
    print(f'{element},')
print("\n##########################################")
print(len(field_names_set))"""

'''df = pd.DataFrame(packets_field_values, columns=fields)'''
print("\n##########################################")


