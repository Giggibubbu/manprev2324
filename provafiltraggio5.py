import pandas as pd
import pyshark as pys
import re

# Caricamento del file di cattura
clean_cap_30m = pys.FileCapture(".\\captures\\captures1_v2\\pingFloodDDoS\\eth2dump-pingFloodDDoS1m-0,5h_1.pcap")

# Definizione dei campi di interesse
fields = [
    # Packet Timestamps
    'timestamp',
    # Inter-Packet Arrival Times
    'inter.packet_arrival_time',
    # Ethernet fields
    'eth.dst', 'eth.src', 'eth.type', 'eth.len',
    # ARP fields
    'arp.hw_type', 'arp.proto_type', 'arp.hw_size', 'arp.proto_size',
    # IP fields
    'ip.version', 'ip.hdr_len', 'ip.dsfield', 'ip.dsfield_dscp', 'ip.dsfield_ecn',
    'ip.len', 'ip.id', 'ip.flags', 'ip.flags_rb', 'ip.flags_df', 'ip.flags_mf',
    'ip.frag_offset', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.checksum_status', 'ip.src', 'ip.dst',
    # TCP fields
    'tcp.srcport', 'tcp.dstport', 'tcp.stream', 'tcp.len', 'tcp.seq', 'tcp.nxtseq', 'tcp.ack', 'tcp.hdr_len', 'tcp.flags', 'tcp.flags_res', 'tcp.flags_ae', 'tcp.flags_cwr', 'tcp.flags_ece', 'tcp.flags_urg', 'tcp.flags_ack', 'tcp.flags_push', 'tcp.flags_reset', 'tcp.flags_syn', 'tcp.flags_fin', 'tcp.flags_str', 'tcp.window_size_value', 'tcp.window_size', 'tcp.window_size_scalefactor', 'tcp.checksum', 'tcp.checksum_status', 'tcp.urgent_pointer',
    # MBTCP fields
    'mbtcp.trans_id', 'mbtcp.prot_id', 'mbtcp.len', 'mbtcp.unit_id',
    # UDP fields
    'udp.srcport', 'udp.dstport', 'udp.port', 'udp.length', 'udp.checksum', 'udp.checksum_status',
    # ICMP fields
    'icmp.type', 'icmp.code', 'icmp.checksum', 'icmp.checksum_status']

df1 = pd.DataFrame(columns=fields)

# Elenco per memorizzare i dati dei pacchetti
packets_data = []

# Iterazione attraverso i pacchetti
for packet_number, packet in enumerate(clean_cap_30m):
    '''if packet_number > 30000:  # Limita a un certo numero di pacchetti
        break'''
    print(packet_number)
    # Estrazione dei dati dei pacchetti
    temp_pkt = []
    field_name_arr = []
    
    field_name_set = set()
    temp_pkt.append(packet.sniff_time)
    ts = "timestamp"
    field_name_arr.append(ts)
    field_name_set.add(ts)
    
    for layer in packet.layers:
        if layer.layer_name in ["eth", "arp", "ip", "tcp", "mbtcp", "udp", "ICMP"]:
            for field_name in layer.field_names:
                concatenated_name = f"{layer.layer_name}.{field_name}"
                
                if concatenated_name in fields and concatenated_name not in field_name_set:
                    temp_pkt.append(layer.get(field_name))
                    field_name_arr.append(concatenated_name)
                    field_name_set.add(concatenated_name)
    
    if len(temp_pkt) == len(field_name_arr):
        # Creazione del DataFrame per il pacchetto corrente
        df = pd.DataFrame([temp_pkt], columns=field_name_arr)
        # Aggiunta dei dati al DataFrame complessivo
        packets_data.append(df)

# Concatenazione dei pacchetti raccolti
result = pd.concat(packets_data, ignore_index=True, sort=False)

# Escludere le colonne vuote o tutte-NA prima della concatenazione finale
result_cleaned = result.dropna(axis=1, how='all')

# Concatenazione finale
concatenated_df = pd.concat([df1, result_cleaned], ignore_index=True, sort=False)

# Calcolo del tempo di arrivo tra i pacchetti
concatenated_df['inter.packet_arrival_time'] = concatenated_df['timestamp'].diff()


# Conta il numero di colonne
print("ciao###################")
numero_colonne = concatenated_df.shape[1]
print(numero_colonne)
print("ciao################")
print(concatenated_df)
