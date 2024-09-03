import numpy as np
import json as json
import costants as cs
import pandas as pd
import ipaddress as ip

def extract_binary_features(packet):
    #  protocolli di interesse
    protocol_mapping = ['eth', 'arp', 'icmp', 'ip', 'tcp', 'udp', 'mbtcp']

    # Estrai dal pacchetto
    protocols_present = packet['_source']['layers'].keys()

    # Crea la rappresentazione binaria come lista di 1/0
    binary_features = ['1' if protocol in protocols_present else '0' for protocol in protocol_mapping]
    
    return binary_features

def open_convert_capture(path):
    capture = open(path)
    capture_data = json.load(capture)
    capture.close()
    return capture_data

def create_array_values(data):
    packets_values = []

    for packet in data:
        
        
        tmp_pkt = []
        tmp_pkt.append(packet['_source']['layers']['frame']['frame.time_epoch'])
    
        for i in range(len(cs.interesting_layers)):
            if cs.interesting_layers[i] in packet['_source']['layers']:
                for field in cs.interesting_layer_fields[i]:
                    if field in packet['_source']['layers'][cs.interesting_layers[i]]:
                        tmp_pkt.append(packet['_source']['layers'][cs.interesting_layers[i]][field])
                    else:
                        tmp_pkt.append(np.nan)
            else:
                for field in cs.interesting_layer_fields[i]:
                    tmp_pkt.append(np.nan)

        if 'ip' in packet['_source']['layers']:
        
            # Aggiungi flags
                if 'ip.flags.rb' in packet['_source']['layers']['ip']['ip.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['ip']['ip.flags_tree']['ip.flags.rb'])
                else:
                    tmp_pkt.append(np.nan)
                if 'ip.flags.df' in packet['_source']['layers']['ip']['ip.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['ip']['ip.flags_tree']['ip.flags.df'])
                else:
                    tmp_pkt.append(np.nan)
                if 'ip.flags.mf' in packet['_source']['layers']['ip']['ip.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['ip']['ip.flags_tree']['ip.flags.mf'])
                else:
                    tmp_pkt.append(np.nan)
        if 'tcp' in packet['_source']['layers']:
            # Aggiungi flags
            if 'tcp.flags.res' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.res'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.ae' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ae'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.cwr' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.cwr'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.urg' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.urg'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.ack' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.push' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.push'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.syn' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'])
            else:
                    tmp_pkt.append(np.nan)
            if 'tcp.flags.fin' in packet['_source']['layers']['tcp']['tcp.flags_tree']:
                    tmp_pkt.append(packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin'])
            else:
                    tmp_pkt.append(np.nan)
        
        fb=extract_binary_features(packet)
        for elem in fb:
            tmp_pkt.append(elem)
            
        packets_values.append(tmp_pkt)
       
    return packets_values

def clean_df(dataframe):
    # Conversione del MAC Address da esadecimale a decimale
    # flags_ tutti nulli//
    # ip.checksum_status tutti nulli//
    # arp tutti null//
    # icmp tutti nulli (da verificare)//
    # tcp.checksum_status tutti null
    # eliminare le colonne che non servono piu alla fine e inserire i campi binari e vedere il numero di feature
    dataframe['eth.dst_cleaned'] = dataframe['eth.dst'].str.replace(":", "", regex=False)
    dataframe['eth.dst_int'] = dataframe['eth.dst_cleaned'].apply(lambda x : int(x, 16))
    dataframe['eth.src_cleaned'] = dataframe['eth.src'].str.replace(":", "", regex=False)
    dataframe['eth.src_int'] = dataframe['eth.src_cleaned'].apply(lambda x : int(x, 16))
    dataframe['eth.type'] = dataframe['eth.type'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) else np.nan
    )
    dataframe['eth.len'] = dataframe['eth.len'].astype(float)
    dataframe.drop(['eth.dst_cleaned', 'eth.dst', 'eth.src_cleaned', 'eth.src'], axis=1, inplace=True)

    dataframe['ip.version'] = dataframe['ip.version'].astype(float)
    dataframe['ip.hdr_len'] = dataframe['ip.hdr_len'].astype(float)
    dataframe['ip.src'].replace({np.nan: '169.254.0.0'}, inplace=True)
    dataframe['ip.dst'].replace({np.nan: '169.254.0.0'}, inplace=True)
    dataframe['ip.src'] = dataframe['ip.src'].apply(lambda x : int(ip.IPv4Address(x)))
    dataframe['ip.dst'] = dataframe['ip.dst'].apply(lambda x : int(ip.IPv4Address(x)))
    dataframe['ip.dsfield'] = dataframe['ip.dsfield'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) else np.nan
    )
    '''df_clean_30m['ip.dsfield_dscp'] = df_clean_30m['ip.dsfield_dscp'].astype(float)
    df_clean_30m['ip.dsfield_ecn'] = df_clean_30m['ip.dsfield_ecn'].astype(float)'''
    dataframe['ip.len'] = pd.to_numeric(dataframe['ip.len'], errors='coerce').astype('Int64')
    dataframe['ip.id'] = dataframe['ip.id'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )

    dataframe['ip.flags'] = dataframe['ip.flags'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )
    '''df_clean_30m['ip.frag_offset'] = df_clean_30m['ip.frag_offset'].astype(float)'''
    dataframe['ip.ttl'].fillna(0, inplace=True)

    # Convertire in intero
    dataframe['ip.ttl'] = dataframe['ip.ttl'].astype(int)
    dataframe['ip.proto'].fillna(0, inplace=True)

    # Ora puoi convertire la colonna 'ip.proto' in intero
    dataframe['ip.proto'] = dataframe['ip.proto'].astype(int)
    dataframe['ip.checksum'] = dataframe['ip.checksum'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )
    dataframe.loc[dataframe['tcp.srcport'] == '0']
    dataframe['tcp.srcport'].replace({np.nan: '0'}, inplace=True)
    dataframe['tcp.dstport'].replace({np.nan: '0'}, inplace=True)
    dataframe['tcp.srcport'] = dataframe['tcp.srcport'].apply(lambda x : int(x))
    dataframe['tcp.dstport'] = dataframe['tcp.dstport'].apply(lambda x : int(x))
    dataframe['tcp.stream'] = dataframe['tcp.stream'].astype(float)
    dataframe['tcp.len'] = dataframe['tcp.len'].astype(float)
    dataframe['tcp.seq'] = dataframe['tcp.seq'].astype(float)
    dataframe['tcp.nxtseq'] = dataframe['tcp.nxtseq'].astype(float)
    dataframe['tcp.ack'] = dataframe['tcp.ack'].astype(float)
    dataframe['tcp.hdr_len'] = dataframe['tcp.hdr_len'].astype(float)
    dataframe['tcp.window_size_value'] = dataframe['tcp.window_size_value'].astype(float)
    dataframe['tcp.window_size'] = dataframe['tcp.window_size'].astype(float)
    '''dataframe['tcp.window_size_scalefactor'] = dataframe['tcp.window_size_scalefactor'].astype(float)'''
    dataframe['tcp.urgent_pointer'] = dataframe['tcp.urgent_pointer'].astype(float)
    dataframe['tcp.flags'] = dataframe['tcp.flags'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )

    # Stesso approccio per 'tcp.checksum'
    dataframe['tcp.checksum'] = dataframe['tcp.checksum'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )


    dataframe['mbtcp.trans_id'] = dataframe['mbtcp.trans_id'].astype(float)
    dataframe['mbtcp.prot_id'] = dataframe['mbtcp.prot_id'].astype(float)
    dataframe['mbtcp.len'] = dataframe['mbtcp.len'].astype(float)
    dataframe['mbtcp.unit_id'] = dataframe['mbtcp.unit_id'].astype(float)

    dataframe['arp.hw.type'] = dataframe['arp.hw.type'].astype(float)
    dataframe['arp.proto.type'] = dataframe['arp.proto.type'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )



    dataframe['arp.hw.size'] = dataframe['arp.hw.size'].astype(float)
    dataframe['arp.proto.size'] = dataframe['arp.proto.size'].astype(float)
    dataframe['ip.checksum.status'] = dataframe['ip.checksum.status'].astype(float)
    dataframe['tcp.checksum.status'] = dataframe['tcp.checksum.status'].astype(float)
    dataframe['udp.srcport'] = dataframe['udp.srcport'].astype(float)
    dataframe['udp.dstport'] = dataframe['udp.dstport'].astype(float)
    dataframe['udp.port'] = dataframe['udp.port'].astype(float)
    dataframe['udp.length'] = dataframe['udp.length'].astype(float)
    dataframe['udp.checksum'] = dataframe['udp.checksum'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )
    dataframe['ip.flags.rb'] = dataframe['ip.flags.rb'].astype(float)
    dataframe['ip.flags.df'] = dataframe['ip.flags.df'].astype(float)
    dataframe['ip.flags.mf'] = dataframe['ip.flags.mf'].astype(float)
    dataframe['tcp.flags.res'] = dataframe['tcp.flags.res'].astype(float)
    dataframe['tcp.flags.ae'] = dataframe['tcp.flags.ae'].astype(float)
    dataframe['tcp.flags.cwr'] = dataframe['tcp.flags.cwr'].astype(float)
    dataframe['tcp.flags.urg'] = dataframe['tcp.flags.urg'].astype(float)
    dataframe['tcp.flags.ack'] = dataframe['tcp.flags.ack'].astype(float)
    dataframe['tcp.flags.push'] = dataframe['tcp.flags.push'].astype(float)
    dataframe['tcp.flags.syn'] = dataframe['tcp.flags.syn'].astype(float)
    dataframe['tcp.flags.fin'] = dataframe['tcp.flags.fin'].astype(float)
    dataframe['eth'] = dataframe['eth'].astype(float)
    dataframe['arp'] = dataframe['arp'].astype(float)
    dataframe['icmp'] = dataframe['icmp'].astype(float)
    dataframe['ip'] = dataframe['ip'].astype(float)
    dataframe['tcp'] = dataframe['tcp'].astype(float)
    dataframe['udp'] = dataframe['udp'].astype(float)
    dataframe['mbtcp'] = dataframe['mbtcp'].astype(float)

    dataframe['icmp.type'] = dataframe['icmp.type'].astype(float)
    dataframe['icmp.code'] = dataframe['icmp.code'].astype(float)
    dataframe['icmp.checksum'] = dataframe['icmp.checksum'].apply(
        lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) and len(x.strip()) > 0 else np.nan
    )
    dataframe['icmp.checksum.status'] = dataframe['icmp.checksum.status'].astype(float)


def get_layers_fields(data):
      layers_fields = {}
      fields_types = {}
      for packet in data:
            for i in range(len(cs.interesting_layers)):
                  
                if cs.interesting_layers[i] in packet['_source']['layers'].keys():
                      if cs.interesting_layers[i] not in layers_fields.keys():
                            layers_fields[cs.interesting_layers[i]] = packet['_source']['layers'][cs.interesting_layers[i]].keys()
                            for field in packet['_source']['layers'][cs.interesting_layers[i]]:
                                  fields_types[field] = packet['_source']['layers'][cs.interesting_layers[i]][field].__class__.__name__
                                  if fields_types[field] == 'dict' or fields_types[field] == 'list':
                                        fields_types[field] = [fields_types[field], len(packet['_source']['layers'][cs.interesting_layers[i]][field])]


      return [layers_fields, fields_types]


def create_list_json(data):
    packet_values = []
    
    
    for packet in data:
        tmp_pkt = []
        tmp_pkt_col = []
        for i in range(len(cs.interesting_layers)):
            if cs.interesting_layers in packet['_source']['layers']:
                for field in packet['_source']['layers'][cs.interesting_layers[i]]:
                    
                     
            
    
      
def extract_values_with_keys(data, parent_key='', result=None):
    if result is None:
        result = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            extract_values_with_keys(value, new_key, result)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_key = f"{parent_key}[{index}]"
            extract_values_with_keys(item, new_key, result)
    else:
        result.append((parent_key, data))
    return result