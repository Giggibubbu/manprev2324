import json
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import pandas as pd
import numpy as np
import ipaddress
from scipy.stats import entropy
import pickle
import os
import random

def init_load_rstate():
    if not os.path.exists("./randomstate_array.pkl"):
        randomstate_array = [random.getrandbits(32) for randnr in range(10)]
        print(randomstate_array)
        with open("./randomstate_array.pkl", "wb") as file:
            pickle.dump(randomstate_array, file)
        return randomstate_array
    else:
        with open("./randomstate_array.pkl", "rb") as file:
            randomstate_array = pickle.load(file)
        return randomstate_array

def load_packets_from_file(file_path):
    with open(file_path, 'rb') as file:
        data = json.load(file)
    return data

def flatten_dict(d, parent_key=''):
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(flatten_dict(item, f"{new_key}[{i}]").items())
                    elif isinstance(item, list):
                        for j, sub_item in enumerate(item):
                            items.extend(flatten_dict({f"{new_key}[{i}][{j}]": sub_item}, new_key).items())
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))
    else:
        items.append((parent_key, d))
    return dict(items)

def extract_features_from_packets(packets, levels_of_interest):
    all_features = []
    
    for packet in packets:
        features = {}
        layers = packet.get('_source', {}).get('layers', {})
        for layer_name, layer_content in layers.items():
            if layer_name in levels_of_interest:
                features.update(flatten_dict(layer_content, layer_name))
        
        all_features.append(features)
    
    return all_features

def calcolo_features_binarie(df):
    # CALCOLO FEATURES BINARIE
    df['protocols_split'] = df['frame.frame.protocols'].str.split(':')

    protocols = set([proto for sublist in df['protocols_split'] for proto in sublist])

    for proto in protocols:
        df[proto] = df['protocols_split'].apply(lambda x: 1 if proto in x else 0)

    df.drop(columns=['protocols_split', 'ethertype'], inplace=True)

def calcola_features(dataframe, _time_groupby=1):
    dataframe['frame.frame.time_utc'] = pd.to_datetime(dataframe['frame.frame.time_utc'], unit='s')
    df_aggregation = pd.DataFrame()

    # Numero di eth, ip, arp, tcp, udp, tcp, mbtcp per raggruppamento nella cattura clean
    df_aggregation['eth_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['eth'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    df_aggregation['ip_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    if 'arp' in dataframe.columns:
        df_aggregation['arp_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['arp'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    else:
        df_aggregation['arp_count']=0
    if 'udp' in dataframe.columns:
        df_aggregation['udp_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['udp'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    else:
        df_aggregation['udp_count']=0
    df_aggregation['tcp_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    df_aggregation['mbtcp_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['mbtcp'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    if 'icmp' in dataframe.columns:
        df_aggregation['icmp_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['icmp'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    else:
        df_aggregation['icmp_count']=0
    
    # Numero di pacchetti per cattura
    df_aggregation['pkt_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['frame.frame.time_utc'].count().reset_index(name='pkt_count')['pkt_count']
    df_aggregation['per_eth_count'] = df_aggregation['eth_count']/df_aggregation['pkt_count']
    df_aggregation['per_ip_count'] = df_aggregation['ip_count']/df_aggregation['pkt_count']
    df_aggregation['per_icmp_count'] = df_aggregation['icmp_count']/df_aggregation['pkt_count']
    df_aggregation['per_arp_count'] = df_aggregation['arp_count']/df_aggregation['pkt_count']
    df_aggregation['per_udp_count'] = df_aggregation['udp_count']/df_aggregation['pkt_count']
    df_aggregation['per_tcp_count'] = df_aggregation['tcp_count']/df_aggregation['pkt_count']
    df_aggregation['per_mbtcp_count'] = df_aggregation['mbtcp_count']/df_aggregation['pkt_count']

    # Conversione dei flags del tcp
    # SYN
    dataframe['tcp.tcp.flags_tree.tcp.flags.syn'].fillna('0', inplace=True)
    dataframe['tcp.tcp.flags_tree.tcp.flags.syn'] = dataframe['tcp.tcp.flags_tree.tcp.flags.syn'].astype(int)
    # ACK
    dataframe['tcp.tcp.flags_tree.tcp.flags.ack'].fillna('0', inplace=True)
    dataframe['tcp.tcp.flags_tree.tcp.flags.ack'] = dataframe['tcp.tcp.flags_tree.tcp.flags.ack'].astype(int)

    # Aggiunta colonne tcp flags aggregate per raggruppamento
    df_aggregation['tcp_syn_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.flags_tree.tcp.flags.syn'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    df_aggregation['tcp_ack_count']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.flags_tree.tcp.flags.ack'].apply(lambda x: (x==1).sum()).reset_index(name='count')['count']
    df_aggregation['tcp_synack_fraction'] = np.where(df_aggregation['tcp_ack_count'] != 0, df_aggregation['tcp_syn_count'] / df_aggregation['tcp_ack_count'], 0)


    # Calcolo dell'inter arrival time
    dataframe['inter.packet_arrival_time'] = dataframe['frame.frame.time_utc'].diff()

    # Calcolo delle features aggregate su inter-arrival-time
    df_aggregation['ipat_std']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['inter.packet_arrival_time'].apply(lambda x: x.std()).reset_index(name='count')['count']
    df_aggregation['ipat_mode']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['inter.packet_arrival_time'].apply(lambda x: x.mode()).reset_index(name='count')['count']
    df_aggregation['ipat_max']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['inter.packet_arrival_time'].apply(lambda x: x.max()).reset_index(name='count')['count']
    df_aggregation['ipat_min']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['inter.packet_arrival_time'].apply(lambda x: x.min()).reset_index(name='count')['count']
    df_aggregation['ipat_entropy']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['inter.packet_arrival_time'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='count')['count']

    # Sostituzione dei NaN con un valore relativo a indirizzo di rete che non viene mai utilizzato nel dataset e conversione dell'ip src in intero
    dataframe['ip.ip.src'].fillna('169.254.0.0', inplace=True)
    dataframe['ip.ip.src_asint'] = dataframe['ip.ip.src'].apply(lambda x: int(ipaddress.IPv4Address(x.strip())))

    # Calcolo delle features aggregate su ip.ip.src
    df_aggregation['ip_src_std']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.src_asint'].apply(lambda x: x.std()).reset_index(name='count')['count']
    df_aggregation['ip_src_mode']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.src_asint'].apply(lambda x: x.mode()).reset_index(name='count')['count']
    df_aggregation['ip_src_entropy']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.src_asint'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='count')['count']

    # Sostituzione dei NaN con un valore relativo a indirizzo di rete che non viene mai utilizzato nel dataset e conversione dell'ip dst in intero
    dataframe['ip.ip.dst'].fillna('169.254.0.0', inplace=True)
    dataframe['ip.ip.dst_asint'] = dataframe['ip.ip.dst'].apply(lambda x: int(ipaddress.IPv4Address(x.strip())))

    # Calcolo delle features aggregate su ip.ip.dst
    df_aggregation['ip_dst_std']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.dst_asint'].apply(lambda x: x.std()).reset_index(name='count')['count']
    df_aggregation['ip_dst_mode']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.dst_asint'].apply(lambda x: x.mode()).reset_index(name='count')['count']
    df_aggregation['ip_dst_entropy']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.dst_asint'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='count')['count']

    # Sostituzione dei NaN con un valore relativo a una porta mai utilizzata e conversione della colonna tcp.tcp.dstport in intero
    dataframe['tcp.tcp.dstport'].fillna('0', inplace=True)
    dataframe['tcp.tcp.dstport_asint'] = dataframe['tcp.tcp.dstport'].apply(lambda x: int(x))

    # Calcolo delle features aggregate su tcp.tcp.dst
    df_aggregation['tcp_dstport_std']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.dstport_asint'].apply(lambda x: x.std()).reset_index(name='count')['count']
    df_aggregation['tcp_dstport_mode']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.dstport_asint'].apply(lambda x: x.mode()).reset_index(name='count')['count']
    df_aggregation['tcp_dstport_entropy']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.dstport_asint'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='count')['count']
    df_aggregation['tcp_dstport_mbtcp']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.dstport_asint'].apply(lambda x: (x==502).sum()).reset_index(name='count')['count']

    # Sostituzione dei NaN con un valore relativo a una porta mai utilizzata e conversione della colonna tcp.tcp.srcport in intero
    dataframe['tcp.tcp.srcport'].fillna('0', inplace=True)
    dataframe['tcp.tcp.srcport_asint'] = dataframe['tcp.tcp.srcport'].apply(lambda x: int(x))

    # Calcolo delle features aggregate su tcp.tcp.src
    df_aggregation['tcp_srcport_std']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.srcport_asint'].apply(lambda x: x.std()).reset_index(name='count')['count']
    df_aggregation['tcp_srcport_mode']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.srcport_asint'].apply(lambda x: x.mode()).reset_index(name='count')['count']
    df_aggregation['tcp_srcport_entropy']=dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['tcp.tcp.srcport_asint'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='count')['count']

    # CALCOLA NUMERO DI PACCHETTI CON STESSO IP DI DESTINAZIONE, MA GLI IP DI DESTINAZIONE POSSONO ESSERE DIVERSI, QUINDI IL DATAFRAME AVRA' PIù RIGHE
    df_cc_1 = dataframe.groupby([pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'), 'ip.ip.dst_asint']).size().reset_index(name='num_unique_ipdst')
    df_aggregation['maxnum_unique_ipdst'] = df_cc_1.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['num_unique_ipdst'].max().reset_index(name='maxnum_unique_ipdst')['maxnum_unique_ipdst']
    df_aggregation['minnum_unique_ipdst'] = df_cc_1.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['num_unique_ipdst'].min().reset_index(name='minnum_unique_ipdst')['minnum_unique_ipdst']
    df_aggregation['modenum_unique_ipdst'] = df_cc_1.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['num_unique_ipdst'].apply(lambda x: x.mode()).reset_index(name='modenum_unique_ipdst')['modenum_unique_ipdst']
    df_aggregation['stdnum_unique_ipdst'] = df_cc_1.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['num_unique_ipdst'].apply(lambda x: x.std()).reset_index(name='stdnum_unique_ipdst')['stdnum_unique_ipdst']
    df_aggregation['entropynum_unique_ipdst'] = df_cc_1.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['num_unique_ipdst'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='entropynum_unique_ipdst')['entropynum_unique_ipdst']

    # Numero di ip sorgenti/destinazione univoci nel raggruppamento
    df_aggregation['num_unique_ipsrc'] = dataframe.groupby([pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s')])['ip.ip.src'].nunique().reset_index(name='num_unique_ipsrc')['num_unique_ipsrc']
    df_aggregation['num_unique_ipdst'] = dataframe.groupby([pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s')])['ip.ip.dst'].nunique().reset_index(name='num_unique_ipdst')['num_unique_ipdst']

    # Sostituzione valori nulli e conversione del campo ip.len in intero
    dataframe['ip.ip.len'].fillna('0', inplace=True)
    dataframe['ip.ip.len'] = dataframe['ip.ip.len'].astype(int)

    # Calcolo aggregazioni su campo ip.len
    ## La moda è stata eliminata poichè ogni riga assumeva valore 40
    df_aggregation['std_iplen'] = dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.len'].apply(lambda x: x.std()).reset_index(name='std_iplen')['std_iplen']
    df_aggregation['entropy_iplen'] = dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.len'].apply(lambda x: entropy(x.value_counts()/len(x))).reset_index(name='entropy_iplen')['entropy_iplen']

    # Calcolo numero di bytes per unita di tempo
    df_aggregation['bytes_per_timeunit'] = dataframe.groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['ip.ip.len'].apply(lambda x: x.sum()/_time_groupby).reset_index(name='bytes_per_timeunit')['bytes_per_timeunit']

    # Calcolo numero di pacchetti per unita di tempo
    df_aggregation['pkt_per_timeunit'] = df_aggregation['pkt_count']/_time_groupby

    # Conversione dei campi sotto elencati in intero del dataframe input
    dataframe['modbus.modbus.func_code'].fillna('67', inplace=True)
    dataframe['modbus.modbus.func_code'] = dataframe['modbus.modbus.func_code'].astype(int)
    dataframe['frame.frame.len'] = dataframe['frame.frame.len'].astype(int)

    # Calcolo features modbus
    df_aggregation['modbus_response_count'] = dataframe[(dataframe['modbus.modbus.func_code'] == 3) & (dataframe['frame.frame.len'] == 85)].groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['frame.frame.len'].apply(lambda x: x.count()).reset_index(name='modbus_response_count')['modbus_response_count']
    df_aggregation['modbus_request_count'] = dataframe[(dataframe['modbus.modbus.func_code'] == 3) & (dataframe['frame.frame.len'] == 66)].groupby(pd.Grouper(key='frame.frame.time_utc', freq=f'{_time_groupby}s'))['frame.frame.len'].apply(lambda x: x.count()).reset_index(name='modbus_request_count')['modbus_request_count']
    df_aggregation['modb_req_resp_fraction'] = df_aggregation['modbus_request_count']/df_aggregation['modbus_request_count']

    
    if 'icmp.icmp.code' in dataframe.columns:
        dataframe['icmp.icmp.code'].fillna(99, inplace=True)
        dataframe['icmp.icmp.code'] = dataframe['icmp.icmp.code'].astype(int)
        df_aggregation['icmp_request_count'] = dataframe[dataframe['icmp.icmp.code'] == 0].groupby(pd.Grouper(key='frame.frame.time_utc', freq='5s'))['icmp.icmp.code'].count().reset_index(name='icmp_request_count')['icmp_request_count']
        df_aggregation['icmp_response_count'] = dataframe[dataframe['icmp.icmp.code'] == 8].groupby(pd.Grouper(key='frame.frame.time_utc', freq='5s'))['icmp.icmp.code'].count().reset_index(name='icmp_response_count')['icmp_response_count']
        df_aggregation['icmp_request_count'].fillna(0, inplace=True)
        if df_aggregation['icmp_response_count'].isna().any():
            df_aggregation['icmp_response_count'].fillna(0, inplace=True)
            df_aggregation['icmp_req_resp_fraction'] = df_aggregation[(df_aggregation['icmp_response_count'] != 0)]['icmp_request_count']/df_aggregation[df_aggregation['icmp_response_count'] !=0]['icmp_response_count']
            df_aggregation['icmp_req_resp_fraction'].fillna(0, inplace=True)
        else:
            df_aggregation['icmp_req_resp_fraction'] = df_aggregation['icmp_request_count'] / df_aggregation['icmp_response_count']
    else:
        df_aggregation['icmp_request_count'] = 0
        df_aggregation['icmp_response_count'] = 0
        df_aggregation['icmp_req_resp_fraction'] = 0

    return df_aggregation




















