import json
import pandas as pd

def load_packets_from_file(file_path):
    with open(file_path, 'r') as file:
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


levels_of_interest = ['frame', 'eth', 'tcp', 'arp', 'udp', 'modbus', 'icmp', 'ip']


file_path = 'C:\\Users\\User\\Desktop\\manprev2324\\manprev2324\\captures\\captures1_v2\\clean\\eth2dump-clean-0,5h_1.json'

packets = load_packets_from_file(file_path)


features_list = extract_features_from_packets(packets, levels_of_interest)


df = pd.DataFrame(features_list)
print(df)


tipi_elementi_univoci = set()


for colonna in df.columns:
    tipi_elementi_univoci.update(type(elemento) for elemento in df[colonna].dropna())


tipi_elementi_univoci_array = list(tipi_elementi_univoci)

print(tipi_elementi_univoci_array)


for colonna in df.columns:
    for index, elemento in df[colonna].items():
        if isinstance(elemento, list):
            print(f"Elemento di tipo list trovato nella colonna '{colonna}' all'indice {index}: {elemento}")
df.to_excel('features_extracted_selected_levels.xlsx', index=False)

print("Il DataFrame è stato scritto su 'features_extracted_selected_levels.xlsx'.")