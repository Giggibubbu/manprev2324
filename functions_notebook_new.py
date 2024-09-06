import json
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
import pandas as pd
import ipaddress

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

def mac_to_int(mac):
   
    if pd.notnull(mac) and isinstance(mac, str):
        return int(mac.replace(':', ''), 16)
    return 0

def ip_to_int(ip):
   
    if pd.notnull(ip) and isinstance(ip, str):
        try:
         
            return int(ipaddress.ip_address(ip))
        except ValueError:
            return 0
    return 0

def hex_to_int(hex_str):

    if pd.notnull(hex_str) and isinstance(hex_str, str):
        try:
            return int(hex_str, 16)  # Converte l'esadecimale in un intero
        except ValueError:
            return 0
    return 0

def convert(df):
 
    df_copy = df.copy()

    mac_columns = ['eth.src', 'eth.dst', 'ipv6.src_slaac_mac', 'ipv6.slaac_mac']
    for col in mac_columns:
        if col in df_copy.columns:
            df_copy[col] = df_copy[col].apply(mac_to_int)


    ip_columns = ['ipv6.src', 'ipv6.dst', 'ipv6.src_host', 'ipv6.dst_host', 'ipv6.host']
    for col in ip_columns:
        if col in df_copy.columns:
            df_copy[col] = df_copy[col].apply(ip_to_int)

 
    hex_columns = [col for col in df_copy.columns if 'raw' in col or 'hex' in col]
    for col in hex_columns:
        if col in df_copy.columns:
            df_copy[col] = df_copy[col].apply(hex_to_int)


    numeric_fields = df_copy.select_dtypes(include=['int64', 'float64']).columns

 
    for field in numeric_fields:
        df_copy[field] = pd.to_numeric(df_copy[field], errors='coerce')


    categorical_fields = df_copy.select_dtypes(include=['object']).columns

 
    label_encoder = LabelEncoder()
    for field in categorical_fields:
        df_copy[field] = label_encoder.fit_transform(df_copy[field].astype(str))


    df_copy.fillna(0, inplace=True)

    return df_copy


import pandas as pd

def df_convert(dataframe,elementi):
    # Elenco delle colonne che vogliamo convertire
    toint = ["frame.frame.encap_type", "frame.frame.number", "frame.frame.len", "eth.eth.dst_tree.eth.dst.oui", 
             "frame.frame.cap_len", "frame.frame.marked", "frame.frame.ignored", "eth.eth.dst_tree.eth.dst.lg_raw[0]", 
             "eth.eth.dst_tree.eth.addr.oui", "eth.eth.dst_tree.eth.dst.lg", "eth.eth.dst_tree.eth.lg_raw[0]", 
             "eth.eth.dst_tree.eth.lg", "eth.eth.dst_tree.eth.dst.ig_raw[0]", "eth.eth.dst_tree.eth.dst.ig", 
             "eth.eth.dst_tree.eth.ig_raw[0]", "eth.eth.dst_tree.eth.ig", "eth.eth.src_tree.eth.src.oui", 
             "eth.eth.src_tree.eth.addr.oui", "eth.eth.src_tree.eth.src.lg_raw[0]", "eth.eth.src_tree.eth.src.lg", 
             "eth.eth.src_tree.eth.lg_raw[0]", "eth.eth.src_tree.eth.lg", "eth.eth.src_tree.eth.src.ig_raw[0]", 
             "eth.eth.src_tree.eth.src.ig", "eth.eth.src_tree.eth.ig_raw[0]", "eth.eth.src_tree.eth.ig"]
    
    tohex = ["eth.eth.dst_raw[0]", "eth.eth.dst_tree.eth.dst_resolved_raw[0]", "eth.eth.dst_tree.eth.dst.oui_raw[0]", 
             "eth.eth.dst_tree.eth.addr_raw[0]", "eth.eth.dst_tree.eth.addr.oui_raw[0]", "eth.eth.src_raw[0]", 
             "eth.eth.src_tree.eth.src_resolved_raw[0]", "eth.eth.src_tree.eth.src.oui_raw[0]", 
             "eth.eth.src_tree.eth.src.oui_resolved_raw[0]", "eth.eth.src_tree.eth.addr_raw[0]",  
             "eth.eth.src_tree.eth.addr_resolved_raw[0]", "eth.eth.src_tree.eth.addr.oui_raw[0]", 
             "eth.eth.src_tree.eth.addr.oui_resolved_raw[0]"]

    mactohex = ["eth.eth.dst", "mac address", "eth.eth.dst_tree.eth.addr", "eth.eth.dst_tree.eth.addr_resolved_raw[0]","eth.eth.src_tree.eth.addr","eth.eth.src"]
    
    tofloat = ["frame.frame.time_epoch", "frame.frame.offset_shift", "frame.frame.time_delta", 
               "frame.frame.time_delta_displayed", "frame.frame.time_relative"]

    # Conversione in int
    for field in toint:
        if field in dataframe.columns and field in elementi:
            dataframe.loc[:, field] = pd.to_numeric(dataframe[field], errors='coerce').fillna(0).astype(int)

    # Conversione degli esadecimali
    for field in tohex:
        if field in dataframe.columns and field in elementi:
            dataframe.loc[:, field] = dataframe[field].apply(lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) else 0)

    # Conversione degli indirizzi MAC in esadecimale
    for field in mactohex:
        if field in dataframe.columns and field in elementi:
            # Rimuove i due punti dagli indirizzi MAC e converte
            dataframe.loc[:, field] = dataframe[field].str.replace(":", "", regex=False)
            dataframe.loc[:, field] = dataframe[field].apply(lambda x: int(x, 16) if pd.notnull(x) and isinstance(x, str) else 0)



    # Conversione in float
    for field in tofloat:
        if field in dataframe.columns and field in elementi:
            dataframe.loc[:, field] = pd.to_numeric(dataframe[field], errors='coerce').astype(float)

    return dataframe





















'''import pandas as pd
from sklearn.preprocessing import LabelEncoder
import ipaddress
import re


def is_valid_mac(mac):

    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$')
    return bool(mac_regex.match(mac))


def mac_to_int(mac):
    """Converte un indirizzo MAC in un numero intero se valido."""
    if isinstance(mac, str) and is_valid_mac(mac):
        return int(mac.replace(':', ''), 16)
    return mac


def ip_to_int(ip):
    """Converte un indirizzo IP in un numero intero, supporta sia IPv4 che IPv6."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return None 


def apply_function(cell_value, column_name):
    if pd.isna(cell_value):
        return None
    if 'mac' in column_name.lower() or 'eth' in column_name.lower():
        return mac_to_int(cell_value)
    elif 'ip' in column_name.lower():
        return ip_to_int(cell_value)
    else:
        return cell_value


for column in df:
    if column not in ['frame.frame.time', 'frame.frame.time_utc']:  # Escludi queste colonne
        df.loc[:, column] = df[column].apply(lambda cell_value: apply_function(cell_value, column))


le = LabelEncoder()
for column in df.select_dtypes(include=['object']).columns:
    if column not in ['frame.frame.time', 'frame.frame.time_utc']: 
        try:
            df.loc[:, column] = le.fit_transform(df[column])
        except:
            pass  
print(df)'''




'''import pandas as pd
from sklearn.feature_selection import VarianceThreshold
from sklearn.preprocessing import LabelEncoder

# Supponiamo che il tuo DataFrame si chiami 'df_clean'

# Lista di colonne da escludere
columns_to_exclude = ['frame.frame.time', 'frame.frame.time_utc']

# 1. Escludi le colonne che non vuoi considerare
df_clean = df_clean.drop(columns=columns_to_exclude)

# 2. Utilizza il LabelEncoder per convertire le colonne categoriali in numeri interi
le = LabelEncoder()
for column in df_clean.select_dtypes(include=['object']).columns:
    try:
        df_clean[column] = le.fit_transform(df_clean[column])
    except Exception as e:
        print(f"Impossibile codificare la colonna {column}: {e}")

# 3. Applica il VarianceThreshold per selezionare le feature con maggiore varianza
selector = VarianceThreshold(threshold=0.0)
df_reduced = selector.fit_transform(df_clean)

# 4. Seleziona le prime 68 feature con varianza maggiore
columns_selected = df_clean.columns[selector.get_support(indices=True)][:68]

# Crea un nuovo DataFrame con solo le prime 68 feature
df_final = pd.DataFrame(df_reduced, columns=columns_selected)

# Visualizza le feature selezionate
print(df_final)
print(f"Le 68 feature selezionate sono: {columns_selected}")
# Salva il DataFrame su un file Excelxlsx
df_final.to_excel('df.xlsx', index=False)'''




'''for column in df_cleaned.columns:
    if df_cleaned[column].dtype == 'object':
        try:
            # Prova a convertire le date in formato numerico (epoch time)
            df_cleaned.loc[:, column] = pd.to_datetime(df_cleaned[column]).astype(int) / 10**9  # Converte in epoch time
        except:
            # Se non si tratta di una data, usa factorize con .loc per evitare SettingWithCopyWarning
            df_cleaned.loc[:, column] = pd.factorize(df_cleaned[column])[0]

# 2. Rimozione delle eventuali colonne che non possono essere convertite
# Qui usiamo pd.to_numeric per forzare la conversione a numerico, sostituendo errori con NaN, quindi rimuoviamo eventuali colonne NaN
df_numeric = df_cleaned.apply(pd.to_numeric, errors='coerce').dropna(axis=1)

# 3. Ora df_numeric contiene solo colonne numeriche ed è pronto per Variance Threshold


from sklearn.feature_selection import VarianceThreshold

# Assicurati che il DataFrame df sia già caricato e preprocessato

# Applica VarianceThreshold
selector = VarianceThreshold()
X_var = selector.fit_transform(df_numeric)  # Usa il DataFrame che hai caricato, es. df

# Ottenere la varianza di ciascuna feature
variances = selector.variances_

# Ordina le varianze in ordine decrescente
sorted_indices = variances.argsort()[::-1]

# Seleziona le prime 68 feature con la varianza più alta
top_68_indices = sorted_indices[:68]

# Ottieni i nomi delle feature selezionate
selected_features = df.columns[top_68_indices]

# Mostra le feature selezionate
print(selected_features)


selectd_features2=['frame.frame.number', 'frame.frame.time', 'frame.frame.time_utc',
       'frame.frame.time_epoch', 'frame.frame.time_relative',
       'frame.frame.time_delta', 'frame.frame.time_delta_displayed',
       'eth.eth.dst_tree.eth.addr',
       'eth.eth.dst_tree.eth.addr_resolved_raw[0]',
       'eth.eth.dst_tree.eth.addr_resolved', 'eth.eth.dst_raw[0]',
       'eth.eth.dst_tree.eth.dst_resolved',
       'eth.eth.dst_tree.eth.dst_resolved_raw[0]', 'eth.eth.dst',
       'eth.eth.dst_tree.eth.addr_raw[0]', 'frame.frame.protocols',
       'eth.eth.src_tree.eth.addr_resolved',
       'eth.eth.src_tree.eth.src.oui_resolved_raw[0]',
       'eth.eth.src_tree.eth.addr.oui_resolved_raw[0]',
       'eth.eth.src_tree.eth.addr_resolved_raw[0]',
       'eth.eth.src_tree.eth.src_resolved', 'eth.eth.src_tree.eth.addr',
       'eth.eth.src_tree.eth.src_resolved_raw[0]',
       'eth.eth.src_tree.eth.addr_raw[0]', 'eth.eth.src', 'eth.eth.src_raw[0]',
       'frame.frame.len', 'frame.frame.cap_len',
       'frame.frame.coloring_rule.string', 'frame.frame.coloring_rule.name',
       'eth.eth.dst_tree.eth.addr.oui_raw[0]', 'eth.eth.dst_tree.eth.addr.oui',
       'eth.eth.dst_tree.eth.dst.oui', 'eth.eth.dst_tree.eth.dst.oui_raw[0]',
       'eth.eth.src_tree.eth.addr.oui_raw[0]', 'eth.eth.src_tree.eth.src.oui',
       'eth.eth.src_tree.eth.addr.oui_resolved',
       'eth.eth.src_tree.eth.addr.oui', 'eth.eth.src_tree.eth.src.oui_raw[0]',
       'eth.eth.src_tree.eth.src.oui_resolved', 'eth.eth.dst_tree.eth.ig',
       'eth.eth.dst_tree.eth.ig_raw[0]', 'eth.eth.dst_tree.eth.dst.ig',
       'eth.eth.dst_tree.eth.dst.ig_raw[0]', 'eth.eth.dst_tree.eth.dst.lg',
       'eth.eth.dst_tree.eth.dst.lg_raw[0]', 'eth.eth.dst_tree.eth.lg',
       'eth.eth.dst_tree.eth.lg_raw[0]', 'eth.eth.dst_tree.eth.dst.lg_raw[4]',
       'eth.eth.dst_raw[2]', 'eth.eth.dst_tree.eth.dst.lg_raw[1]',
       'eth.eth.dst_tree.eth.dst.lg_raw[2]', 'eth.eth.dst_raw[1]',
       'frame.frame.ignored', 'eth.eth.dst_tree.eth.dst.lg_raw[3]',
       'eth.eth.dst_tree.eth.addr_raw[2]', 'eth.eth.dst_raw[4]',
       'frame.frame.marked', 'frame.frame.offset_shift',
       'eth.eth.dst_tree.eth.lg_raw[1]', 'eth.eth.dst_tree.eth.lg_raw[2]',
       'eth.eth.dst_tree.eth.lg_raw[3]', 'eth.eth.dst_tree.eth.lg_raw[4]',
       'eth.eth.dst_raw[3]', 'eth.eth.dst_tree.eth.addr.oui_raw[4]',
       'eth.eth.dst_tree.eth.addr_raw[3]',
       'eth.eth.dst_tree.eth.dst.oui_raw[1]',
       'eth.eth.dst_tree.eth.addr_raw[4]']

df_numeric2 = df_numeric[selectd_features2]


# Salva il DataFrame su un file Excel
df_numeric2.to_excel('features_e.xlsx', index=False)'''

