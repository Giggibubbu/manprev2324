import pandas as pd
import sklearn 
import pyshark
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score

i=2
capture = pyshark.FileCapture("C:\\Users\\User\\Desktop\\MANUTENZIONE PROGETTO\\dataset\\captures1_v2\\captures1_v2\\clean\\eth2dump-clean-0,5h_1.pcap")
packets_data = []
for packet in capture:
    if 'IP' in packet and 'TCP' in packet:
        packet_info = {
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'src_port': packet.tcp.srcport,
            'dst_port': packet.tcp.dstport,
            'length': packet.length
        }
        packets_data.append(packet_info)

# Chiudi la cattura
capture.close()
df = pd.DataFrame(packets_data)
df['src_ip'] = df['src_ip'].apply(lambda x: int(''.join([f'{int(octet):08b}' for octet in x.split('.')]), 2))
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(''.join([f'{int(octet):08b}' for octet in x.split('.')]), 2))

# Converti le porte in numeri interi
df['src_port'] = df['src_port'].astype(int)
df['dst_port'] = df['dst_port'].astype(int)

scaler = StandardScaler()
df_normalized = scaler.fit_transform(df)

labels = [0, 1] * (len(df_normalized) // 2)  # Etichette di esempio

# Dividi i dati in set di allenamento e test
X_train, X_test, y_train, y_test = train_test_split(df_normalized, labels, test_size=0.3, random_state=42)

# Crea il modello KNN
knn = KNeighborsClassifier(n_neighbors=3)

# Addestra il modello
knn.fit(X_train, y_train)

# Fai previsioni
y_pred = knn.predict(X_test)

# Valuta il modello
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')
