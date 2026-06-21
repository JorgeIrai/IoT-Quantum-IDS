import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split


def extract_features(TCP_file, UDP_file, label):
    # Cargar el archivo CSV en un DataFrame
    df = TCP_file
    #print(df.isna().sum())
    df.fillna(0, inplace=True)
    
    # Calcular la desviación estándar de los puertos de origen y destino para cada flujo
    stdev_src = df.groupby('tcp.stream')['tcp.srcport'].std()
    stdev_dst = df.groupby('tcp.stream')['tcp.dstport'].std()
    
    # Calcular estadísticas de frame_len por flujo
    frame_len_min = df.groupby('tcp.stream')['frame.len'].min()
    frame_len_max = df.groupby('tcp.stream')['frame.len'].max()
    frame_len_std = df.groupby('tcp.stream')['frame.len'].std()
    frame_len_mean = df.groupby('tcp.stream')['frame.len'].mean()
    
    # Calcular la proporción de paquetes con cada flag activado en cada flujo
    total_pack = df.groupby('tcp.stream').size()
    
    
    ip_flags_rb = df.groupby('tcp.stream')['ip.flags.rb'].apply(lambda x: (x==1).sum()) / total_pack
    ip_flags_df = df.groupby('tcp.stream')['ip.flags.df'].apply(lambda x: (x==1).sum()) / total_pack
    ip_flags_mf = df.groupby('tcp.stream')['ip.flags.mf'].apply(lambda x: (x==1).sum()) / total_pack
    
    # Calcular la proporción de paquetes con cada flag TCP activado en cada flujo
    tcp_flags_res = df.groupby('tcp.stream')['tcp.flags.res'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ns = df.groupby('tcp.stream')['tcp.flags.ns'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_cwr = df.groupby('tcp.stream')['tcp.flags.cwr'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ecn = df.groupby('tcp.stream')['tcp.flags.ecn'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_urg = df.groupby('tcp.stream')['tcp.flags.urg'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ack = df.groupby('tcp.stream')['tcp.flags.ack'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_push = df.groupby('tcp.stream')['tcp.flags.push'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_reset = df.groupby('tcp.stream')['tcp.flags.reset'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_syn = df.groupby('tcp.stream')['tcp.flags.syn'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_fin = df.groupby('tcp.stream')['tcp.flags.fin'].apply(lambda x: (x==1).sum()) / total_pack
    
    
    df['Interarrival'] = ((df['frame.time_epoch']).diff())
    df['Interarrival'].fillna(0, inplace=True)
    int_std = df.groupby('tcp.stream')['Interarrival'].std()
    int_min = df.groupby('tcp.stream')['Interarrival'].min()
    int_max = df.groupby('tcp.stream')['Interarrival'].max()
    int_mean = df.groupby('tcp.stream')['Interarrival'].mean()
    
    
    # Calcular estadísticas de TTL por flujo
    df['ip.ttl']=df['ip.ttl'].astype(str)
    df['ip.ttl']=pd.to_numeric(df['ip.ttl'].str.replace(',','.'))
    
    ip_ttl_std = df.groupby('tcp.stream')['ip.ttl'].std()
    ip_ttl_min = df.groupby('tcp.stream')['ip.ttl'].min()
    ip_ttl_max = df.groupby('tcp.stream')['ip.ttl'].max()
    ip_ttl_mean = df.groupby('tcp.stream')['ip.ttl'].mean()
    
    
    df['ip.checksum.status']=df['ip.checksum.status'].astype(str)
    df['ip.checksum.status']=pd.to_numeric(df['ip.checksum.status'].str.replace(',','.'))
    ip_checksum_status_std = df.groupby('tcp.stream')['ip.checksum.status'].std()
    ip_checksum_status_min = df.groupby('tcp.stream')['ip.checksum.status'].min()
    ip_checksum_status_max = df.groupby('tcp.stream')['ip.checksum.status'].max()
    ip_checksum_status_mean = df.groupby('tcp.stream')['ip.checksum.status'].mean()
    
    
    # Calcular estadísticas de tcp.checksum.status por flujo
    df['tcp.checksum.status']=df['tcp.checksum.status'].astype(str)
    df['tcp.checksum.status']=pd.to_numeric(df['tcp.checksum.status'].str.replace(',','.'))
    tcp_checksum_status_std = df.groupby('tcp.stream')['tcp.checksum.status'].std()
    tcp_checksum_status_min = df.groupby('tcp.stream')['tcp.checksum.status'].min()
    tcp_checksum_status_max = df.groupby('tcp.stream')['tcp.checksum.status'].max()
    tcp_checksum_status_mean = df.groupby('tcp.stream')['tcp.checksum.status'].mean()
    
    # Calcular estadísticas de tcp.seq_raw por flujo
    tcp_seq_raw_std = df.groupby('tcp.stream')['tcp.seq_raw'].std()
    tcp_seq_raw_min = df.groupby('tcp.stream')['tcp.seq_raw'].min()
    tcp_seq_raw_max = df.groupby('tcp.stream')['tcp.seq_raw'].max()
    tcp_seq_raw_mean = df.groupby('tcp.stream')['tcp.seq_raw'].mean()
    
    # Calcular estadísticas de tcp.ack_raw por flujo
    tcp_ack_raw_std = df.groupby('tcp.stream')['tcp.ack_raw'].std()
    tcp_ack_raw_min = df.groupby('tcp.stream')['tcp.ack_raw'].min()
    tcp_ack_raw_max = df.groupby('tcp.stream')['tcp.ack_raw'].max()
    tcp_ack_raw_mean = df.groupby('tcp.stream')['tcp.ack_raw'].mean()
    
    tcp_window_size_value_std = df.groupby('tcp.stream')['tcp.window_size_value'].std()
    tcp_window_size_value_min = df.groupby('tcp.stream')['tcp.window_size_value'].min()
    tcp_window_size_value_max = df.groupby('tcp.stream')['tcp.window_size_value'].max()
    tcp_window_size_value_mean = df.groupby('tcp.stream')['tcp.window_size_value'].mean()
    
    
    #El campo frame.time_epoch ya está en segundos
    stream_duration = (df.groupby('tcp.stream')['frame.time_epoch'].max() - df.groupby('tcp.stream')['frame.time_epoch'].min())
    
    #Número de paquetes por segundo en cada flujo
    packet_rate = total_pack/stream_duration
    packet_rate = packet_rate.replace(np.inf,0) 
    
    #Bps throughput
    frame_len_rate = df.groupby('tcp.stream')['frame.len'].sum()/stream_duration
    frame_len_rate = frame_len_rate.replace(np.inf,0) 
    
    
    payload_std = df.groupby('tcp.stream')['tcp.len'].std()
    payload_min =  df.groupby('tcp.stream')['tcp.len'].min()
    payload_max =  df.groupby('tcp.stream')['tcp.len'].max()
    payload_mean =  df.groupby('tcp.stream')['tcp.len'].mean()
    
    proto = "TCP"
    
        
    # Fusionar las desviaciones estándar con el DataFrame original
    df_TCP = pd.DataFrame({
        'srcport.std': stdev_src.values,
        'dstport.std': stdev_dst.values,
        'frame.len.min': frame_len_min.values,
        'frame.len.max': frame_len_max.values,
        'frame.len.std': frame_len_std.values,
        'frame.len.mean': frame_len_mean.values,
        'frame.len.rate':frame_len_rate.values,
        'ip.flags.rb': ip_flags_rb.values,
        'ip.flags.df': ip_flags_df.values,
        'ip.flags.mf': ip_flags_mf.values,
        'tcp.flags.res': tcp_flags_res.values,
        'tcp.flags.ns': tcp_flags_ns.values,
        'tcp.flags.cwr': tcp_flags_cwr.values,
        'tcp.flags.ecn': tcp_flags_ecn.values,
        'tcp.flags.urg': tcp_flags_urg.values,
        'tcp.flags.ack': tcp_flags_ack.values,
        'tcp.flags.push': tcp_flags_push.values,
        'tcp.flags.reset': tcp_flags_reset.values,
        'tcp.flags.syn': tcp_flags_syn.values,
        'tcp.flags.fin': tcp_flags_fin.values,
        'int.std': int_std.values,
        'int.min': int_min.values,
        'int.max': int_max.values,
        'int.mean': int_mean.values,
        'count': total_pack,
        'ip.ttl.std': ip_ttl_std,
        'ip.ttl.min': ip_ttl_min,
        'ip.ttl.max': ip_ttl_max,
        'ip.ttl.mean': ip_ttl_mean,
        'ip.checksum.status.std': ip_checksum_status_std,
        'ip.checksum.status.min': ip_checksum_status_min,
        'ip.checksum.status.max': ip_checksum_status_max,
        'ip.checksum.status.mean': ip_checksum_status_mean,
        'l4.checksum.status.std': tcp_checksum_status_std,
        'l4.checksum.status.min': tcp_checksum_status_min,
        'l4.checksum.status.max': tcp_checksum_status_max,
        'l4.checksum.status.mean': tcp_checksum_status_mean,
        'tcp.seq_raw.std': tcp_seq_raw_std,
        'tcp.seq_raw.min': tcp_seq_raw_min,
        'tcp.seq_raw.max': tcp_seq_raw_max,
        'tcp.seq_raw.mean': tcp_seq_raw_mean,
        'tcp.ack_raw.std': tcp_ack_raw_std,
        'tcp.ack_raw.min': tcp_ack_raw_min,
        'tcp.ack_raw.max': tcp_ack_raw_max,
        'tcp.ack_raw.mean': tcp_ack_raw_mean,
        'tcp.window_size_value.std': tcp_window_size_value_std,
        'tcp.window_size_value.min': tcp_window_size_value_min,
        'tcp.window_size_value.max': tcp_window_size_value_max,
        'tcp.window_size_value.mean': tcp_window_size_value_mean,
        'duration': stream_duration,
        'prate': packet_rate,
        'payload.std': payload_std.values,
        'payload.min': payload_min.values,
        'payload.max': payload_max.values,
        'payload.mean': payload_mean.values,
        'proto': proto})
        
    

    
    ###############################################################################################
    
    df_UDP = UDP_file
    df_UDP.fillna(0, inplace=True)
    
    # Calcular la desviación estándar de los puertos de origen y destino para cada flujo
    stdev_src = df_UDP.groupby('udp.stream')['udp.srcport'].std()
    stdev_dst = df_UDP.groupby('udp.stream')['udp.dstport'].std()
    
    # Calcular estadísticas de frame_len por flujo
    frame_len_min = df_UDP.groupby('udp.stream')['frame.len'].min()
    frame_len_max = df_UDP.groupby('udp.stream')['frame.len'].max()
    frame_len_std = df_UDP.groupby('udp.stream')['frame.len'].std()
    frame_len_mean = df_UDP.groupby('udp.stream')['frame.len'].mean()
    
    # Calcular la proporción de paquetes con cada flag activado en cada flujo
    total_pack = df_UDP.groupby('udp.stream').size()
    
    ip_flags_rb = df_UDP.groupby('udp.stream')['ip.flags.rb'].apply(lambda x: (x==1).sum()) / total_pack
    ip_flags_df = df_UDP.groupby('udp.stream')['ip.flags.df'].apply(lambda x: (x==1).sum()) / total_pack
    ip_flags_mf = df_UDP.groupby('udp.stream')['ip.flags.mf'].apply(lambda x: (x==1).sum()) / total_pack
    
    # Calcular la proporción de paquetes con cada flag TCP activado en cada flujo
    tcp_flags_res = df_UDP.groupby('udp.stream')['tcp.flags.res'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ns = df_UDP.groupby('udp.stream')['tcp.flags.ns'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_cwr = df_UDP.groupby('udp.stream')['tcp.flags.cwr'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ecn = df_UDP.groupby('udp.stream')['tcp.flags.ecn'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_urg = df_UDP.groupby('udp.stream')['tcp.flags.urg'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_ack = df_UDP.groupby('udp.stream')['tcp.flags.ack'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_push = df_UDP.groupby('udp.stream')['tcp.flags.push'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_reset = df_UDP.groupby('udp.stream')['tcp.flags.reset'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_syn = df_UDP.groupby('udp.stream')['tcp.flags.syn'].apply(lambda x: (x==1).sum()) / total_pack
    tcp_flags_fin = df_UDP.groupby('udp.stream')['tcp.flags.fin'].apply(lambda x: (x==1).sum()) / total_pack
    
    df_UDP['Interarrival'] = ((df_UDP['frame.time_epoch']).diff())
    df_UDP['Interarrival'].fillna(0, inplace=True)
    int_std = df_UDP.groupby('udp.stream')['Interarrival'].std()
    int_min = df_UDP.groupby('udp.stream')['Interarrival'].min()
    int_max = df_UDP.groupby('udp.stream')['Interarrival'].max()
    int_mean = df_UDP.groupby('udp.stream')['Interarrival'].mean()
    
    # Calcular estadísticas de TTL por flujo
    df_UDP['ip.ttl'] = df_UDP['ip.ttl'].astype(str).str.replace(',', '.')
    df_UDP['ip.ttl'] = pd.to_numeric(df_UDP['ip.ttl'])
    ip_ttl_std = df_UDP.groupby('udp.stream')['ip.ttl'].std()
    ip_ttl_min = df_UDP.groupby('udp.stream')['ip.ttl'].min()
    ip_ttl_max = df_UDP.groupby('udp.stream')['ip.ttl'].max()
    ip_ttl_mean = df_UDP.groupby('udp.stream')['ip.ttl'].mean()
    
    df_UDP['ip.checksum.status'] = df_UDP['ip.checksum.status'].astype(str).str.replace(',', '.')
    df_UDP['ip.checksum.status'] = pd.to_numeric(df_UDP['ip.checksum.status'])
    ip_checksum_status_std = df_UDP.groupby('udp.stream')['ip.checksum.status'].std()
    ip_checksum_status_min = df_UDP.groupby('udp.stream')['ip.checksum.status'].min()
    ip_checksum_status_max = df_UDP.groupby('udp.stream')['ip.checksum.status'].max()
    ip_checksum_status_mean = df_UDP.groupby('udp.stream')['ip.checksum.status'].mean()
    
    # Calcular estadísticas de tcp.checksum.status por flujo
    df_UDP['udp.checksum.status'] = df_UDP['udp.checksum.status'].astype(str).str.replace(',', '.')
    df_UDP['udp.checksum.status'] = pd.to_numeric(df_UDP['udp.checksum.status'])
    udp_checksum_status_std = df_UDP.groupby('udp.stream')['udp.checksum.status'].std()
    udp_checksum_status_min = df_UDP.groupby('udp.stream')['udp.checksum.status'].min()
    udp_checksum_status_max = df_UDP.groupby('udp.stream')['udp.checksum.status'].max()
    udp_checksum_status_mean = df_UDP.groupby('udp.stream')['udp.checksum.status'].mean()
    
    # Calcular estadísticas de tcp.seq_raw por flujo
    tcp_seq_raw_std = df_UDP.groupby('udp.stream')['tcp.seq_raw'].std()
    tcp_seq_raw_min = df_UDP.groupby('udp.stream')['tcp.seq_raw'].min()
    tcp_seq_raw_max = df_UDP.groupby('udp.stream')['tcp.seq_raw'].max()
    tcp_seq_raw_mean = df_UDP.groupby('udp.stream')['tcp.seq_raw'].mean()
    
    # Calcular estadísticas de tcp.ack_raw por flujo
    tcp_ack_raw_std = df_UDP.groupby('udp.stream')['tcp.ack_raw'].std()
    tcp_ack_raw_min = df_UDP.groupby('udp.stream')['tcp.ack_raw'].min()
    tcp_ack_raw_max = df_UDP.groupby('udp.stream')['tcp.ack_raw'].max()
    tcp_ack_raw_mean = df_UDP.groupby('udp.stream')['tcp.ack_raw'].mean()
    
    tcp_window_size_value_std = df_UDP.groupby('udp.stream')['tcp.window_size_value'].std()
    tcp_window_size_value_min = df_UDP.groupby('udp.stream')['tcp.window_size_value'].min()
    tcp_window_size_value_max = df_UDP.groupby('udp.stream')['tcp.window_size_value'].max()
    tcp_window_size_value_mean = df_UDP.groupby('udp.stream')['tcp.window_size_value'].mean()
    
    # El campo frame.time_epoch ya está en segundos
    stream_duration = (df_UDP.groupby('udp.stream')['frame.time_epoch'].max() - df_UDP.groupby('udp.stream')['frame.time_epoch'].min())
    
    # Número de paquetes por segundo en cada flujo
    packet_rate = total_pack / stream_duration
    packet_rate = packet_rate.replace(np.inf, 0)
    
    # Bps throughput
    frame_len_rate = df_UDP.groupby('udp.stream')['frame.len'].sum() / stream_duration
    frame_len_rate = frame_len_rate.replace(np.inf, 0)
    
    payload_std = df_UDP.groupby('udp.stream')['udp.length'].std()
    payload_min = df_UDP.groupby('udp.stream')['udp.length'].min()
    payload_max = df_UDP.groupby('udp.stream')['udp.length'].max()
    payload_mean = df_UDP.groupby('udp.stream')['udp.length'].mean()
    
    proto_UDP = "UDP"
    
    # Fusionar las desviaciones estándar con el DataFrame original
    df_UDP = pd.DataFrame({
        'srcport.std': stdev_src.values,
        'dstport.std': stdev_dst.values,
        'frame.len.min': frame_len_min.values,
        'frame.len.max': frame_len_max.values,
        'frame.len.std': frame_len_std.values,
        'frame.len.mean': frame_len_mean.values,
        'frame.len.rate':frame_len_rate.values,
        'ip.flags.rb': ip_flags_rb.values,
        'ip.flags.df': ip_flags_df.values,
        'ip.flags.mf': ip_flags_mf.values,
        'tcp.flags.res': tcp_flags_res.values,
        'tcp.flags.ns': tcp_flags_ns.values,
        'tcp.flags.cwr': tcp_flags_cwr.values,
        'tcp.flags.ecn': tcp_flags_ecn.values,
        'tcp.flags.urg': tcp_flags_urg.values,
        'tcp.flags.ack': tcp_flags_ack.values,
        'tcp.flags.push': tcp_flags_push.values,
        'tcp.flags.reset': tcp_flags_reset.values,
        'tcp.flags.syn': tcp_flags_syn.values,
        'tcp.flags.fin': tcp_flags_fin.values,
        'int.std': int_std.values,
        'int.min': int_min.values,
        'int.max': int_max.values,
        'int.mean': int_mean.values,
        'count': total_pack,
        'ip.ttl.std': ip_ttl_std,
        'ip.ttl.min': ip_ttl_min,
        'ip.ttl.max': ip_ttl_max,
        'ip.ttl.mean': ip_ttl_mean,
        'ip.checksum.status.std': ip_checksum_status_std,
        'ip.checksum.status.min': ip_checksum_status_min,
        'ip.checksum.status.max': ip_checksum_status_max,
        'ip.checksum.status.mean': ip_checksum_status_mean,
        'l4.checksum.status.std': udp_checksum_status_std,
        'l4.checksum.status.min': udp_checksum_status_min,
        'l4.checksum.status.max': udp_checksum_status_max,
        'l4.checksum.status.mean': udp_checksum_status_mean,
        'tcp.seq_raw.std': tcp_seq_raw_std,
        'tcp.seq_raw.min': tcp_seq_raw_min,
        'tcp.seq_raw.max': tcp_seq_raw_max,
        'tcp.seq_raw.mean': tcp_seq_raw_mean,
        'tcp.ack_raw.std': tcp_ack_raw_std,
        'tcp.ack_raw.min': tcp_ack_raw_min,
        'tcp.ack_raw.max': tcp_ack_raw_max,
        'tcp.ack_raw.mean': tcp_ack_raw_mean,
        'tcp.window_size_value.std': tcp_window_size_value_std,
        'tcp.window_size_value.min': tcp_window_size_value_min,
        'tcp.window_size_value.max': tcp_window_size_value_max,
        'tcp.window_size_value.mean': tcp_window_size_value_mean,
        'duration': stream_duration,
        'prate': packet_rate,
        'payload.std': payload_std.values,
        'payload.min': payload_min.values,
        'payload.max': payload_max.values,
        'payload.mean': payload_mean.values,
        'proto': proto_UDP
    })

   
    df_TCP.fillna(0, inplace=True)
    df_UDP.fillna(0, inplace=True)
    
    
    X_TCP = df_TCP.drop(columns=['proto'])
    y_TCP = df_TCP['proto']
    X_train_TCP, X_test_TCP, y_train_TCP, y_test_TCP = train_test_split(X_TCP, y_TCP, test_size=0.3)
    X_val_TCP, X_test_TCP, y_val_TCP, y_test_TCP = train_test_split(X_test_TCP, y_test_TCP, test_size=2/3)
    
    X_UDP = df_UDP.drop(columns=['proto'])
    y_UDP = df_UDP['proto']
    X_train_UDP, X_test_UDP, y_train_UDP, y_test_UDP = train_test_split(X_UDP, y_UDP, test_size=0.3)
    X_val_UDP, X_test_UDP, y_val_UDP, y_test_UDP = train_test_split(X_test_UDP, y_test_UDP, test_size=2/3)
    
    
    # Para el conjunto de entrenamiento
    train_data_TCP = X_train_TCP.copy()
    train_data_TCP['proto'] = y_train_TCP
    
    train_data_UDP = X_train_UDP.copy()
    train_data_UDP['proto'] = y_train_UDP
    
    train = pd.concat([train_data_TCP, train_data_UDP], ignore_index=True)
    

    # Para el conjunto de validación
    val_data_TCP = X_val_TCP.copy()
    val_data_TCP['proto'] = y_val_TCP
    
    val_data_UDP = X_val_UDP.copy()
    val_data_UDP['proto'] = y_val_UDP
    
    validation = pd.concat([val_data_TCP, val_data_UDP], ignore_index=True)

    
    # Para el conjunto de prueba
    test_data_TCP = X_test_TCP.copy()
    test_data_TCP['proto'] = y_test_TCP
    
    test_data_UDP = X_test_UDP.copy()
    test_data_UDP['proto'] = y_test_UDP
    
    test = pd.concat([test_data_TCP, test_data_UDP], ignore_index=True)
    
    
    train['category'] = label
    validation['category'] = label
    test['category'] = label
    
    
    
    
    
    return train, validation, test
    
    
def Benign_Dataset():
    TCP_file1 = os.path.join("Benign_final", "BenignTCP.txt")
    UDP_file1 = os.path.join("Benign_final", "BenignUDP.txt")
    label = "Benign"

    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')
    
    train1, validation1, test1 = extract_features(TCP1, UDP1, label)
    
    TCP_file2 = os.path.join("Benign_final", "BenignTCP1.txt")
    UDP_file2 = os.path.join("Benign_final", "BenignUDP1.txt")

    TCP2 = pd.read_csv(TCP_file2, delimiter='\t')
    UDP2 = pd.read_csv(UDP_file2, delimiter='\t')
    
    train2, validation2, test2 = extract_features(TCP2, UDP2, label)

    
    TCP_file3 = os.path.join("Benign_final", "BenignTCP2.txt")
    UDP_file3 = os.path.join("Benign_final", "BenignUDP2.txt")

    TCP3 = pd.read_csv(TCP_file3, delimiter='\t')
    UDP3 = pd.read_csv(UDP_file3, delimiter='\t')
    
    train3, validation3, test3 = extract_features(TCP3, UDP3, label)
    
    TCP_file4 = os.path.join("Benign_final", "BenignTCP3.txt")
    UDP_file4 = os.path.join("Benign_final", "BenignUDP3.txt")
    
    TCP4 = pd.read_csv(TCP_file4, delimiter='\t')
    UDP4 = pd.read_csv(UDP_file4, delimiter='\t')
    
    train4, validation4, test4 = extract_features(TCP4, UDP4, label)
    
    train = pd.concat([train1, train2, train3, train4], ignore_index=True)
    validation = pd.concat([validation1, validation2, validation3, validation4], ignore_index=True)
    test = pd.concat([test1, test2, test3, test4], ignore_index=True)

    
    return train, validation, test



def PortScan_Dataset():
    TCP_file1 = os.path.join("Recon-PortScan", "ReconPortScanTCP.txt")
    UDP_file1 = os.path.join("Recon-PortScan", "ReconPortScanUDP.txt")
    label = "Recon-PortScan"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test



def OSScan_Dataset():
    TCP_file1 = os.path.join("Recon-OSScan", "ReconOSScanTCP.txt")
    UDP_file1 = os.path.join("Recon-OSScan", "ReconOSScanUDP.txt")
    label = "Recon-OSScan"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test



def HostDiscovery_Dataset():
    TCP_file1 = os.path.join("Recon-HostDiscovery", "ReconHostDiscoveryTCP.txt")
    UDP_file1 = os.path.join("Recon-HostDiscovery", "ReconHostDiscoveryUDP.txt")
    label = "Recon-HostDiscovery"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test




def DDosHTTPFlood_Dataset():
    TCP_file1 = os.path.join("DDoS-HTTP_Flood", "DDoSHTTPFloodTCP.txt")
    UDP_file1 = os.path.join("DDoS-HTTP_Flood", "DDoSHTTPFloodUDP.txt")
    label = "DDoS-HTTP_Flood"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test

def DDosUDPFlood_Dataset():
    
    TCP_file1 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodTCP.txt")
    UDP_file1 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodUDP.txt")
    label = "DDoS-UDP_Flood"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train1, validation1, test1 = extract_features(TCP1, UDP1, label)
    
    TCP_file2 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodTCP1.txt")
    UDP_file2 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodUDP1.txt")
    
    TCP2 = pd.read_csv(TCP_file2, delimiter='\t')
    UDP2 = pd.read_csv(UDP_file2, delimiter='\t')

    train2, validation2, test2 = extract_features(TCP2, UDP2, label)
    
    
    TCP_file3 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodTCP2.txt")
    UDP_file3 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodUDP2.txt")
        
    TCP3 = pd.read_csv(TCP_file3, delimiter='\t')
    UDP3 = pd.read_csv(UDP_file3, delimiter='\t')
    
    train3, validation3, test3 = extract_features(TCP3, UDP3, label)
    
    
    TCP_file4 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodTCP3.txt")
    UDP_file4 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodUDP3.txt")
        
    TCP4 = pd.read_csv(TCP_file4, delimiter='\t')
    UDP4 = pd.read_csv(UDP_file4, delimiter='\t')
    
    train4, validation4, test4 = extract_features(TCP4, UDP4, label)
    

    TCP_file5 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodTCP4.txt")
    UDP_file5 = os.path.join("DDoS-UDP_Flood", "DDoSUDPFloodUDP4.txt")
    
    TCP5 = pd.read_csv(TCP_file5, delimiter='\t')
    UDP5 = pd.read_csv(UDP_file5, delimiter='\t')

    train5, validation5, test5 = extract_features(TCP5, UDP5, label)
    
    train = pd.concat([train1, train2, train3, train4, train5], ignore_index=True)
    validation = pd.concat([validation1, validation2, validation3, validation4, validation5], ignore_index=True)
    test = pd.concat([test1, test2, test3, test4, test5], ignore_index=True)
  
    
    
    return train, validation, test


def DDosSYNFlood_Dataset():
    TCP_file1 = os.path.join("DDoS-SYN_Flood", "DDoSSYNFloodTCP.txt")
    UDP_file1 = os.path.join("DDoS-SYN_Flood", "DDoSSYNFloodUDP.txt")
    label = "DDoS-SYN_Flood"

    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    
    return train, validation, test


def DosHTTPFlood_Dataset():
    TCP_file1 = os.path.join("DoS-HTTP_Flood", "DoSHTTPFloodTCP.txt")
    UDP_file1 = os.path.join("DoS-HTTP_Flood", "DoSHTTPFloodUDP.txt")
    label = "DoS-HTTP_Flood"
    
    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test

def DosSYNFlood_Dataset():
    TCP_file1 = os.path.join("DoS-SYN_Flood", "DoSSYNFloodTCP.txt")
    UDP_file1 = os.path.join("DoS-SYN_Flood", "DoSSYNFloodUDP.txt")
    label = "DoS-SYN_Flood"

    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test
    

def DosUDPFlood_Dataset():
    TCP_file1 = os.path.join("DoS-UDP_Flood", "DoSUDPFloodTCP.txt")
    UDP_file1 = os.path.join("DoS-UDP_Flood", "DoSUDPFloodUDP.txt")
    label = "DoS-UDP_Flood"

    TCP1 = pd.read_csv(TCP_file1, delimiter='\t')
    UDP1 = pd.read_csv(UDP_file1, delimiter='\t')

    train, validation, test = extract_features(TCP1, UDP1, label)
    
    return train, validation, test

def Balance_Dataset(train, validation, test):
    requeridos_train = 111783
    requeridos_val = 15969
    requeridos_test = 31940
    
    
    train_TCP = train[train['proto']=='TCP'].shape[0]
    train_UDP = train[train['proto']=='UDP'].shape[0]
    total_train = train.shape[0]
    
    porcentaje_train = (requeridos_train*100)/total_train
    portentaje_a_eliminar_train = (100-porcentaje_train)/100

    train_TCP_n = round(train_TCP * portentaje_a_eliminar_train)
    train_UDP_n = round(train_UDP * portentaje_a_eliminar_train)
    
    train = train.drop(train[train['proto'] == 'TCP'].sample(n=train_TCP_n).index)
    train = train.drop(train[train['proto'] == 'UDP'].sample(n=train_UDP_n).index)
    
    
    
    val_TCP = validation[validation['proto']=='TCP'].shape[0]
    val_UDP = validation[validation['proto']=='UDP'].shape[0]
    total_val = validation.shape[0]
    
    porcentaje_val = (requeridos_val*100)/total_val
    portentaje_a_eliminar_val = (100-porcentaje_val)/100

    val_TCP_n = round(val_TCP * portentaje_a_eliminar_val)
    val_UDP_n = round(val_UDP * portentaje_a_eliminar_val)
    
    validation = validation.drop(validation[validation['proto'] == 'TCP'].sample(n=val_TCP_n).index)
    validation = validation.drop(validation[validation['proto'] == 'UDP'].sample(n=val_UDP_n).index)
    
    
    
    # Calcula el número de filas para TCP y UDP en test
    test_TCP = test[test['proto']=='TCP'].shape[0]
    test_UDP = test[test['proto']=='UDP'].shape[0]
    total_test = test.shape[0]
    
    # Calcula el porcentaje de muestras requeridas en test
    porcentaje_test = (requeridos_test * 100) / total_test
    porcentaje_a_eliminar_test = (100 - porcentaje_test) / 100
    
    # Calcula el número de muestras a eliminar para TCP y UDP en test
    test_TCP_n = round(test_TCP * porcentaje_a_eliminar_test)
    test_UDP_n = round(test_UDP * porcentaje_a_eliminar_test)
    
    # Elimina muestras aleatorias de TCP y UDP en test
    test = test.drop(test[test['proto'] == 'TCP'].sample(n=test_TCP_n).index)
    test = test.drop(test[test['proto'] == 'UDP'].sample(n=test_UDP_n).index)
    
    return train, validation, test

if __name__ == "__main__":    
    
    train1, validation1, test1 = Benign_Dataset()
    
        
    train2, validation2, test2 = PortScan_Dataset()
    
    train3, validation3, test3 = OSScan_Dataset()
    
    train4, validation4, test4 = HostDiscovery_Dataset()
    
    train5, validation5, test5 = DosSYNFlood_Dataset()
    
    train6, validation6, test6 = DDosHTTPFlood_Dataset()
    
    train7, validation7, test7 = DDosSYNFlood_Dataset()
    
    train8, validation8, test8 = DosHTTPFlood_Dataset()

    train9, validation9, test9 = DosUDPFlood_Dataset()
    
    train10, validation10, test10 = DDosUDPFlood_Dataset()

    
    
    train1, validation1, test1 = Balance_Dataset(train1, validation1, test1)
    train5, validation5, test5 = Balance_Dataset(train5, validation5, test5)
    train6, validation6, test6 = Balance_Dataset(train6, validation6, test6)
    train7, validation7, test7 = Balance_Dataset(train7, validation7, test7)
    train8, validation8, test8 = Balance_Dataset(train8, validation8, test8)
    train9, validation9, test9 = Balance_Dataset(train9, validation9, test9)
    train10, validation10, test10 = Balance_Dataset(train10, validation10, test10)
    
    train = pd.concat([train1, train2, train3, train4, train5, train6, train7, train8, train9], ignore_index=True)
    validation = pd.concat([validation1, validation2, validation3, validation4, validation5, validation6, validation7, validation8, validation9], ignore_index=True)
    test = pd.concat([test1, test2, test3, test4, test5, test6, test7, test8, test9], ignore_index=True)
    
    tr = pd.read_csv('train.csv')
    val = pd.read_csv('validation.csv')
    te = pd.read_csv('test.csv')
    
    
    
    
    train=tr.drop(columns='Unnamed: 0')
    validation=val.drop(columns = 'Unnamed: 0')
    test=te.drop(columns='Unnamed: 0')
    
    train = pd.concat([train, train10], ignore_index=True)
    validation = pd.concat([validation, validation10], ignore_index=True)
    test = pd.concat([test, test10], ignore_index=True)
    
    train.to_csv('train.csv')
    validation.to_csv('validation.csv')
    test.to_csv('test.csv')
    
    

    
    a=pd.read_csv("BenignTCP.txt", delimiter='\t')
    b=pd.read_csv("DDoSUDPFloodUDP2.txt", delimiter='\t')
    
    num_streams = a['tcp.stream'].nunique()
    num_streams2 = b['udp.stream'].nunique()
    
    



    


    

