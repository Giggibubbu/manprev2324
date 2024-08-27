interesting_layers = ["eth", "arp", "icmp", "ip", "tcp", "udp", "mbtcp"]
timestamp_field_name = 'frame.time_epoch'
ipat_field_name = 'inter.packet_arrival_time'
eth_fields = ['eth.dst', 'eth.src', 'eth.type', 'eth.len']
arp_fields = ['arp.hw.type', 'arp.proto.type', 'arp.hw.size', 'arp.proto.size']
icmp_fields = ['icmp.type', 'icmp.code', 'icmp.checksum', 'icmp.checksum.status']
ip_fields = ['ip.version', 'ip.hdr_len', 'ip.dsfield','ip.len', 'ip.id', 'ip.flags', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.checksum.status', 'ip.src', 'ip.dst']
tcp_fields = ['tcp.srcport', 'tcp.dstport', 'tcp.stream', 'tcp.len', 'tcp.seq', 'tcp.nxtseq', 'tcp.ack',
            'tcp.hdr_len', 'tcp.flags', 'tcp.window_size_value', 'tcp.window_size', 'tcp.window_size_scalefactor', 'tcp.checksum',
            'tcp.checksum.status', 'tcp.urgent_pointer']
udp_fields = ['udp.srcport', 'udp.dstport', 'udp.port', 'udp.length', 'udp.checksum', 'udp.checksum_status']
mbtcp_fields = ['mbtcp.trans_id', 'mbtcp.prot_id', 'mbtcp.len', 'mbtcp.unit_id']
interesting_layer_fields = [eth_fields, arp_fields, icmp_fields, ip_fields, tcp_fields, udp_fields, mbtcp_fields]
df_columns = [timestamp_field_name] + eth_fields + arp_fields + icmp_fields + ip_fields + tcp_fields + udp_fields + mbtcp_fields