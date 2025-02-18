import os
import json
import dpkt
import socket
import pickle
from multiprocessing.pool import ThreadPool
#计算网络数据包的放大倍率（amplification ratio）。它使用dpkt库解析.pcap文件中的网络数据包，并使用多线程进行放大倍率的计算。
#该函数使用UDP协议发送数据包到目标地址和端口，并接收返回的数据。函数计算放大倍率，即返回数据的长度与发送的数据长度之比。
#如果放大倍率大于1，则表示该数据包具有放大效应。
def amplification_ratio(info):
    pkg, addr, port, data = info
    res_len = 0
    _d = bytes()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        d_len = len(data)
        _sent = sock.sendto(data, (addr, port))
        sock.settimeout(10)
        while True:
            r_data, server = sock.recvfrom(10*10000)
            _d += r_data
    except:
        if len(_d)/d_len > 1:
            return (pkg, addr, port, data, _d)


#递归遍历指定目录下的所有.pcap文件
leaks = []
hardcoded_keys = []
all_packets = set()
words_path = []
all_words = []
c = 0
#root 是当前正在遍历的目录路径。 dirnames 是一个包含当前目录下的所有子目录名称的列表。filenames 是一个包含当前目录下的所有文件名称的列表。
for root, dirnames, filenames in os.walk("./"):
    for filename in filenames:
        if filename.endswith(".pcap"):
            conns_files = []
            local_addrs = set()
            if os.path.exists(root+"/conn-1.txt"):
                conns_file_1 = open(os.path.join(root, "conn-1.txt"), "rb")
                conns_files += conns_file_1.readlines()
                conns_file_1.close()
            if os.path.exists(root+"/conn-2.txt"):
                conns_file_2 = open(os.path.join(root, "conn-2.txt"), "rb")
                conns_files += conns_file_2.readlines()
                conns_file_2.close()
            #从每个.pcap文件中提取与特定条件匹配的UDP数据包，这些条件包括源IP地址、源端口和目标端口。接下来，它将匹配的数据包存储在一个集合中。
            for conn in conns_files:
                if (b"'udp'" in conn or b"'udp6'" in conn) and (not (b":53'," in conn or b":1900'," in conn or b":443'," in conn or b":123'," in conn or b":0'," in conn or b"'null" in conn)) and (b"local_address': '10.42.0" in conn or b"local_address': '/10.42.0" in conn or b"local_address': '::ffff:10.42.0" in conn):
                    cj = json.loads(
                        conn.decode().strip().replace("'", '"'))
                    local_addr = cj["java"]["local_address"] if "java" in cj else cj["native"]["local_address"]
                    local_addrs.add(local_addr.replace(
                        "::ffff:", "").replace("/", ""))
            if len(local_addrs) == 0:
                continue
            _pcap = open(root+"/"+filename, "rb")
            
            for _, pkt in dpkt.pcap.Reader(_pcap):
                packet = dpkt.ethernet.Ethernet(pkt)
                if type(packet.data) == dpkt.ip.IP and type(packet.data.data) == dpkt.udp.UDP and len(packet.data.src) == 4:
                    if socket.inet_ntoa(packet.data.src)+":"+str(packet.data.data.sport) in local_addrs and int(packet.data.data.dport) not in (53, 0) and not (packet.data.dst[0] == 255 or packet.data.dst[0] in range(224, 240)):
                        all_packets.add((root, socket.inet_ntoa(packet.data.dst), int(
                            packet.data.data.dport), packet.data.data.data))




amplification_rates = dict()
_ar = list()
#使用多线程池并发地对每个数据包执行amplification_ratio函数
with ThreadPool(100) as p:
    _ar += [data for data in (p.map(amplification_ratio, all_packets)) if data]
with ThreadPool(500) as p:
    for (pkg, addr, port, data, rdata) in [data for data in (p.map(amplification_ratio, all_packets)) if data]+_ar:
        pkg_name = pkg.split("/")[-1]
        rate = len(rdata)/len(data)
        if pkg_name in amplification_rates:
            if rate > amplification_rates[pkg_name]:
                amplification_rates[pkg_name] = rate
        else:
            amplification_rates[pkg_name] = rate
#将每个数据包所属的文件名以及放大倍率保存在一个字典中，并将字典写入名为amplification_ratio.json的JSON文件中。
with open('amplification_ratio.json', 'w') as outfile:
    json.dump(amplification_rates, outfile, indent=4)
