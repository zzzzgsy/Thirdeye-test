import json
import os
from pprint import pprint

pkg_name = "com.wteamweb.jjkj.shooting"
outdir = os.path.join("out/", pkg_name)
#读取指定目录下的加密文件crypt.txt，将其内容解析成JSON格式，并输出相关信息。
crypt_list = []
with open(os.path.join(outdir, 'crypt.txt')) as f:
    for line in f:
        crypt_list.append(json.loads(line))

print(len(crypt_list))
#if len(crypt_list) > 0:
    #print(type(crypt_list[0]))
    #pprint(crypt_list[:5])



import base64
#将加密算法调用按照参数和返回值的相关性进行聚类，并输出每个聚类组中的加密算法调用数量大于1的组。
# 判断bytes是否为有一定长度的base64
def isBase64(s:bytes)->bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s and len(base64.b64decode(s)) > 16
    except Exception:
        return False

def CryptInfoFilter(crypt_info):
    method_black_list = ["percentdecode", "urlencode", "encodedquery"]
    if crypt_info['method_name'].lower() in method_black_list:
        return False
    class_method_black_list = [("javax.crypto.Cipher", "init-key"), ("javax.crypto.spec.SecretKeySpec", "$new")]
    # class_method_black_list.append(("javax.crypto.Cipher", "update"))
    if (crypt_info['class_name'], crypt_info['method_name']) in class_method_black_list:
        return False
    return True
crypt_list = list(filter(CryptInfoFilter, crypt_list))

# 根据参数和返回值，将相关的加密算法调用进行聚类
crypt_groups = []
while len(crypt_list) > 0:
    related_str = set() # 在加密算法的参数和返回值中出现过的字符串
    group = []  # 一组相关的加密算法调用
    crypt_info = crypt_list.pop(0)  # 先取出一个加密算法调用
    group.append(crypt_info)
    # 将字符串类型的参数和返回值加入related_str中
    for arg in crypt_info['args']:
        if isinstance(arg, str) and isBase64(arg.encode('utf-8')):
            related_str.add(arg)
    if isinstance(crypt_info['ret'], str) and isBase64(crypt_info['ret'].encode('utf-8')):
        related_str.add(crypt_info['ret'])
    group_updated = True    # 记录在本次循环中group是否更新，如果更新就再循环一次
    while group_updated:
        group_updated = False
        i = 0
        while i < len(crypt_list):
            crypt_info = crypt_list[i]
            related_flag = False    # 表示当前元素是否相关
            for arg in crypt_info['args']:
                if isinstance(arg, str) and isBase64(arg.encode('utf-8')) and arg in related_str:
                    related_flag = True
                    break
            if isinstance(crypt_info['ret'], str) and isBase64(crypt_info['ret'].encode('utf-8')) and crypt_info['ret'] in related_str:
                related_flag = True
            if not related_flag:    # 不相关，继续看下一个元素
                i += 1
                continue
            # 相关，将其从crypt_list中取出，加入group，并更新related_str
            crypt_info = crypt_list.pop(i)
            group.append(crypt_info)
            group_updated = True
            for arg in crypt_info['args']:
                if isinstance(arg, str) and isBase64(arg.encode('utf-8')):
                    related_str.add(arg)
            if isinstance(crypt_info['ret'], str) and isBase64(crypt_info['ret'].encode('utf-8')):
                related_str.add(crypt_info['ret'])
    # group构建结束
    crypt_groups.append(group)
print("Group Number:", len(crypt_groups))
#pprint([x for x in crypt_groups if len(x) > 1])



# 分析网络流量数据
#with open(os.path.join(outdir, 'Full.txt'), "rb") as f:
with open(os.path.join(outdir, 'mitmdump'), "rb") as f:
    full_data = f.read()
#http_traffic_data = full_data.split(b'------------------------------------------------------------------')
http_traffic_data = full_data.split(b'-----BEGIN CERTIFICATE-----')
print(len(http_traffic_data))


from urllib.parse import urlparse
#搜索网络流量数据
# 检查data数据是否在traffic中
def IsDataInTraffic(data_bytes: bytes, traffic: bytes) -> bool:
    # 数据不在URL中，并且在流量数据中，或其各种编码结果在traffic中
    result = data_bytes in traffic
    result = result or data_bytes.replace(b'/', b'\\/') in traffic
    result = result or base64.b64encode(data_bytes) in traffic
    if isBase64(data_bytes):
        result = result or base64.b64decode(data_bytes) in traffic
    result = result or data_bytes.hex().encode('utf-8') in traffic
    for sep in [',', ' ', '-']:
        result = result or data_bytes.hex(sep).encode('utf-8') in traffic
    result = result and data_bytes not in GetTrafficURL(traffic)
    return result

# 在http_traffic_data中搜索data，返回包含这段data的http流量集合
# data是base64格式字符串
def SearchData(data: str, http_traffic_data: list) -> set:
    if not isBase64(data.encode('utf-8')):
        return set()
    matched_traffic = set()
    data_bytes = base64.b64decode(data)
    for traffic in http_traffic_data:
        # 如果发现数据在traffic中，则将traffic加入集合
        if IsDataInTraffic(data_bytes, traffic):
            matched_traffic.add(traffic)
    return matched_traffic

def GetTrafficURL(traffic: bytes) -> bytes:
    try:
        return traffic.split()[1].split(b'?')[0]
    except:
        return b''

# 在分组中搜索网络流量数据，搜索结果存放在列表group_infos中
# group_infos元素结构为：{"url": [], "traffic": [], "group": []}
group_infos = []
for group in crypt_groups:
    traffic_set = set()
    for crypt_info in group:
        for arg in crypt_info['args']:
            if isinstance(arg, str):
                traffic_set.update(SearchData(arg, http_traffic_data))#在网络流量数据中搜索加解密参数
        if isinstance(crypt_info['ret'], str):
            traffic_set.update(SearchData(crypt_info['ret'], http_traffic_data))
    if len(traffic_set) > 0:
        group_info = dict()
        group_info['traffic'] = list(traffic_set)
        group_info['group'] = sorted(group, key=lambda x: x['ts'])  # group中的调用信息按照时间排序
        url = set()
        for traffic in traffic_set:
            url.add(urlparse(traffic.split()[1]).netloc.decode('utf-8'))
        group_info['url'] = list(url)
        group_infos.append(group_info)
#print(len(group_infos))
# pprint(group_infos)
        


from pathlib import Path
#将函数调用信息和网络流量数据保存到文件
# 新建traffic文件夹，用于存储分析结果
traffic_dir = os.path.join(outdir, 'traffic')
Path(traffic_dir).mkdir(parents=True, exist_ok=True)

# 检查字符串是否为JSON格式
def is_json(s):
    try:
        json.loads(s)
    except ValueError as e:
        return False
    return True

# 传入base64格式数据，尝试转换成可打印字符串
def Base64toPrintableStr(s: str) -> str:
    if not isBase64(s.encode('utf-8')):
        return ""
    try:
        result = base64.b64decode(s).decode('utf-8')
        if is_json(result):
            result = json.dumps(json.loads(result), indent='\t')
        return result
    except (UnicodeDecodeError, AttributeError):
        return ""

from datetime import datetime
import textwrap
# 将函数调用信息转换为可打印字符串形式
def crypt_info2str(crypt_info: dict) -> str:
    result = "Time: " + str(datetime.fromtimestamp(crypt_info['ts'])) + "\n"
    result += "Class: " + crypt_info['class_name'] + "\n"
    result += "Method: " + crypt_info['method_name'] + "\n"
    result += "Args:\n"
    for arg in crypt_info['args']:
        printable_str = Base64toPrintableStr(str(arg))
        if printable_str:
            add_str = "*****\n" + printable_str + "\n*****\n"
            result += textwrap.indent(add_str, "\t")
        else:
            result += textwrap.indent(str(arg), "\t") + "\n"
    result += "Ret:\n"
    printable_str = Base64toPrintableStr(str(crypt_info['ret']))
    if printable_str:
        add_str = "*****\n" + printable_str + "\n*****\n"
        result += textwrap.indent(add_str, "\t")
    elif not str(crypt_info['ret']):
        result += textwrap.indent("null", "\t") + "\n"
    else:
        result += textwrap.indent(str(crypt_info['ret']), "\t") + "\n"
    result += "StackTrace:\n"
    if 'stackTrace' in crypt_info:
        result += textwrap.indent(base64.b64decode(crypt_info['stackTrace']).decode('utf-8'), "\t") + "\n"
    else:
        result += textwrap.indent("null", "\t") + "\n"
    return result

import string
import random

for group_info in group_infos:
    # 在文件名后面加一段随机数字，防止重名
    filename = str(group_info['group'][0]['ts']) + \
        ''.join(random.choice(string.digits) for _ in range(6))

    crypt_info_pretty_print = ""
    for crypt_info in group_info['group']:
        crypt_info_pretty_print += crypt_info2str(crypt_info) + "-" * 66 + "\n"

    traffic_pretty_print = b"+" * 66 + b"\r\n"
    for traffic in group_info['traffic']:
        traffic_pretty_print += traffic.lstrip() + b'+' * 66 + b"\r\n"

    for url in group_info['url']:
        # 将结果保存在url文件夹中
        Path(os.path.join(traffic_dir, url.replace(':', '.'))).mkdir(parents=True, exist_ok=True)
        with open(os.path.join(traffic_dir, url.replace(':', '.'), filename), "w") as f:
            f.write(crypt_info_pretty_print)
        with open(os.path.join(traffic_dir, url.replace(':', '.'), filename), "ab") as f:
            f.write(traffic_pretty_print)




