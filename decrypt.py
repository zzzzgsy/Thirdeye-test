import base64
import json
import sys
import os
from pathlib import Path

if (len(sys.argv)) < 2:
    print("Usage: python decrypt.py package_name")
    exit(0)
pkg_name = sys.argv[1]
# 读取txt文件

outdir = os.path.join("out/", pkg_name)
with open(os.path.join(outdir, 'crypt.txt')) as file:
    lines = file.readlines()

# 处理每一行数据
results = []
for line in lines:
    data = json.loads(line)

    # 只处理包含加密参数的行
    if data.get("method_name") == "doFinal" or data.get("method_name") == "write":
        args = data.get("args", [])
        decrypted_args = []
        
        for arg in args:
            try:
                # 尝试解码Base64编码的字符串
                decoded_arg = base64.b64decode(arg).decode('utf-8')
                decrypted_args.append(decoded_arg)
            except Exception as e:
                # 如果解码失败，直接保留原始值
                decrypted_args.append(arg)
        
        # 如果有解码数据，保存解码后的数据
        result_data = {
            "class_name": data.get("class_name"),
            "hashcode": data.get("hashcode"),
            "method_name": data.get("method_name"),
            "args": decrypted_args,
            "ret": data.get("ret", ""),  # 保留返回值
            "stackTrace": data.get("stackTrace", ""),  # 保留堆栈信息
            "ts": data.get("ts", "")  # 保留时间戳
        }
        results.append(result_data)
    else:
        # 如果不需要解码的行，直接保存原数据
        results.append(data)
        

# 将结果写入文件
#Path(os.path.join(outdir, 'output.txt')).mkdir(parents=True, exist_ok=True)
with open(os.path.join(outdir,'output.txt'), "w", encoding='utf-8') as output_file:
    for result in results:
        output_file.write(json.dumps(result) + '\n')
