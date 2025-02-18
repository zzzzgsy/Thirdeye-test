import hashlib
import sys
import os


#打开一个指定路径的文件（以二进制读取模式），然后逐块读取文件内容（每次读取 8192 字节）
#对每一块数据更新 SHA-1 对象，最后返回整个文件的 SHA-1 哈希值（以十六进制形式）
def calculate_sha1(file_path):
    with open(file_path, 'rb') as file:
        sha1 = hashlib.sha1()
        while chunk := file.read(8192):
            sha1.update(chunk)
    return sha1.hexdigest()

def calculate_md5(file_path):
    with open(file_path, 'rb') as file:
        md5 = hashlib.md5()
        while chunk := file.read(8192):
            md5.update(chunk)
    return md5.hexdigest()

if (len(sys.argv)) < 2:
    print("Usage: python analyze.py package_name")
    exit(0)
pkg_name = sys.argv[1]

folder_path = r"I:\\added_apks"
file_path = os.path.join(folder_path, pkg_name + ".apk")

if os.path.exists(file_path):
    apk_sha1 = calculate_sha1(file_path)
    print(apk_sha1)
else:
    print("APK file not found: {}".format(file_path))

