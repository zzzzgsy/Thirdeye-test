# -*- coding: UTF-8 -*-
import device
import functools
import sys
import exceptions
import hooker
import time
import static
import dynamic
import logging
import os
import shutil
import frida
import psutil

# logging.debug(list(substring in "aaass" for substring in ['java/security', 'javax/crypto/spec']))
# 创建根记录器 root 并设置日志级别为调试模式（DEBUG）
root = logging.getLogger() 
root.setLevel(logging.DEBUG)
# 创建一个流处理器 ch，将日志消息输出到标准输出
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
FORMAT = "[%(asctime)s - %(filename)s:%(lineno)s - %(funcName)s() ] %(message)s"# 设置日志消息的格式
formatter = logging.Formatter(FORMAT)
ch.setFormatter(formatter)
root.addHandler(ch) # 将流处理器添加到根记录器中


def main():
    #cdevice = frida.get_usb_device()
    #device = frida.get_device_manager().add_remote_device('192.168.137.169:12345')
    #pid = device.spawn([pkg_name])
    #time.sleep(1) #Without it Java.perform silently fails
    #session = device.attach(pid)

    devices = device.get_active_devices() #获取设备列表
    for d in devices: #遍历设备列表
            #if d.d.serialno == "10.42.0.27:5555": #选择指定序列号的设备
                # continue
        cdevice = d
    
    #with open("packages.txt", "r") as packages: # 打开包名列表文件

    # if i < 20:
    #     continue
    pkg_name = "com.mihoyo.hyperion"
    #logging.debug(pkg_name)
    
    static_analysis = static.Package(pkg_name) # 创建静态分析实例 static_analysis，用于对指定的软件包进行静态分析和处理。
    (p, mitm) = cdevice.start_capture(pkg_name) #启动tcpdump和mitm抓包
    

    h = dynamic.Dynamic(cdevice, pkg_name, static_analysis) #设置动态分析
    h.run() #执行动态分析，启动 Frida 
    analysis_time = int(time.time()) #
    with open("out/"+pkg_name+"/time.txt", "a") as f: #记录分析时间到文件
        f.write("s1+:"+str(analysis_time)+"\n")
    cdevice.run_app(pkg_name) #运行应用
    cdevice.start_interaction(pkg_name, 1, analysis_time) #启动应用交互并记录时间戳
    cdevice.close_app(pkg_name) #关闭应用
    with open("out/"+pkg_name+"/time.txt", "a") as f: #记录分析时间到文件
        f.write("s1-:"+str(int(time.time()))+"\n")
    cdevice.store_files(pkg_name, 1) #存储应用文件
    
    h.stop() #停止动态分析
    cdevice.stop_capture(p, mitm, pkg_name) #停止抓包
    # break
    # package = static.Package(pkg_name)
    # # native_methods = package.get_methods(lambda m: (
    # #     m.get_access_flags() & 0x100) == 0x100)  # 0x100 means native
    # # native_methods = package.get_methods(
    # #     lambda m: (m.get_name() in ("encrypt", "decrypt") or any(substring in m.get_descriptor().decode("utf-8") for substring in ['java/security', 'javax/crypto/spec'])))
    # native_methods = package.get_methods(
    #     lambda m: (m.get_name() in ("encrypt", "decrypt") or m.get_name().decode("utf-8").startswith("hash")))
    # jscode = "Java.perform(function () {"+("".join((m.to_frida(p).decode("utf-8")
    #                                                 for m in native_methods)))+"});"
    # logging.debug(jscode)
    # with open("js/bypass_root_detection.js") as f:
    #     jscode += f.read()
    # # logging.debug(cdevice.is_alive())
    # cdevice.frida.on("spawn-added", functools.partial(hooker.spawn_added,
    #                                                   package=pkg_name, jscode=jscode, frida_device=cdevice.frida, processes=dict()))
    # cdevice.frida.enable_spawn_gating()
    # logging.debug("x")
    # sys.stdin.read()


if __name__ == '__main__':
    main()

# for i in `find . -name "*.pcap" -type f`; do
#    python ../pcap-full.py "$i"
# done
