import subprocess
import time
package = "test"

# subprocess.Popen(
#             [
#                 "mitmdump",
#                 "-w",
#                 "out/"+package+"/mitmdump",
#                 "--anticomp",
#                 "--listen-port",
#                 "8081",
#             ],
#             stdout=subprocess.DEVNULL,
#             stderr=subprocess.DEVNULL,
#             shell=True,
#         )

# process = subprocess.Popen([
#     "adb",
#     "shell",
#     "su",
#     "-c",
#     "\"tcpdump port not 5555 -i wlan0 -w /data/local/tmp/" + package + ".pcap\"",
# ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
subprocess.run('taskkill /F /T /IM mitmdump.exe', shell=True)
# mitm_proc = subprocess.Popen(
#     [
#         "mitmdump",
#         "-w",
#         "out/"+package+"/mitmdump",
#         "--anticomp",
#         "--listen-port",
#         "8081",
#     ],
#     # stdout=subprocess.DEVNULL,
#     # stderr=subprocess.DEVNULL,
# )
# # time.sleep(20) 

#subprocess.run('taskkill /F /T /IM mitmdump.exe', shell=True)
# # process.kill()

# subprocess.Popen(
#     [
#         "pcapfix-1.1.5-win32/pcapfix",
#         "out/" + package + "/"+package + ".pcap",
#         "-o",
#         "out/" + package + "/clean.pcap",
#     ],
#     stdout=subprocess.DEVNULL,
#     stderr=subprocess.DEVNULL,
# ).wait() #修复保存



import psutil
#获取当前运行的所有进程
processes = psutil.process_iter()
#遍历进程列表并输出进程信息
for process in processes:
    if process.name() == "mitmdump.exe":
        print(f"进程ID：{process.pid}，进程名称：{process.name()}")



# import execjs
# # JavaScript代码
# js_code = """
# function getNewString() {
#     var teststring = "http://example.com:8080";
#     return teststring.toString().replace(/^.*\//, '');
# }
# """
# # 使用PyExecJS执行JavaScript代码
# ctx = execjs.compile(js_code)
# result = ctx.eval("getNewString()")
# print(result)

