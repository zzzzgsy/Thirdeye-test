import hashlib
import json
import logging
import math
import os
import subprocess
import sys
import time

import frida
from com.dtmilano.android.adb.adbclient import AdbClient
from com.dtmilano.android.viewclient import ViewClient
#from uiautomator import device

import exceptions
import interactor
import timeout

# adb shell ime list -s -a
# adb shell ime set com.apedroid.hwkeyboardhelperfree/.HWKeyboardHelperIME


def get_active_devices():
    devices = list() #空列表 devices 用于存储获取到的设备。
    for d in AdbClient().getDevices(): #AdbClient().getDevices()获取连接到计算机并可用的Android设备列表
        transport_id = [i for i in d.qualifiers if i.startswith(
            'transport_id:')][0][13:] #从d.qualifiers中获取"transport_id:"开头的字符串、提取出"transport_id:"后的值作为transport_id
        devices.append(Device(AdbClient(serialno=d.serialno), transport_id))
        logging.debug(d.serialno)
    if devices == []:
        raise exceptions.DeviceNotFound
    return devices

class Device:
    def __init__(self, d, transport_id):
            
        self.d = d
        self.transport_id = transport_id
        self.shell = lambda c: self.d.shell(c).strip()
        self.alive = True
        self.info = {}
        self.update_info()
        self.frida = list(d for d in frida.get_device_manager(
        ).enumerate_devices() if d.id in (self.d.serialno, self.info["ro.serialno"]))[0]
        self.close_all_apps()
        #self.vc = ViewClient(*(self.d, self.d.serialno))
        self.display = Display(self)
        self.permissions = self.get_device_permissions()

    def second(self):
        self.frida = list(d for d in frida.get_device_manager().enumerate_devices(
        ) if d.id in (self.d.serialno, self.info["ro.serialno"]))[0]

    def get_device_permissions(self):
        return set(p[11:] for p in self.shell("pm list permissions").splitlines() if p.startswith("permission:"))

    #解析应用程序的 dumpsys package 输出，提取应用程序的权限集合和服务名称
    def get_app_permissions(self, package):
        dumpsys = self.shell("dumpsys package "+package).splitlines() #获取指定应用程序的包信息和状态，包括权限、服务、运行时权限
        l = {"android.permission.SYSTEM_ALERT_WINDOW"}
        a = str()
        f = False

        for i, r in enumerate(dumpsys):#遍历 dumpsys 列表中的每一行
            if r.startswith((" "*6)+"android.service.notification.NotificationListenerService") and dumpsys[i+1].startswith(" "*8) and dumpsys[i+1].endswith("BIND_NOTIFICATION_LISTENER_SERVICE"):
                a += "cmd notification allow_listener {};".format(
                    dumpsys[i+1][8:].split(' ')[1])
                break #检查是否有通知监听器服务，并构建相应的命令以允许应用程序作为通知监听器。
        for i, r in enumerate(dumpsys):
            if r.startswith((" "*6)+"android.accessibilityservice.AccessibilityService") and dumpsys[i+1].startswith(" "*8) and dumpsys[i+1].endswith("BIND_ACCESSIBILITY_SERVICE"):
                a += "settings put secure enabled_accessibility_services {};".format(
                    dumpsys[i+1][8:].split(' ')[1])
                break #检查是否有辅助功能服务，并构建相应的命令
        for i in dumpsys: #查找运行时权限信息，
            if i.startswith((" "*6)+"runtime permissions"):
                f = True
                continue
            if f and i.startswith(" "*8):
                if ' ' in i[8:]:
                    l.add(i[8:].split(': ')[0])
                else:
                    l.add(i[8:])
            else:
                f = False
        # print(l)
        return l, a # l（包含应用程序的权限）和变量 a（包含构建的命令）。
        # for i in self.shell("dumpsys package "+package).splitlines():
        #     if i.startswith((" "*4)+"requested permissions"):
        #         f = True
        #         continue
        #     if f and i.startswith(" "*6):
        #         if ' ' in i[6:]:
        #             l.add(i[6:].split(': ')[0])
        #         else:
        #             l.add(i[6:])
        #     else:
        #         f = False
        # return l

    def grant_app_permissions(self, package, perms=set(), service_name=str(), service=True):
    #package应用程序的包名，perms需要授予的权限集合（默认为空集合），service_name服务名称（默认为空字符串），service是否需要执行服务命令（默认为 True）
        _perms = set() 
        if len(perms) == 0:#perms 参数为空，则调用 get_app_permissions 方法来获取应用程序的权限集合和服务名称
            _perms, _service_name = self.get_app_permissions(package)
        else:
            _perms = perms
            _service_name = service_name
        for perm in _perms: #遍历 _perms 集合中的每个权限
            self.shell("pm grant "+package+" "+perm) #授予应用程序相应的权限
        if _service_name:
            self.shell(_service_name) #不为空则执行命令
        return _perms, _service_name

    def update_info(self):
        serialno = self.shell("getprop ro.serialno")
        if len(serialno) != 0:
            self.info["ro.serialno"] = serialno

    def is_alive(self):
        try:
            with timeout.timeout(seconds=20):
                if self.shell("echo alive") == "alive":
                    self.alive = True
                    return True
                else:
                    self.alive = False
                    return False
        except:
            self.alive = False
            return False

    def close_app(self, package):
        try:
            if self.shell("pm clear "+package) == "Success":
                print("close")
                return True
            else:
                return False
        except:
            return False

    def close_all_apps(self):
        packages = self.get_paused_activites() #获取当前暂停运行的应用程序包名列表
        print(packages)
        if self.get_current_activity() != None: #如果当前正在运行应用程序，则将其包名添加到 packages 列表中。
            packages.add(self.get_current_activity())
        # packages.discard('com.android.launcher3/.lineage.LineageLauncher')
        ##从 packages 列表中移除不需要关闭的应用程序包名。
        packages.discard(
            'com.google.android.apps.nexuslauncher/.NexusLauncherActivity')
        packages.discard('com.google.android.apps.nexuslauncher/com.android.launcher3.settings.SettingsActivity')
        # packages.add('org.lineageos.jelly')
        # packages.add('com.android.chrome')
        print(packages)
        for package in packages: #遍历 packages 列表中的每个应用程序包名
            p = package.split("/")[0]
            if p == "com.google.android.apps.nexuslauncher":
                self.shell("am force-stop "+p) #如果应用程序是系统启动器，则使用 shell 方法强制停止该应用程序；
            elif self.shell("pm clear "+p) != "Success": #否则，使用 shell 方法清除该应用程序的数据。
                return False
        return True

    def close_paused_apps(self):
        for package in self.get_paused_activites():
            p = package.split("/")[0]
            if p == "com.google.android.apps.nexuslauncher":
                self.shell("am force-stop "+p)
            elif self.shell("pm clear "+p) != "Success":
                return False
        return True

    def uninstall_3rd_party_apps(self):
        self.shell("su -c killall tcpdump") #终止tcpdump,确保在删除应用前终止
        #列出所有第三方应用程序的包名（不包括指定的例外应用程序）。 
        packages = self.shell('pm list packages -3 | cut -c9- | grep -Ev "(com.apedroid.hwkeyboardhelperfree|com.github.shadowsocks|com.research.helper|org.proxydroid|com.fakemygps.android|org.meowcat.edxposed.manager|edu.berkeley.icsi.haystack|com.topjohnwu.magisk|app.greyshirts.sslcapture|tw.fatminmin.xposed.minminguard|com.cofface.ivader)"')
        #列出所有第三方应用程序的包名|每行文本删除前8个字符（因为第三方应用程序的包名通常以 "package:"开头）|grep 工具进行筛选，排除特定的应用程序包名
        for package in packages.splitlines():
            self.uninstall_app(package) #遍历 packages 列表中的每个应用程序包名删除

    def is_internet_available(self):
        # if "success" in self.shell(
        # "echo \"GET /success.txt\" | nc detectportal.firefox.com 80"):
        # if "success" in self.shell("curl --connect-timeout 2 detectportal.firefox.com/success.txt"):
        #if "ttl=" in self.shell("ping -c 1 1.1.1.1"):
        if "ttl=" in self.shell("ping -c 1 180.76.76.76"):
            return True
        return False

    def wait_if_internet_isnt_available(self):
        while self.is_internet_available() == False:
            logging.warning('Internet is not available, please wait')
            time.sleep(2)

    def is_app_crashed(self, app):
        #使用dumpsys命令获取当前正在运行的Activity信息,使用grep命令过滤出包含"Application Error"和指定应用程序名称的Activity信息
        current_focus = self.shell(
            "dumpsys activity activities | grep -E \"mCurrentFocus.+Application Error:.+"+app+"\"").split()
        if len(current_focus) > 0:
            return True
        else:
            return False

    def is_app_hangs(self, app):
        current_focus = self.shell(
            "dumpsys activity activities | grep -E \"mCurrentFocus.+Application Not Responding:.+"+app+"\"").split()
        if len(current_focus) > 0:
            return True
        else:
            return False

    def get_current_activity(self):
        # time.sleep(0.5)
        m_resumed_activity = self.shell(
            "dumpsys activity activities | grep mResumedActivity").split()
        print("00s00")
        print(m_resumed_activity)
        print("00s01")
        i = 0
        if len(m_resumed_activity) > 0:
            print("00s01-1")
            if m_resumed_activity in (["Can't", 'find', 'service:', 'activity']) or m_resumed_activity[0] == "Can't":
                print("00s01-2")
                os.system('kill -9 {pid}'.format(pid=os.getpid()))

        while m_resumed_activity in ([], ['mHoldScreenWindow=null']):
            if i > 8:
                return None
                break
            i += 1
            print(m_resumed_activity)
            print("00s11")
            # self.shell('input keyevent KEYCODE_POWER')
            self.shell('input keyevent KEYCODE_HOME')
            time.sleep(3)
            self.d.wake()
            m_resumed_activity = self.shell(
                "dumpsys activity activities | grep mResumedActivity").split()
            if m_resumed_activity == []:
                m_resumed_activity = self.shell(
                    "dumpsys window windows | grep mHoldScreenWindow").split()
            if m_resumed_activity in ([], ['mHoldScreenWindow=null']):
                m_resumed_activity = self.shell(
                    "dumpsys window windows | grep mActivityRecord | grep -v com.android.launcher3").split()
                print(m_resumed_activity)
            if len(m_resumed_activity) > 0:
                if m_resumed_activity in (["Can't", 'find', 'service:', 'activity']) or m_resumed_activity[0] == "Can't":
                    os.system('kill -9 {pid}'.format(pid=os.getpid()))
            # logging.debug("m_resumed_activity")
            # logging.debug(m_resumed_activity)

        # while m_resumed_activity == []:
        #     logging.debug(m_resumed_activity)
        #     time.sleep(0.5)
        #     m_resumed_activity = self.shell(
        #         "dumpsys activity activities | grep mResumedActivity").split()
        # logging.debug(m_resumed_activity)
        print(len(m_resumed_activity))
        if len(m_resumed_activity) > 2 and m_resumed_activity[0].startswith("mActivityRecord"):
            print(m_resumed_activity[2])
            return m_resumed_activity[2]
        if len(m_resumed_activity) > 4:
            print(m_resumed_activity[3])
            return m_resumed_activity[3]

    def get_paused_activites(self): #获取当前暂停运行的应用程序包名列表
        return set(line.split()[3] for line in self.shell("dumpsys activity activities | grep mLastPausedActivity").splitlines())
        #执行 dumpsys activity activities命令，获取当前所有运行的应用程序的相关信息，使用 grep 命令过滤出所有包含 "mLastPausedActivity" 字符串的行
        #遍历每个字符串，提取出第四列（即应用程序的包名）作为结果列表中的一个元素。
        #将结果列表转换为集合，去除重复项并返回结果

    def get_package_window_hash(self, pkg):
        packages = self.get_paused_activites()
        if self.get_current_activity() != None:
            packages.add(self.get_current_activity())
        for package in packages:
            if package.startswith(pkg):
                return hashlib.sha256(self.shell("dumpsys window | grep "+pkg).encode("utf-8")).hexdigest()

    def pull(self, src, dst="./"):
        # logging.debug(src)
        final_path = dst+"/"+src.split("/").pop()
        try:
            apk_device_hash = self.shell("sha256sum"+" "+src).split()[0]
            logging.debug(apk_device_hash)
            logging.debug(src)
            logging.debug(dst)
            logging.debug(final_path)
        except:
            return False

        if os.path.exists(final_path):
            with open(final_path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == apk_device_hash:
                    return True
        p = subprocess.Popen(
            ["adb", "-t", self.transport_id, "pull", src, dst],)
#                             stdout=subprocess.PIPE,)
        p.wait()
        with open(final_path, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != apk_device_hash:
                return False
            return True

    def push(self, src, dst):
        # src_name = src.split("/").pop()
        with open(src, "rb") as f:
            fhash = hashlib.sha256(f.read()).hexdigest()
        p = subprocess.Popen(
            ["adb", "-t", self.transport_id, "push", src, dst],)
#                             stdout=subprocess.PIPE,)
        p.wait()
        try:
            apk_device_hash = self.shell(
                "sha256sum"+" "+dst+src.split("/").pop()).split()[0]
        except:
            return False
        if fhash != apk_device_hash:
            return False
        return True

    def start_capture(self, package):
        self.shell("rm -f /sdcard/*")
        self.shell("rm -f /data/local/tmp/*.pcap")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return (subprocess.Popen(
            [
                "adb",
                "shell",
                "su",
                "-c",
                "\"tcpdump port not 5555 -i wlan0 -w /data/local/tmp/" + package + ".pcap\"",
            ], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL, 
            shell=True
            ),subprocess.Popen(
            [
                "mitmdump",
                "-w",
                "out/"+package+"/mitmdump",
                "--anticomp",
                "--listen-port",
                "8081",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True,
        ))

    def file_readable(self, path):
        if (self.shell("if [ -r \""+path+"\" ] && [ -f \""+path+"\" ]; then echo True;fi") == "True"):
            return True
        else:
            return False

    def store_files(self, package, stage): #存储文件到指定目录。
        outpath = "out/"+package+"/"
        filelines = []
        for f in os.listdir(outpath):
            if f.startswith('fs-') and f.endswith('.txt'):
                with open(outpath+f, 'r') as _f:
                    filelines += _f.readlines()
        recordes = [json.loads(i) for i in filelines if json.loads(i)[
            "function"] in ("open", "rename")]
        paths = ((i["path"] if i[
            "function"] == "open" else i["destination"]) for i in recordes)

        for p in paths:

            if self.file_readable(p):
                os.makedirs(outpath+"/files-"+str(stage) + "/" +
                            os.path.dirname(p), exist_ok=True)
                self.pull(p, outpath+"/files-"+str(stage) +
                          "/"+os.path.dirname(p)+"/")

    def stop_capture(self, p, mitm, package):
        p.terminate()
        p.kill()
        mitm.terminate()
        mitm.kill()
        # parents_of_dead_kids=$(ps -ef | grep [d]efunct  | awk '{print $3}' | sort | uniq | egrep -v '^1$'); echo "$parents_of_dead_kids" | xargs kill
        self.shell("su -c killall tcpdump") #终止进程
        # logging.debug("x")
        self.pull("/data/local/tmp/" + package+".pcap", "out/"+package) #pull下载拉取
        #self.pull("/data/local/tmp/" +"test.pcap", "out/"+package) #pull下载拉取
        subprocess.Popen(
            [
                "pcapfix-1.1.5-win32/pcapfix",
                "out/" + package + "/"+package + ".pcap",
                "-o",
                "out/" + package + "/clean.pcap",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).wait() #修复保存
        # tmp
        #os.system(
            #"echo $(ps -ef | grep [d]efunct | awk '{print $3}' | sort | uniq | grep mitmdump| egrep -v '^1$') | xargs kill -9")
        #获取到所有与 mitmdump 相关的僵尸进程的父进程 ID，然后使用 kill -9 命令将这些进程强制终止。
        subprocess.run('taskkill /F /T /IM mitmdump.exe', shell=True)
    def install_app(self, package, output="out/", reinstall=True):  # multiple try
        if os.path.exists(output + package+"/"+package + ".pcap") or os.path.exists("out/" + package + ".fail"):
            return False #检查是否已存在指定的输出目录和文件
        self.shell("su -c 'pm disable com.android.chrome;pm disable com.google.android.youtube;pm disable com.google.android.calendar;pm disable com.google.android.apps.docs;pm disable com.google.android.apps.customization.pixel;pm disable com.google.android.gm;pm disable com.google.android.apps.tycho;pm disable com.google.android.calculator;pm disable com.google.android.markup;pm disable com.android.safetyregulatoryinfo;pm disable com.google.android.apps.wallpaper.pixel;pm disable com.google.android.videos;pm disable com.google.android.apps.youtube.music;pm disable com.google.pixel.dynamicwallpapers;pm disable com.google.ar.core;pm disable com.google.android.projection.gearhead;pm disable com.google.android.apps.tips;pm disable com.google.android.googlequicksearchbox;pm disable com.google.android.apps.safetyhub'")
        #禁用一些预定义的应用程序
        if self.is_app_exist(package) and reinstall:
            self.uninstall_app(package) #已经存在则先卸载
        elif self.is_app_exist(package) and reinstall == False:
            self.shell("su -c pm disable {package};".format(package=package))
            return True #禁用
        self.shell(
            "content insert --uri content://settings/system --bind name:s:accelerometer_rotation --bind value:i:0")#禁用加速度计自动旋转
        if os.path.exists(output + package + "/base.apk"):  # debug如果存在指定的应用程序的基础 APK 文件，则进入调试模式。
            #将 APK 文件列表和 OBB 文件列表提取出来
            apks = list(output + package + "/"+f for f in os.listdir(
                output + package) if f.endswith('.apk'))
            obbs = list(output + package + "/"+f for f in os.listdir(
                output + package) if f.endswith('.obb'))
            if apks: #如果存在 APK 文件
                #使用 subprocess.Popen 执行 adb install-multiple 命令来安装多个 APK 文件。
                p = subprocess.Popen(
                    ["adb", "-t", self.transport_id,"install-multiple" , "-g"]+apks, stdout=subprocess.PIPE,)
                p.wait()
                try:
                    if "Success" in str(p.communicate()[0]):
                        if obbs:
                            self.shell("mkdir -p /sdcard/obb/"+package)
                            print(obbs)
                            if all([self.push(obb, "/sdcard/obb/"+package+"/") for obb in obbs]):
                                self.shell("mv /sdcard/obb/{} /sdcard/Android/obb/".format(package))
                                self.shell(
                                    "su -c pm disable {package};".format(package=package))
                                return True
                            else:
                                return False
                        self.shell(
                            "su -c pm disable {package};".format(package=package))
                        return True
                except:
                    return False
        else:
            if os.path.exists(output + package + ".fail"):
                return False
            gp = interactor.GooglePlay(self) #从 Google Play 下载并安装应用程序
            for _ in range(0, 2):
                gpi = gp.install(package)
                if gpi == None or gpi == False:
                    with open(output + package + ".fail", 'w') as fp:
                        pass
                    return False
                elif gpi == True:
                    self.shell(
                        "su -c pm disable {package};".format(package=package))
                    return True
            pass
        pass

    def uninstall_app(self, package):
        self.shell(
            'for file in $(find /sdcard/ -maxdepth 1 ); do if [ $file != "/sdcard/DCIM" ] && [ $file != "/sdcard/" ]; then rm -rf "$file" ;fi;done;rm -rf /sdcard/*\ *')
            #循环遍历 /sdcard/ 目录下的所有文件和文件夹，如果当前文件或文件夹不是 /sdcard/DCIM 和 /sdcard/。则删除
        if self.is_app_exist(package) and self.shell("pm uninstall {package}".format(package=package)) == "Success":
            return True #如果应用程序包名存在 并且执行 pm uninstall 命令卸载该应用程序成功
        return False

    def is_app_open(self, package): #检查指定包名的应用程序是否处于打开状态
        try:
            current_activity = self.get_current_activity() #获取当前的活动页面
            print(current_activity)
            if self.get_current_activity() and (current_activity.startswith(package) or current_activity.startswith("com.google.android.gms/.common") or current_activity in ["com.google.android.gms/.signin.activity.ConsentActivity", "com.google.android.gms/.auth.uiflows.consent.BrowserConsentActivity", "com.google.android.gms/.auth.uiflows.addaccount.AccountIntroActivity", "com.android.permissioncontroller/.permission.ui.ReviewPermissionsActivity"]):
                return True #检查当前活动页面是否存在，并且判断当前活动页面是否以指定的包名开头，或者是否是一些特定的 Google 服务相关的活动页面。
            return False
        except:
            return False

    def run_app(self, package, close=True):
        if close:
            self.close_all_apps() #关闭所有应用程序。
        self.shell(
            "su -c pm enable {package};monkey -p {package} --pct-touch 100 1".format(package=package))
            #启用指定包名的应用程序      模拟触摸事件来运行应用程序。
        # print("----------")
        time.sleep(1) #等待应用程序打开。
        if not self.is_app_open(package): #判断是否打开
            return True
        else:
            return False

    def is_app_exist(self, package):
        for exsited_package in self.shell("cmd package list packages "+package).splitlines():
            if exsited_package.split(":", 1)[1] == package:
                return True
        return False

    def store_app(self, package, output="out/"):
        if os.path.exists(output + package+"/base.apk"):
            return
        if not os.path.exists(output + package):
            os.makedirs(output + package)
        obbs = list(map(lambda x: "/sdcard/Android/obb/"+package+"/"+x,
                    self.shell("ls -1 /sdcard/Android/obb/"+package+"/").split("\n")))
        if "No such" in obbs[0]:
            obbs.clear()
        apks = list(map(lambda x: x[8:], self.shell(
            "pm path "+package).split("\n")))
        for i in obbs+apks:
            while True:
                try:
                    with timeout.timeout(seconds=120):
                        logging.debug("t2")
                        print(i, output + package)
                        if self.pull(i, output + package) == True:
                            break
                except:
                    subprocess.Popen(["killall", "adb"],
                                     stdout=subprocess.PIPE,).wait()
                    subprocess.Popen(
                        ["rm", "-rf", output + package], stdout=subprocess.PIPE,).wait()
                    # sys.exit()
                    os.system('kill -9 {pid}'.format(pid=os.getpid()))

    def start_interaction(self, package, stage, analysis_time):
        # try:
        if not self.is_app_open(package):
            self.run_app(package)
        interaction = interactor.App(self, package, stage, analysis_time)
        interaction.smart() #自动化测试
        print("return1")
        # except:
        #     with open("out/"+package+"/animat.txt", "a") as f:
        #         f.write(str(stage)+"-"+str(int(time.time()))+"\n")
        #     return False
        #     # The views are being refreshed too frequently to dump.
        #     logging.debug("xx")


class Display:
    def __init__(self, device):
        self.density = int(device.shell("wm density").split(" ")[-1])
        (x, y) = device.shell("wm size").split(" ")[-1].split("x")
        self.x = int(x)
        self.y = int(y)
        self.statusbar = math.ceil(self.density/160)*24


# adb shell content query --uri content://com.android.contacts/data --projection display_name:data1:data4:contact_id
# adb shell "su -c 'sqlite3 /data/data/com.android.providers.contacts/databases/calllog.db \"select * from calls\"'"
