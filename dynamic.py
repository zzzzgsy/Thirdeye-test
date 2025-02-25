import time
import json
import functools
import logging
import os
import sys
import subprocess
import frida


def fh(method, body):
    params = ""
    for i, (key, _) in enumerate(body.items()):
        if i > 0:
            params += "+'\\\\\", \\\\\"'+"
            # params += "+'\\\\\"], [\\\\\"'+"
        params += "btoa(" + key+")"
#Java.use('android.provider.Settings$Secure').getString(Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver(), 'android_id')
    exec = "var ret = this." + \
        str(method.name)+"("+(", ".join([key for key, value in body.items()]))+");"
    return exec+"send('{\"crypto\":\"{\\\\\"class_name\\\\\":\\\\\""+method.class_name+"\\\\\",\\\\\"method_name\\\\\":\\\\\""+str(method.name)+"\\\\\",\\\\\"args\\\\\":["+("\\\\\"'+"+params+"+'\\\\\"" if params else "")+"],\\\\\"ret\\\\\":\\\\\"'+btoa(ret)+'\\\\\",\\\\\"stackTrace\\\\\":\\\\\"'+btoa(Java.use(\"android.util.Log\").getStackTraceString(Java.use(\"java.lang.Exception\").$new()))+'\\\\\"}\"}');return ret;"
    #console.log('"+method.class_name.decode("utf-8")+":"+method.name.decode("utf-8")+"("+("'+"+params+"+'" if params else "")+")->'+ret);

#Java.use('android.provider.Settings$Secure').getString(Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver(), 'android_id');

#在移动设备上使用 Frida 进行动态分析和操作
class Dynamic:
    def __init__(self, device, package, static):

        self.frida = device.frida
        self.device = device
        self.package = package
        self.sessions = set()
        self.jscode = str()

        def candid_methods(m): 
            #print(dir(m))
            return "java.lang.String" in m or "java.lang.Byte" in m or "byte" == m #m(方法名称)中是否包含这些字符串
        # args , ret = description_mapper(method.get_descriptor())
        # self.params, self.return_type
        #调用 static 对象的 get_methods 方法，传入一个 lambda 表达式作为参数，该 lambda 表达式用于过滤出符合条件的方法。
        #具体条件是方法名中包含 "rooted"，类名中不包含 "path" 和 ".db."，且不属于 Google 或 Kotlin 相关的类，并且返回类型为布尔值。将符合条件的方法存储在 rooted_methods 变量中。

        #过滤出符合条件的方法
        #rooted_methods = static.get_methods( 
            #lambda m: (("rooted" in m.name.lower()) and "path" not in m.class_name and ".db." not in m.class_name and "google" not in m.class_name and "kotlin" not in m.class_name and m.return_type == "boolean"))
            #lambda m: (("rooted" in m.name.lower().decode("utf-8")) and b"path" not in m.class_name.decode("utf-8") and b".db." not in m.class_name.decode("utf-8") and b"google" not in m.class_name.decode("utf-8") and b"kotlin" not in m.class_name.decode("utf-8") and m.return_type.decode("utf-8") == b"boolean"))
        
        rooted_methods = static.get_methods(lambda m: ( ("rooted" in str(m.name.lower())) and "path" not in m.class_name and ".db." not in m.class_name and "google" not in m.class_name and "kotlin" not in m.class_name and m.return_type == "boolean"))
                                                       # and b"path" not in m.class_name.encode("utf-8") and b".db." not in m.class_name.encode("utf-8") and b"google" not in m.class_name.encode("utf-8") and b"kotlin" not in m.class_name.encode("utf-8") and m.return_type.encode("utf-8") == b"boolean"))
  
        self.jscode = "Java.perform(function () {"+(
            "".join((m.to_frida((lambda _m, _b: ""), "return false;") for m in rooted_methods)))+(
            "".join((m.to_frida((lambda _m, _b: "p0 = false;")) for m in static.get_methods(
                #lambda m: (("root" in m.name.lower() and "detect" in m.name.lower()) and ".db." not in m.class_name and "path" not in m.class_name and "google" not in m.class_name and m.return_type == "void" and len(m.params) == 1 and m.params[0] == "boolean")))))+"});"
                lambda m: (("root" in str(m.name.lower()) and "detect" in str(m.name.lower())) and ".db." not in m.class_name and "path" not in m.class_name and "google" not in m.class_name and m.return_type == "void" and len(m.params) == 1 and m.params[0] == "boolean")))))+"});"
                
            #构建了一段 JavaScript 代码，遍历 rooted_methods 和另一个过滤条件，将符合条件的方法转换为 Frida 的 JavaScript 代码，并拼接到 jscode 字符串中。
        # fake_verifiers = static.get_methods(
        #     lambda m: (("verify" == m.name.lower()) and "google" not in m.class_name and "java" not in m.class_name and "kotlin" not in m.class_name and m.return_type == "boolean" and len(m.params) == 2))

        # self.jscode = "Java.perform(function () {"+(
        #     "".join((m.to_frida((lambda _m, _b: ""), "return true;") for m in fake_verifiers)))+"});"

        # self.jscode += "Java.perform(function () {"+(
        #     "".join((m.to_frida((lambda _m,_b: "p0 = false;")) for m in static.get_methods(
        #     lambda m: (("root" in m.name.lower() and "detect" in m.name.lower()) and ".db." not in m.class_name and "path" not in m.class_name and "google" not in m.class_name and m.return_type == "void" and len(m.params) == 1 and m.params[0] == "boolean")))))+"});"
        # crypto_methods = static.get_methods(
        #     lambda m: (((("encrypt" in m.name.lower() or "decrypt" in m.name.lower()) and ("aes" in m.name.lower() or "rsa" in m.name.lower() or "byte" in m.name.lower() and "compress" in m.name.lower() and "string" in m.name.lower())) or ("encrypt" == m.name.lower() or "decrypt" == m.name.lower())) and ".db." not in m.class_name and 1 <= len(m.params) >= 3  and all([candid_methods(param) for param in m.params]) and candid_methods(m.return_type)))

        '''
                rooted_methods = static.get_methods(
                    lambda m: ( ("rooted" in str(m.name.lower())) and m.return_type == "boolean"))
                self.jscode = "Java.perform(function () {"+(
                    "".join((m.to_frida((lambda _m, _b: ""),"return false;") for m in rooted_methods)))+"});"
                
                crypto_methods = static.get_methods(
                    lambda m: (("encrypt" == str(m.name.lower()) or "decrypt" in str(m.name.lower())) 
                                        and 1 <= len(m.params) <= 4 ))
                self.jscode += "Java.perform(function () {"+(
                    "".join((m.to_frida(fh) for m in crypto_methods)))+"});"
        '''

        crypto_methods = static.get_methods(
            lambda m: (("encrypt" == str(m.name.lower()) or "decrypt" in str(m.name.lower()) ) #or "encode" in str(m.name.lower()) or "decode" in str(m.name.lower())   ) 
                       and ".db." not in m.class_name and 1 <= len(m.params) <= 4 
                       and all([candid_methods(param) for param in m.params]) 
                       and candid_methods(m.return_type)))
        self.jscode += "Java.perform(function () {"+(
            "".join((m.to_frida(fh) for m in crypto_methods)))+"});"

        print(self.jscode)
        
        for file in ("general.js", "debug.js", "bypass_root_detection.js",  "native.js", "java.js", "media.js", "fs.js", "sslpinning.js", "built_in_crypto.js", "built_in_encode.js"):
            with open("js/"+file,encoding='utf-8') as f:
                self.jscode += f.read() #打开指定文件并读取文件内容，将文件内容追加到 jscode 字符串中
       
        # for file in ("general.js", "debug.js", "bypass_root_detection.js",  "native.js", "java.js", "media.js", "fs.js", "built_in_crypto.js", "built_in_encode.js"):
        #     with open("js/"+file) as f:
        #         self.jscode += f.read()
        #         #jscode += f.read()
        # for file in ("httptoolkit-config.js", "android-certificate-unpinning.js", "android-certificate-unpinning-fallback.js"):
        #     with open("js/"+file) as f:
        #         self.jscode += f.read()
        #         #jscode += f.read()   
       
       
        # "java.lang.Object" in m or "JSONObject" in m or
        #创建了一个偏函数，绑定到 Frida 对象的特定事件上
        self.spawn = functools.partial(spawn_added, frida_device=self.frida, device=self.device,
                                       package=self.package, jscode=self.jscode, processes=dict(), fs=dict(), sessions=self.sessions)
        self.frida.on("spawn-added", self.spawn)
        self.frida.on("child-added", self.spawn)

    def run(self):
        self.frida.enable_spawn_gating() #启动 Frida 的 spawn gating（生成门限）功能。

    def stop(self): #停止 Frida 的 spawn gating 功能，并且关闭 Frida 的会话。
        # self.frida.close()
        try:
            self.frida.disable_spawn_gating()
            self.frida.off("spawn-added", self.spawn)
            self.frida.off("child-added", self.spawn)
            for session in self.sessions:
                session.detach()
        except:
            pass


def spawn_added(spawn, frida_device, device, package, jscode, processes, fs, sessions):  # identifier pid
    # print("-------->"+spawn.identifier)
    print(spawn.identifier+"::::::"+package)
    if spawn.identifier.startswith(package) or spawn.identifier.startswith("com.android") or spawn.identifier.startswith("com.google.process") or spawn.identifier.startswith("com.google.android") or spawn.identifier in ("com.research.helper", "com.topjohnwu.magisk"):
        logging.debug("Process:"+str(spawn))
        processes[spawn.pid] = spawn.identifier
        if spawn.identifier.startswith(package+":") or spawn.identifier == package:
            try:
                session = frida_device.attach(spawn.pid)
                sessions.add(session)
                script = session.create_script(jscode)
                script.on("message", functools.partial(
                    on_message, processes=processes, fs=fs, package=package))
                script.load()
            except:
                session.detach()
                # pass
                # sys.exit()
        # logging.debug(spawn.pid)
        else:
            pass
            # session.detach()
        try:
            frida_device.resume(spawn.pid)
        except:
            logging.debug("Errrr:"+str(spawn))
            pass
    # else:
    #     for p in frida_device.enumerate_processes():
    #         if p.pid == spawn.pid:
    #             print("killed" + str(spawn.pid) + ":" + spawn.identifier)
    #             frida_device.resume(spawn.pid)
    #             frida_device.kill(spawn.pid)
    #             device.close_app(spawn.identifier)


def on_message(message, data, package, processes, fs):
    #stage = "-2" if os.path.exists("out/"+package+"/2nd.lock") else "-1"
    stage=''
    try:
        # print(message["payload"])
        # print(message)
        conn = json.loads(message["payload"])
        if "crypto" in conn:
            with open("out/"+package+"/crypt"+stage+".txt", "a") as f:
                c = json.loads(conn["crypto"])
                c["ts"] = time.time()
                f.write(json.dumps(c) + '\n')
        elif "key-iv" in conn:
            with open("out/"+package+"/key-iv"+stage+".txt", "a") as f:
                k = json.loads(conn["key-iv"])
                k["ts"] = time.time()
                f.write(json.dumps(k) + '\n')
        elif "deviceid" in conn:
            with open("out/"+package+"/id"+stage+".txt", "w") as f:
                f.write(str(conn["deviceid"]) + '\n')
        elif "fs" in conn:
            with open("out/"+package+"/fs"+stage+".txt", "a") as f:
                conn["fs"]["ts"] = time.time()
                f.write(json.dumps(conn["fs"]) + '\n')
        elif "media" in conn:
            with open("out/"+package+"/media"+stage+".txt", "a") as f:
                c = json.loads(conn["media"])
                ts = time.time()
                c["ts"] = ts
                print("adb exec-out screencap -p > out/" +
                      package+"/media-"+str(ts)+".png")
                pp = subprocess.Popen(
                    ["adb", "exec-out", "screencap", "-p"], stdout=subprocess.PIPE,)
                stdoutdata, stderrdata = pp.communicate()
                with open("out/"+package+"/media"+stage+"-"+str(ts)+".png", "wb") as fm:
                    fm.write(stdoutdata)
                pp.wait()
    #                c["ts"] = time.time()
                f.write(json.dumps(c) + '\n')
        else:
            t = "java" if "java" in conn else "native"
            conn[t]["pid"] = str(conn[t]["pid"])+"-"+processes[conn[t]["pid"]]
            conn[t]["ts"] = time.time()
            with open("out/"+package+"/conn"+stage+".txt", "a") as f:
                f.write(str(conn) + '\n')
    except:
        logging.debug("mm")
        logging.debug(message)
