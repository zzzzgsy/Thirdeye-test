import datetime
import hashlib
import itertools
import json
import logging
import os
import random
import sqlite3
import sys
import time
from functools import partial

import translators

import timeout

# pm list packages -3 | cut -d':' -f2 | tr '\r' ' ' | grep -v com.github.shadowsocks
# 1- adb reboot recovery
# 2- twrp wipe system ; twrp wipe dalvik ; twrp wipe data ; twrp wipe cache ; rm -rf /sdcard/*
# 3- adb push TWRP /sdcard/
# 4- twrp restore clean
# 5- rm -rf /sdcard/TWRP
# adb shell dumpsys window | grep com.android.vending
# adb shell dumpsys activity activities | grep mResumedActivity

# pm list packages -3 | cut -c9- | grep -Ev "(com.github.shadowsocks|org.proxydroid|com.fakemygps.android|org.meowcat.edxposed.manager|edu.berkeley.icsi.haystack|com.topjohnwu.magisk|app.greyshirts.sslcapture|tw.fatminmin.xposed.minminguard|com.cofface.ivader)" | xargs pm uninstall


def dictionary(text):
    en = text
    if len(text) > 2:
        con = sqlite3.connect('dict.db')
        cur = con.cursor()
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS words (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, original text, en text)''')
        cur.execute("select en from words where original = ?", (text,))
        row = cur.fetchone()

        if row == None:
            i = 0
            while i < 10:
                # print("zzz")
                # print(i)
                try:
                    with timeout.timeout(seconds=10):
                        en = translators.google(text)
                    break
                except:
                    i += 1
                    time.sleep(2)
                    continue
            logging.debug("dict")
            cur.execute("insert into words values (?,?,?)",
                        (None, text, en))
            con.commit()
        else:
            en = row[0]
        con.close()
    return en

#查找可点击、启用状态以及指定属性值满足条件的视图对象。
def find_clickable_enable(view, text="", click=False, translate=True, exclude=["None"], obj_class=["android.widget.checkedtextview", "android.view.view", "android.widget.button", "android.widget.textview","android.widget.LinearLayout"], attr="text"):
    #判断当前视图对象是否满足可点击、启用状态和指定类名的要求
    #如果满足条件，则根据指定的属性类型获取视图对象的属性值，并进行相应的处理。如果属性类型是 "text"，则将属性值转换为小写并进行翻译（如果需要）。
    #如果属性类型是 "id"，则获取视图对象的 ID 并将其转换为小写。如果属性类型是 "cd" 或者 "content-desc"，则获取视图对象的内容描述属性值并将其转换为小写。
    #然后，将目标属性值和要匹配的属性值都转换为小写，并根据一系列条件判断是否满足匹配要求。如果满足条件，则根据 click 参数决定是否执行点击操作，并返回 True。
    if (view.isClickable() or view.__getattr__('isEnabled')() or view.__getattr__('checkable')()) and view.getClass().lower() in obj_class:
        if attr.lower() == "text":
            # obj_text = (view.getText()).lower()
            obj_text = dictionary(view.getText()).lower(
            ) if translate else view.getText().lower()
        elif attr.lower() == "id":
            obj_text = view.getId().lower()
            if "/" in obj_text:
                obj_text = obj_text.split("/")[1]
        elif attr.lower() in ("cd","content-desc"):
            # obj_text = (view.getContentDescription()).lower()
            obj_text = dictionary(view.getContentDescription()).lower(
            ) if translate else view.getContentDescription().lower()
        else:
            return None
        text = text.lower()
        if (text == obj_text and exclude == ['None']) or (text in obj_text and len(obj_text) < 64 and (not any(substring in obj_text for substring in exclude) and exclude != ['None'])):
            if click:
                logging.debug("::"+text)
                view.touch()
            return True


def window_hash(root): #生成给定应用程序界面的哈希值
    #将所有可用控件的ID按照字典序排序后，使用SHA-256算法生成哈希值。
    id_list = [v.getId()
               for v in finder(root, lambda v: True if v.getId() else False)]
    id_list.sort()
    return hashlib.sha256(json.dumps(id_list).encode('utf-8')).hexdigest() #这个哈希值可以用于标识应用程序界面的唯一性，


def problem(view):
    if view.getText().startswith("Can't download"):
        # "You're offline"
        return True

#遍历界面中的节点，并将满足条件的节点添加到一个列表中。
def finder(root, transform=str, nlist=None, count=[-1], window_hash="", memory=None):
    if memory is None:
        memory = dict()
    if nlist is None:
        nlist = []
    if not root or count[0] == 0 or (memory.get(window_hash) != None and (root.getUniqueId()+root.getId()+str(root.isClickable())+str(root.__getattr__('isEnabled')())) in memory.get(window_hash)):
        return
    if transform(root) and (window_hash == "" or memory.get(window_hash) == None or (root.getUniqueId()+root.getId()+str(root.isClickable())+str(root.__getattr__('isEnabled')())) not in memory.get(window_hash)):
        if count[0] != -1:
            count[0] -= 1
        nlist.append(root)
        if window_hash != "":
            if window_hash in memory:
                memory.get(window_hash).add(root.getUniqueId(
                )+root.getId()+str(root.isClickable())+str(root.__getattr__('isEnabled')()))
                # memory.update(
                #     {window_hash: {root.getUniqueId()+root.getId()}})
            else:
                memory.update(
                    {window_hash: {root.getUniqueId()+root.getId()+str(root.isClickable())+str(root.__getattr__('isEnabled')())}})

    for ch in root.children:
        finder(ch, transform=transform, nlist=nlist, count=count,
               window_hash=window_hash, memory=memory)
    return nlist

#从特定设备上获取应用程序界面的根节点
def get_root(device, window=-1, sleep=0.5):
    #通过设备的 vc.dump 方法来获取界面上的所有节点，然后遍历这些节点，找到没有父节点的节点（即根节点），并将其返回。
    for chanse in range(0, 10):
        try:
            for n in device.vc.dump(window=window, sleep=sleep):
                if n.getParent() == None:
                    return n
        except Exception as e: #异常处理
            if chanse < 3:
                time.sleep(2)
                continue
            raise e


class GooglePlay():
    def __init__(self, device):
        self.device = device

    def install(self, package):
        self.device.close_app("com.android.vending")
        self.device.wait_if_internet_isnt_available()
        self.open_package_page(package)
        # time.sleep(3)
        name = self.get_package_name()
        root = get_root(self.device)
        if None in (self.is_package_installable(package), self.get_package_name()) and finder(root, transform=partial(
                find_clickable_enable, text="Understood", click=True, translate=False)) == []:
            logging.debug(str(name) + " " + package)
            return None
        try:
            with timeout.timeout(seconds=200):
                uninstallable = 0
                while True:
                    if os.path.exists("./skip"):
                        os.remove("./skip")
                        return None
                    # self.device.close_app("com.android.chrome")
                    # self.device.close_app("org.lineageos.jelly")
                    logging.debug("4444")
                    self.device.wait_if_internet_isnt_available()
                    self.device.d.wake()
                    # time.sleep(2)
                    root = get_root(self.device)
                    if self.is_gp_open(root=root) == False or name != self.get_package_name():
                        self.open_package_page(package)

                    if finder(root, transform=partial(
                            find_clickable_enable, text="Open", translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Enable", translate=False)):
                        return True

                    if finder(root, transform=partial(
                            find_clickable_enable, text="Play", translate=False)):
                        return True

                    if finder(root, transform=partial(
                            find_clickable_enable, text="Uninstall", translate=False)):
                        if uninstallable >= 2:
                            return None
                        uninstallable += 1
                        continue

                    if finder(root, transform=partial(
                            find_clickable_enable, text="Install", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Try again", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Retry", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Accept", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Update", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Skip", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Accept", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="No thanks", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Continue", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Ok", click=True, translate=False)):
                        logging.debug("5555")
                        continue
                    if finder(root, transform=partial(
                            find_clickable_enable, text="Got it", click=True, translate=False)) or finder(root, transform=partial(
                            find_clickable_enable, text="Understood", click=True, translate=False)):
                        return None
        except:
            # return None
            self.device.d.wake()
            root = get_root(self.device)
            if self.is_gp_open(root=root) == False or name != self.get_package_name():
                self.open_package_page(package)
            if finder(root, transform=partial(find_clickable_enable, text="Cancel", click=True, translate=False)) or finder(root, transform=partial(find_clickable_enable, text="Uninstall", click=True, translate=False)):
                return None
            else:
                time.sleep(2)
                self.device.uninstall_app(package)
                return None

    def is_package_installable(self, package):
        if self.is_gp_open():
            items = [c.getText() for i in self.device.vc.dump() if i.getClass() == "android.view.ViewGroup" and i.getParent(
            ).getClass() != "android.widget.LinearLayout" for c in i.getChildren()]
            if "Install" in items or "Update" in items or "Open" in items:
                return True

    def is_package_installed(self, package, name):
        if self.is_gp_open() or name == self.get_package_name():
            if self.device.uiautomator(
                text="Open",
                className="android.widget.Button",
                clickable="true",
                enabled="true",
            ).exists:
                return True
        return False

    def is_gp_open(self, root='root'):
        if root == 'root':
            root = get_root(self.device)
            # google loading page hash
            while window_hash(root) == "bcdec05b796550fb1c36544f80af3d15dec9c4d4bcede57fe9187ab65ce632be":
                root = get_root(self.device)
        if self.device.get_current_activity() and self.device.get_current_activity().startswith("com.android.vending") and (not finder(root, transform=problem)):
            return True
        return False

    def get_package_name(self):
        if self.is_gp_open():
            _try = 0
            while _try < 2:
                while True:
                    root = get_root(self.device)
                    if (finder(root, transform=partial(
                            find_clickable_enable, text="Retry", click=True, translate=False)) or finder(root, transform=partial(
                                find_clickable_enable, text="Understood", click=True, translate=False)) or finder(root, transform=partial(
                                    find_clickable_enable, text="Skip", click=True, translate=False)) or finder(root, transform=partial(
                                        find_clickable_enable, text="Accept", click=True, translate=False)) or finder(root, transform=partial(
                                            find_clickable_enable, text="No, thanks", click=True, translate=False)) or finder(root, transform=partial(
                                                find_clickable_enable, text="Continue", click=True, translate=False)) or finder(root, transform=partial(
                                                    find_clickable_enable, text="Got it", click=True, translate=False))) == []:
                        logging.debug("7777")
                        break
                try:
                    return [i.getText() for i in self.device.vc.dump() if i.getClass() == "android.widget.TextView" and i.getParent().getClass() == "android.widget.LinearLayout"][0]
                except:
                    _try += 1
                    self.device.d.shell('input keyevent KEYCODE_BACK')
        # if not re.match(r'^(2[0-3]|[01]?[0-9]):([0-5]?[0-9])$', name):

    def open_package_page(self, package):
        self.device.d.wake()
        self.device.shell(
            "am start -a android.intent.action.VIEW -d 'market://details?id=" + package + "'")
        for _ in range(0, 5):
            time.sleep(0.5)
            if self.is_gp_open() == True:
                return True
        return False


# def remove_space(words):
#     nd = dict()
#     for key, value in words.items():
#         if ' ' in key:
#             nd[key.replace(' ', '')] = list(w.replace(' ', '')
#                                             if ' ' in w else w for w in value)
#             nd[key.replace(' ', '-')] = list(w.replace(' ', '-')
#                                              if ' ' in w else w for w in value)
#             nd[key.replace(' ', '_')] = list(w.replace(' ', '_')
#                                              if ' ' in w else w for w in value)
#         else:
#             nd[key] = list(itertools.chain.from_iterable([w.replace(' ', ''), w.replace(
#                 ' ', '_'), w.replace(' ', '-')] if ' ' in w else [w] for w in value))
#     return nd


class App:
    def __init__(self, device, package, stage, analysis_time, param_path="./interactor_parameters.json"):
        self.d = device
        self.p = package
        self.t = analysis_time
        self.stage = str(stage)
        self.memory = dict()
        with open(param_path, 'r') as file:
            self.params = json.loads(file.read())

    def get_params(self, text=True):
        if text:
            return self.params
        else:
            res = dict()
            for cat, val in self.params.items():
                nd = dict()
                for key, value in val.items():

                    if ' ' in key:
                        nd[key.replace(' ', '')] = value if type(value) is not list else list(w.replace(' ', '')
                                                                                              if ' ' in w else w for w in value)
                        nd[key.replace(' ', '-')] = value if type(value) is not list else list(w.replace(' ', '-')
                                                                                               if ' ' in w else w for w in value)
                        nd[key.replace(' ', '_')] = value if type(value) is not list else list(w.replace(' ', '_')
                                                                                               if ' ' in w else w for w in value)
                    else:
                        nd[key] = value if type(value) is not list else list(itertools.chain.from_iterable([w.replace(' ', ''), w.replace(
                            ' ', '_'), w.replace(' ', '-')] if ' ' in w else [w] for w in value))
                res[cat] = nd
            return res

    def find_and_click_by_text(self, root, obj_class):
        w_hash = window_hash(root)
        # print("----------")
        current_activity = self.d.get_current_activity()
        if current_activity in ["com.google.android.gms/.signin.activity.ConsentActivity", "com.google.android.gms/.auth.uiflows.consent.BrowserConsentActivity"]:
            if len(finder(root, transform=partial(find_clickable_enable, text="allow", click=True)) + finder(root, transform=partial(find_clickable_enable, text="continue", click=True))) == 0:
                w = self.d.d.display['width']
                h = self.d.d.display['height']
                s = (w / 2, (h / 3) * 2)
                e = (w / 2, (h / 3))
                self.d.d.drag(s, e, 500, 20, -1)
                self.d.d.drag(s, e, 500, 20, -1)
                # google found
                return True
            # time.sleep(1)
        elif current_activity in ["com.android.vending/com.google.android.finsky.activities.MarketDeepLinkHandlerActivity", "com.android.vending/com.google.android.finsky.billing.acquire.LockToPortraitUiBuilderHostActivity", "com.android.vending/com.google.android.finsky.billing.acquire.SheetUiBuilderHostActivity"] or current_activity.endswith("/com.google.android.gms.ads.AdActivity") or current_activity.endswith("/com.unity3d.services.ads.adunit.AdUnitActivity") or current_activity.endswith("/com.unity3d.ads.adunit.AdUnitActivity"):
            time.sleep(1.5)
            # com.android.vending/com.google.android.finsky.billing.acquire.SheetUiBuilderHostActivity
            print("////////////////")
            self.d.shell('input keyevent KEYCODE_BACK')
            return True
        for include, exclude in self.get_params()["keywords"].items():
            for node in finder(root, transform=partial(
                    find_clickable_enable, text=include, exclude=exclude, obj_class=obj_class, attr="CD"), count=[1], window_hash=w_hash, memory=self.memory):
                logging.debug("id12:"+include)
                node.touch()
                return True
        for include, exclude in self.get_params(text=False)["keywords"].items():
            for node in finder(root, transform=partial(
                    find_clickable_enable, text=include, exclude=exclude, obj_class=obj_class, attr="Id"), count=[1], window_hash=w_hash, memory=self.memory):
                logging.debug("id13:"+include)
                node.touch()
                return True
        for include, exclude in self.get_params()["keywords"].items():
            for node in finder(root, transform=partial(
                    find_clickable_enable, text=include, exclude=exclude, obj_class=obj_class), count=[1], window_hash=w_hash, memory=self.memory):
                node.touch()
                time.sleep(0.5)
                return True
            # print("----------1-2")
        # for include, exclude in self.get_params()["avoid"].items():
        #     for node in finder(root, transform=partial(
        #             find_clickable_enable, text=include, exclude=exclude, obj_class=obj_class), count=[1], window_hash=w_hash, memory=self.memory):
        #         # com.android.vending/com.google.android.finsky.activities.MarketDeepLinkHandlerActivity install
        #         # */com.google.android.gms.ads.AdActivity
        #         # com.android.vending/com.google.android.finsky.billing.acquire.LockToPortraitUiBuilderHostActivity
        #         logging.debug("id-----------------------------:"+node.getText())
        #         logging.debug("id11:"+include)
        #         print("--+++++++++++--"+self.d.get_current_activity())
        #         node.touch()
        #         return True
        time.sleep(1)
        return False

    def find_and_scroll(self, root):
        pass

    #在给定的应用程序界面中查找所有可输入的文本框，并填充这些文本框。
    def find_input_and_fill(self, root, obj_class):
        w_hash = window_hash(root)
        for key, value in self.get_params()["input"].items(): #遍历指定的文本输入参数。界面中查找对应的文本框进行填充
            for node in finder(root, transform=partial(
                    find_clickable_enable, text=key, exclude=[], obj_class=obj_class), count=[1], window_hash=w_hash, memory=self.memory):
                logging.debug("id1:"+node.getId())
                node.setText(value)
                return True
        for key, value in self.get_params(text=False)["input"].items():
            for node in finder(root, transform=partial(
                    find_clickable_enable, text=key, exclude=[], obj_class=obj_class, attr="Id"), count=[1], window_hash=w_hash, memory=self.memory):
                logging.debug("id2:"+node.getId())
                logging.debug("v1:"+value)
                node.setText(value)
                return True
        # for node in finder(root, transform=partial(
        #         find_clickable_enable, text=key, obj_class=obj_class), count=[1], window_hash=w_hash, memory=self.memory):
        #     node.setText(value)
        #     return True
        return False

    def scroll_down(self, w, h):
        w = self.d.d.display['width']
        h = self.d.d.display['height']
        self.d.shell("input swipe {} {} {} {} 100".format(
            w / 2, (h / 3) * 2, w / 2, h / 3))

    def scroll_up(self, w, h):
        w = self.d.d.display['width']
        h = self.d.d.display['height']
        self.d.shell("input swipe {} {} {} {} 100".format(
            w / 2, h / 3, w / 2, (h / 3) * 2))

    def scroll_right(self, w, h):
        self.d.shell("input swipe {} {} {} {} 100".format(
            w / 5, h / 2, (w / 5 * 4), h / 2, 500, 20))

    #模拟用户的交互行为来进行屏幕操作。根据传入的参数 deep 来判断是否进行深度交互
    def dumb_interaction(self, deep=False):
        click_command = ""
        w = int(self.d.display.y)
        h = int(self.d.display.x - self.d.display.statusbar)
        if bool(random.getrandbits(1)): #根据随机数的结果选择向上或向下滚动屏幕
            self.scroll_up(w, h)
        else:
            self.scroll_down(w, h)
        self.scroll_right(w, h) #向右滚动屏幕
        if deep:
            base = (10, 5)
        else:
            base = (6, 3)
        for y in reversed(range(int(h/base[0]), h, int(h/base[0]))): #循环遍历屏幕区域，并生成相应的点击命令，依次点击屏幕上的各个位置。
            for x in range(int(w/base[1]), w, int(w/base[1])):
                click_command += "input tap {} {};".format(x, y)
        self.d.shell(click_command) #利用设备的 shell 方法执行生成的点击命令，实现模拟用户的交互操作。

    def smart(self):
        futile = -1
        back_key = 2
        app_closed = 0
        time.sleep(10)
        start = int(time.time())
        for _ in range(0, 100):
            if os.path.exists("./skip"):
                os.remove("./skip")
                break #如果当前目录下存在名为“skip”的文件，则删除该文件并退出循环。
            if int(time.time()) - start > 300:  # 300
                break #如果当前目录下存在名为“skip”的文件，则删除该文件并退出循环。
            if self.d.is_app_crashed(self.p): #如果应用程序崩溃，记录并模拟返回
                with open("out/"+self.p+"/crash-"+self.stage+"-"+str(int(time.time()))+".txt", "a") as f:
                    f.write(self.d.shell('logcat -d *:E -t \''+datetime.datetime.fromtimestamp(
                        self.t).strftime('%m-%d %H:%M:%S.0')+'\'|base64')+"\n")
                    self.d.shell('input keyevent KEYCODE_BACK')
            if self.d.is_app_hangs(self.p): #如果应用程序挂起，记录并模拟返回
                with open("out/"+self.p+"/hang-"+self.stage+"-"+str(int(time.time()))+".txt", "a") as f:
                    f.write(str(int(time.time()))+"\n")
                    self.d.shell('input keyevent KEYCODE_BACK')

            if self.d.frida.is_lost != 0: #如果Frida丢失连接，则终止当前进程。
                os.system('kill -9 {pid}'.format(pid=os.getpid()))
            
            #通过shell命令向Android系统发送广播，模拟发送GPS位置信息。
            self.d.d.shell( 
                "am broadcast -n com.research.helper/.SendGPS -e lat 45.4950378 -e lon -73.5779508 -e accurate 0.5 -e alt 5")
            #(测试某个应用程序在接收到GPS位置信息时的行为)
            
            try:
                # print("sleep 10")
                # time.sleep(10)

                if not self.d.is_app_open(self.p):
                    if app_closed >= 3:
                        break
                    app_closed += 1
                    self.d.run_app(self.p, close=False)
                # print("sleep 10.1")
                # time.sleep(10)

                memory_snapshot = len(str(self.memory)) #记录当前内存状态的快照。
                #self.d.wait_if_internet_isnt_available()
                self.d.d.wake() #等待网络可用，并唤醒设备屏幕。
                #########
                time.sleep(180) 
                print("OOOOOOOOOOOOOOOOOOOOOKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")
                #root = get_root(self.d) #获取设备当前界面的根元素。
                #print("**---++----")
                #for _ in range(0, 10): #循环10次，查找所有可输入文本框并填写字符串。
                    #self.find_input_and_fill(
                        #root, obj_class=["android.widget.edittext"])

                #for _ in range(0, 10): #再循环10次，查找所有可点击的按钮并模拟点击。如果找到了，则重新获取设备当前界面的根元素。否则退出循环。
                    #if finder(root, transform=partial(
                            #find_clickable_enable, text="9", obj_class=["android.widget.button"], click=True), count=[1], window_hash=window_hash(root)):
                        #root = get_root(self.d)
                    #else:
                        #break
                #windowhash = window_hash(root) #计算当前界面的哈希值。

                #if not self.d.is_app_open(self.p): #应用程序未打开，则重新启动它
                    #if app_closed >= 3:
                        #break #如果已经重试了3次，则退出循环。
                    #app_closed += 1
                    #self.d.run_app(self.p, close=False)
                    #continue

                #尝试通过文本查找并点击一个UI元素，该元素可能是多种类型之一，如TextView、Button等等。
                #fct = self.find_and_click_by_text(
                    #root, obj_class=["android.widget.checkedtextview", "android.view.view", "android.widget.button", "android.widget.textview", "android.widget.imageview", "android.widget.imagebutton","android.widget.LinearLayout"])
                #logging.debug("mem:"+str(self.memory))
                #if fct == False: #如果未找到任何要点击的元素，则模拟按下返回键。
                    #if windowhash == get_root(self.d):
                        #self.d.shell('input keyevent KEYCODE_BACK')
                
                #if memory_snapshot == len(str(self.memory)):
                    #logging.debug("futile:"+str(futile))
                    #if futile >= 4: #如果futile大于等于4
                        #if back_key <= 0:
                            #break
                        #futile -= 1
                        #self.d.shell('input keyevent KEYCODE_BACK') #模拟按下返回键
                        #time.sleep(1)#并等待一秒钟
                        #if not self.d.is_app_open(self.p):
                            #break
                        #back_key -= 1
                    #elif futile == 3:
                        #self.dumb_interaction()#滚动
                    #futile += 1
                    #time.sleep(abs(futile)/2) #将futile加1，并根据其值确定等待时间。
                    #logging.debug("xxxxxx")
                #else:#如果内存快照与先前不同
                    #logging.debug("aaaaaa")
                    #back_key = 3
                    #futile = 1
            except ValueError as ee: #捕获可能出现的ValueError和RuntimeError异常
                logging.debug("xsxs")
                logging.debug(ee)
                #self.dumb_interaction()
                #if back_key <= 0:
                    #break
                time.sleep(10) 
                #self.d.shell('input keyevent KEYCODE_BACK')
                #back_key -= 1
            #except RuntimeError:
                #self.dumb_interaction(deep=True)
                # self.d.shell('input keyevent KEYCODE_BACK')
                #time.sleep(10) 
            #exit()
            # logging.debug(self.memory)
        # time.sleep(20)
        # finder(root, transform=partial(find_button_click, text="Update"))
        # logging.debug(self.d.vc.dump())

    def find_similar_button(self):
        pass

    def dump(self):
        pass
