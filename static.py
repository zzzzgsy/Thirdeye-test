import os
import re
from zipfile import BadZipFile

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

#这个类分析应用程序包中的 dex 文件，并提取其中的方法信息，然后根据一定的条件进行过滤和处理。
class Package:
    def __init__(self, package, output="out/"):
        self.dexes = set()
        #遍历指定目录下的APK文件
        for apk_path in [output+package+'/'+f for f in os.listdir(
                output+package+'/') if re.match(r'.+\.apk', f)]:
            try:
                for dex in APK(apk_path).get_all_dex():
                    try:#提取其中的 dex 文件，转换成 DalvikVMFormat 对象
                        self.dexes.add(DalvikVMFormat(dex))
                    except:
                        pass
                    # break
            except BadZipFile:
                (os.remove(apk_path) for apk_path in [
                 output+package+'/'+f for f in os.listdir(output+package+'/') if re.match(r'.+\.apk', f)])
                os.system('kill -9 {pid}'.format(pid=os.getpid()))

    def get_methods(self, filter): # filter 参数，用于过滤方法
        methods = set()
        for dex in self.dexes: #遍历 dexes 集合中的所有 DalvikVMFormat 对象
            for method in dex.get_methods():
                if method.get_name().endswith(b"-impl"): 
                #if method.get_name().endswith("-impl"): 
                    continue #跳过 -impl 结尾的
                new_method = Method() 
                new_method.into(method)
                if method.get_name().decode("utf-8").find(' ') == -1 and method.get_name().decode("utf-8").find('-') == -1 and method.class_name.decode("utf-8").find('$') == -1 and method.get_descriptor().decode("utf-8").find('$') == -1 and not method.class_name.decode("utf-8").endswith("Impl;") and not (method.get_access_flags() & 0x100) == 0x100:
                #if method.get_name().find(' ') == -1 and method.get_name().find('-') == -1 and method.class_name.find('$') == -1 and method.get_descriptor().find('$') == -1 and not method.class_name.endswith("Impl;") and not (method.get_access_flags() & 0x100) == 0x100:
                
                    if filter(new_method):
                        #print(method.class_name)
                        #print(method.get_name())
                        methods.add(new_method)
        return methods


class Method:
    def into(self, method):
        #从给定的 method 对象中获取类名
        self.class_name = (method.get_class_name()[1:].decode("utf-8").rstrip(';').replace('/', '.'))
        #self.class_name = method.get_class_name()[1:].rstrip(';').replace('/', '.')
        #self.name = ("$init" if method.get_name().decode("utf-8") ==
                     #"<init>" else method.get_name().decode("utf-8")) #获取方法名称，并对其进行处理
        self.name = "$init" if method.get_name() == "<init>" else method.get_name()

        self.params, self.return_type = description_mapper(
            method.get_descriptor())

    #调用jni_translation 函数将self.class_name 和self.name 进行 JNI（Java Native Interface）翻译，并将结果拼接成字符串后返回。
    def to_jni(self):
        return "Java_"+jni_translation(self.class_name).replace('.', "_")+"_"+jni_translation(self.name)

    def to_frida(self, body=lambda method, body: "", ret=""):
        params = {}
        for i, param in enumerate(self.params): #使用 enumerate 函数遍历 self.params 列表中的元素
            params["p"+str(i)] = param
        if ret == "":
            ret = "return this."+str(self.name) + \
                "("+(", ".join([key for key, value in params.items()]))+")"
        #return "try{Java.use('"+self.class_name+"')."+self.name+".overload("+("" if len(params) == 0 else "'"+"', '".join([value for key, value in params.items()])+"'")+").implementation  = function ("+", ".join([key for key, value in params.items()])+") {"+body(self, params)+";"+ret+"};} catch(_e) {}"
        #return "try{Java.use('" + self.class_name + "')." + str(self.name) + ".overload(" + ("" if len(params) == 0 else "'" + "', '".join([str(value.decode()) for key, value in params.items()]) + "'") + ").implementation = function (" + ", ".join([str(key.decode()) for key, value in params.items()]) + ") {" + str(body(self, params)) + ";" + ret + "};} catch(_e) {}"
        return "try{Java.use('" + self.class_name + "')." + str(self.name) + ".overload(" + ("" if len(params) == 0 else "'"+"', '".join([value for key, value in params.items()])+"'")+").implementation  = function ("+", ".join([key for key, value in params.items()])+") {"+body(self, params)+";"+ret+"};} catch(_e) {}"

        #使用 Frida 框架的 Java.use 方法获取指定类名和方法名的对象.通过 overload 方法指定方法的重载签名和实现

def jni_translation(_str):
    return _str.replace('_', '_1').replace(';', '_2').replace('[', '_3')


def description_mapper(description):
    types = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    description, return_type = description.split(")", 1)
    param_list = list()
    return_type = types[return_type] if return_type in types else "[" + \
        types[return_type[1:]] if return_type[1:] in types else return_type.replace(
            "/", ".")
    ret = return_type if type(return_type) == str else return_type.decode()

    for params in description[1:].split(" "):
        if params in types and params[0] != "[":
            param_list.append((types[params] if type(
                types[params]) == str else types[params].decode()))
        elif len(params) != 0:
            if len(params) != 0 and params[0] == "[":
                param_list.append("["+(params[1:] if type(params[1:])
                                  == str else params[1:].decode()).replace("/", "."))
            else:
                param_list.append((params[1:len(params)-1] if type(params[1:len(
                    params)-1]) == str else params[1:len(params)-1].decode()).replace("/", "."))

    return param_list, ret

# def description_mapper(description):
#     types = {
#         "V": "void",
#         "Z": "boolean",
#         "B": "byte",
#         "S": "short",
#         "C": "char",
#         "I": "int",
#         "J": "long",
#         "F": "float",
#         "D": "double",
#     }
#     description, return_type = description.split(")", 1)
#     param_list = list()
#     return_type = types[return_type] if return_type in types else "[" + \
#         types[return_type[1:]] if return_type[1:] in types else return_type.replace(
#             "/", ".")

#     for params in description[1:].split(" "):
#         if params in types and params[0] != "[":
#             param_list.append(bytes(types[params], encoding='utf8'))
#         elif len(params) != 0:
#             if len(params) != 0 and params[0] == "[":
#                 param_list.append(b"["+params[1:].replace("/", "."))
#             else:
#                 param_list.append(params[1:len(params)-1].replace("/", "."))

#     return param_list, return_type
