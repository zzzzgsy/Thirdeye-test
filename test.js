Java.perform(() => {
        let JSONObject = Java.use("org.json.JSONObject");
        JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (key, val) {
            console.log("key : " + key + ", val : " + val)
            let result = this.put(key, val);
            // console.log(`result=${result}`)
            return result;
        };
    })
// function hook_dlopen() {
//     try {
//         var dlopen = Module.findExportByName("libc.so", "dlopen");
//         if (dlopen) {
//             Interceptor.attach(dlopen, {
//                 onEnter: function (args) {
//                     var pathptr = args[0];
//                     if (pathptr !== undefined && pathptr != null) {
//                         var path = ptr(pathptr).readCString();
//                         console.log("dlopen called with path: " + path);
//                     }
//                 }
//             });
//         } else {
//             console.log("dlopen not found");
//         }
//     } catch (e) {
//         console.log("Error hooking dlopen: " + e.message);
//     }
// }

// setTimeout(hook_dlopen);

// Java.perform(function () {
 
//     var dlopen = Module.findExportByName(null, "dlopen");
//     var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
 
//     Interceptor.attach(dlopen, {
//         onEnter: function (args) {
//             var path_ptr = args[0];
//             var path = ptr(path_ptr).readCString();
//             console.log("[dlopen:]", path);
//         },
//         onLeave: function (retval) {
 
//         }
//     });
 
//     Interceptor.attach(android_dlopen_ext, {
//         onEnter: function (args) {
//             var path_ptr = args[0];
//             var path = ptr(path_ptr).readCString();
//             console.log("[dlopen_ext:]", path);
//         },
//         onLeave: function (retval) {
 
//         }
//     });
 
 
// });


