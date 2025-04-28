// function readFile(fileName) {
//     console.log("> Reading file: ", fileName);
//     const JString = Java.use("java.lang.String");
//     const Files = Java.use("java.nio.file.Files");
//     const Paths = Java.use("java.nio.file.Paths");
//     const URI = Java.use("java.net.URI");
//     const pathName = "file://" + fileName;
//     const path = Paths.get(URI.create(pathName));
//     const fileBytes = Files.readAllBytes(path);
//     return JString.$new(fileBytes);
// }
//
// // libfrida-agent-raw.so
//
// function fridaScan(startAddress, endAddress, searchValue, replaceValue) {
//     Memory.scan(startAddress, endAddress.sub(startAddress).toInt32(), searchValue, {
//         onMatch: function (address, size) {
//             console.log("找到数据！地址：" + address);
//             Memory.patchCode(address, size, function (code) {
//                 const replaceArray = replaceValue.split(" ").map(hexString=>{
//                     return parseInt(hexString, 16)
//                 })
//                 code.writeByteArray(replaceArray)
//             })
//             console.log("替换成功")
//         },
//         onComplete: function () {
//             console.log("搜索完成。");
//         }
//     });
// }
//
// function main(){
//     const data = readFile("/proc/self/maps")
//     Interceptor.detachAll();
//     let startAddress, endAddress;
//     let num = 0;
//     data.split("\n").forEach(line=>{
//         if (line.indexOf("/memfd") !== -1){
//             const match = line.match(/^([0-9a-f]+)-([0-9a-f]+)/);
//             console.log(line)
//             if (num === 0) {
//                 startAddress = ptr(parseInt(match[1], 16));
//                 endAddress = ptr(parseInt(match[2], 16));
//             }
//             num += 1;
//         }
//     })
//     console.log(startAddress)
//     console.log(endAddress)
//     const fridaStringHex = "6c 69 62 66 72 69 64 61 2d 61 67 65 6e 74"
//     const replaceStringHex = "6c 69 62 78 64 6d 68 61 2d 61 67 65 6e 74"
//     fridaScan(startAddress, endAddress, fridaStringHex, replaceStringHex);
// }

function hook_so_dlopen(so_name) {
    var target_so_name = so_name;
    Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
        onEnter: function (args) {
            hook_native()
            this.flag = false;
            var library_path = Memory.readCString(args[0]);
            this.path = library_path;
            console.log("[Load SO] => " + library_path);

            if (library_path.indexOf(target_so_name) >= 0) {

                this.flag = true;
                console.log("[Load SO] => " + library_path);

            }

        },
        onLeave: function (retval) {
            console.log(this.flag)


            if (this.flag) {
                // hook_jni_onload()
                replace_thread()
                hook_native()
                // 等待 so 加载完成后再 hook JNI_OnLoad
                // try {
                //     const jni_onload_ptr = Module.findExportByName(target_so_name, "JNI_OnLoad");
                //     if (jni_onload_ptr) {
                //         console.log("[*] Found JNI_OnLoad at:", jni_onload_ptr);
                //
                //         Interceptor.attach(jni_onload_ptr, {
                //             onEnter: function (args) {
                //                 console.log("[*] JNI_OnLoad Called");
                //                 // const threadId = Process.getCurrentThreadId();
                //                 const module = Process.findModuleByName(target_so_name);
                //                 // const base = mod.base;
                //                 // const offset = jni_onload_ptr.sub(base);
                //                 // const size = 0x31A38-0x2F9D0; // 估一个大概范围
                //                 //
                //                 // Stalker.follow(threadId, {
                //                 //     transform: function (iterator) {
                //                 //         let instruction = iterator.next();
                //                 //         do {
                //                 //             const addr = instruction.address;
                //                 //             const off = addr.sub(base);
                //                 //             if (off.compare(offset) >= 0 && off.compare(offset.add(size)) <= 0) {
                //                 //                 console.log("[*] " + addr + " <+" + off + "> " + instruction);
                //                 //             }
                //                 //             iterator.keep();
                //                 //         } while ((instruction = iterator.next()) !== null);
                //                 //     }
                //                 // });
                //                 const threadId = Process.getCurrentThreadId();
                //                 const base = module.base;
                //                 //jni_onload
                //                 // const start_offset=0x2F9D0;
                //                 // const end_offset = 0x31A38;
                //                 // sub_31a3c
                //                 const start_offset = 0x31a3c;
                //                 const end_offset = 0x370b4;
                //                 const size = end_offset - start_offset;
                //                 const startBase = base.add(start_offset);
                //                 // const size = 0x31A60-0x31A3C;
                //
                //                 Stalker.follow(threadId, {
                //                     transform: function (iterator) {
                //                         let instruction = iterator.next();
                //                         const baseFirstAddress = instruction.address;
                //                         const isModuleCode = baseFirstAddress.compare(startBase) >= 0 &&
                //                             baseFirstAddress.compare(startBase.add(size)) <= 0;
                //                         if (isModuleCode) {
                //                             if (module) {
                //                                 const name = "libDexHelper.so";
                //                                 const offset = baseFirstAddress.sub(base);
                //                                 console.log(`[transform] start: ${baseFirstAddress} name:${name} offset: ${offset} base: ${base}`);
                //                             } else {
                //                                 console.log(`[transform] start: ${baseFirstAddress}`);
                //                             }
                //                         }
                //                         do {
                //                             const curRealAddr = instruction.address;
                //                             const curOffset = curRealAddr.sub(baseFirstAddress);
                //                             const curOffsetInt = curOffset.toInt32()
                //                             const instructionStr = instruction.toString()
                //                             if (isModuleCode) {
                //
                //                                 console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr);
                //                             }
                //                             iterator.keep();
                //                         } while ((instruction = iterator.next()) !== null);
                //                         if (isModuleCode) {
                //                             console.log()
                //                         }
                //                     }
                //                 });
                //
                //             },
                //             onLeave: function () {
                //                 console.log("[*] JNI_OnLoad returned.");
                //             }
                //         });
                //     } else {
                //         console.log("[!] JNI_OnLoad not found.");
                //     }
                // } catch (e) {
                //     console.error("[!] Error:", e);
                // }
            }
        }
    });
}


function hook_dlopen(){
    //Android8.0之后加载so通过android_dlopen_ext函数
    var android_dlopen_ext = Module.findExportByName(null,"android_dlopen_ext");
    console.log("addr_android_dlopen_ext",android_dlopen_ext);
    Interceptor.attach(android_dlopen_ext,{
        onEnter:function(args){
            var pathptr = args[0];
            if(pathptr!=null && pathptr != undefined){
                var path = ptr(pathptr).readCString();
                console.log("android_dlopen_ext:",path);
            }
        },
        onLeave:function(retvel){
        }
    })
}

function hook_pthread_create() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create");
    if (!pthread_create_addr) {
        console.error("[-] pthread_create not found!");
        return;
    }

    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);

    const pthread_create_hook = new NativeCallback((parg0, parg1, parg2, parg3) => {
        try {
            if (parg2.isNull() || !Process.isAddressValid(parg2)) {
                console.warn("[*] pthread_create with invalid start_routine address:", parg2);
                return pthread_create(parg0, parg1, parg2, parg3);
            }

            let module = Process.findModuleByAddress(parg2);
            if (module) {
                let offset = parg2.sub(module.base);

                // 打印信息
                console.log("[*] pthread_create from", module.name, "offset 0x" + offset.toString(16), "arg3: 0x" + parg3.toString(16));

                // 根据so名字做拦截，比如libDexHelper.so拦住
                if (module.name.indexOf("libDexHelper.so") !== -1) {
                    console.warn("[*] Block pthread_create from", module.name, "at offset 0x" + offset.toString(16));
                    return 0; // 直接返回，不让线程创建
                }
            } else {
                console.warn("[*] pthread_create but module not found for", parg2);
            }
        } catch (e) {
            console.error("[!] Exception in pthread_create hook:", e);
        }

        return pthread_create(parg0, parg1, parg2, parg3);
    }, "int", ["pointer", "pointer", "pointer", "pointer"]);

    Interceptor.replace(pthread_create_addr, pthread_create_hook);

    console.log("[+] Successfully hooked pthread_create");
}

// 调用



function pthread_create_1() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create")
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        const so_name = module.name;
        const baseAddr = module.base;
        if (so_name.indexOf("libDexHelper.so") !== -1) {
            console.log("pthread_create", so_name, "0x" + parg2.sub(baseAddr).toString(16), "0x" + parg3.toString(16))
            return 0;
        }
        return pthread_create(parg0, parg1, parg2, parg3)
    }, "int", ["pointer", "pointer", "pointer", "pointer"])
}


// function hook_pthread() {
//
//     var pthread_create_addr = Module.findExportByName(null, 'pthread_create');
//
//     var pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
//     Interceptor.replace(pthread_create_addr, new NativeCallback(function (parg0, parg1, parg2, parg3) {
//         var so_name = Process.findModuleByAddress(parg2).name;
//         var so_path = Process.findModuleByAddress(parg2).path;
//         var so_base = Module.getBaseAddress(so_name);
//         var offset = parg2 - so_base;
//         var PC = 0;
//         if ((so_name.indexOf("libexec.so") > -1)) {
//             console.log("find thread func offset", so_name, offset);
//             if ((207076 === offset)) {
//                 console.log("anti bypass");
//             } else if (207308 === offset) {
//                 console.log("anti bypass");
//             } else if (283820 === offset) {
//                 console.log("anti bypass");
//             } else if (286488 === offset) {
//                 console.log("anti bypass");
//             } else if (292416 === offset) {
//                 console.log("anti bypass");
//             } else if (78136 === offset) {
//                 console.log("anti bypass");
//             } else if (293768 === offset) {
//                 console.log("anti bypass");
//             } else {
//                 PC = pthread_create(parg0, parg1, parg2, parg3);
//             }
//         } else {
//             PC = pthread_create(parg0, parg1, parg2, parg3);
//         }
//         return PC;
//     }, "int", ["pointer", "pointer", "pointer", "pointer"]))
// }

function create_pthread_create() {
    const pthread_create_addr = Module.findExportByName(null, "pthread_create")
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        const so_name = module.name;
        const baseAddr = module.base
        console.log("pthread_create", so_name, "0x" + parg2.sub(baseAddr).toString(16), "0x" + parg3.toString(16))
        // 成功的返回值是0
        return pthread_create(parg0, parg1, parg2, parg3)

    }, "int", ["pointer", "pointer", "pointer", "pointer"])
}


function replace_thread() {
    // var new_pthread_create = create_pthread_create()
    var pthread_create_addr = Module.findExportByName(null, "pthread_create")
    // 函数替换
    Interceptor.replace(pthread_create_addr, pthread_create_1());

}


function hook_native(){

    var base_so = Module.findBaseAddress("libDexHelper.so");
    if (base_so) {
        //console.log("base_hello_jni",base_hello_jni);
        Interceptor.attach(base_so.add(0x4B2E0), {

            onEnter: function (args) {
                console.log("[*] sub_4B2E0 onEnter");
            },
            onLeave: function (retval) {
                    retval.replace(ptr(0));
            }

        });

        //     var sub_38E94 = base_so.add(0x38E94);
        //     Interceptor.attach(sub_38E94, {
        //         onEnter: function (args) {
        //             // console.log("sub_38E94 onEnter:", hexdump(args[0]), "\r\n", args[1].toInt32());
        //             console.log("sub_38E94 onEnter:");
        //             console.log("Arg0 (a1):", args[0].readCString());  // const char* a1
        //             console.log("Arg1 (a2):", args[1].toInt32());       // int64 a2
        //         }, onLeave: function (retval) {
        //             console.log("sub_38E94 onLeave:", retval.toInt32());
        //         }
        //     });
        // }

        // Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
        //     onEnter: function (args) {
        //         this.arg1 = Memory.readCString(args[0]);
        //         this.arg2 = Memory.readCString(args[1]);
        //         this.n = args[2].toInt32();
        //
        //         console.log("[*] strncmp called");
        //         console.log("    arg0: " + this.arg1);
        //         console.log("    arg1: " + this.arg2);
        //         console.log("    n   : " + this.n);
        //     },
        //     onLeave: function (retval) {
        //         console.log("    return: " + retval);
        //     }
        // });

    }

}


function hook_jnionload() {

    const module = Process.findModuleByName('libantssm.so');
    const JNI_OnLoad = module.findExportByName("JNI_OnLoad");
    Interceptor.attach(JNI_OnLoad, {
        onEnter: function () {
            console.log('进来')
        },
        onLeave: function () {
            console.log('离开')
        }
    })

}
function hook_jni_onload() {
    // Module.load('libantssm.so');
    // Module.ensureInitialized('libantssm.so');

    // Module.findExportByName('libantssm.so', 'JNI_OnLoad');
    const module = Process.findModuleByName('libDexHelper.so');
    if (module == null) {
        console.log('libDexHelper.so 没加载');
        return;
    }
    const base = module.base;
    const addr = module.findExportByName('JNI_OnLoad');
    if (addr == null) {
        console.log('找不到 JNI_OnLoad');
        return;
    }

    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log('进入 JNI_OnLoad');
        },
        onLeave: function (retval) {
            console.log('离开 JNI_OnLoad');
        }
    });
}


// replace_thread()
// hook_dlopen()

hook_native()
// replace_thread()
hook_so_dlopen("libDexHelper.so")
// hook_jni_onload()
// main()








// const module = Process.findModuleByName('libDexHelper.so');
// const JNI_OnLoad = module.findExportByName("JNI_OnLoad");
// Interceptor.attach(JNI_OnLoad, {
//     onEnter: function () {
//         console.log('进来')
//     },
//     onLeave: function () {
//         console.log('离开')
//     }
// })



/* Bypass Frida Detection Based On Port Number */
// Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
//     onEnter: function(args) {
//         var memory = Memory.readByteArray(args[1], 64);
//         var b = new Uint8Array(memory);
//         if (b[2] == 0x69 && b[3] == 0xa2 && b[4] == 0x7f && b[5] == 0x00 && b[6] == 0x00 && b[7] == 0x01) {
//             this.frida_detection = true;
//         }
//     },
//     onLeave: function(retval) {
//         if (this.frida_detection) {
//             console.log("Frida Bypassed");
//             retval.replace(-1);
//         }
//     }
// });
// Interceptor.attach(Module.findExportByName(null, "connect"), {
//     onEnter: function(args) {
//         var family = Memory.readU16(args[1]);
//         if (family !== 2) {
//             return
//         }
//         var port = Memory.readU16(args[1].add(2));
//         port = ((port & 0xff) << 8) | (port >> 8);
//         if (port === 27042) {
//             console.log('frida check');
//             Memory.writeU16(args[1].add(2), 0x0101);
//         }
//     }
// });
// /* Bypass TracerPid Detection Based On Pid Status */
// var fgetsPtr = Module.findExportByName("libc.so", "fgets");
// var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
// Interceptor.replace(fgetsPtr, new NativeCallback(function(buffer, size, fp) {
//     // console.warn(buffer);
//     var retval = fgets(buffer, size, fp);
//     var bufstr = Memory.readUtf8String(buffer);
//     if (bufstr.indexOf("TracerPid:") > -1) {
//         Memory.writeUtf8String(buffer, "TracerPid:\t0");
//         console.log("Bypassing TracerPID Check");
//     }
//     return retval;
// }, 'pointer', ['pointer', 'int', 'pointer']))
// /* Bypass Ptrace Checks */
// Interceptor.attach(Module.findExportByName(null, "ptrace"), {
//     onEnter: function(args) {},
//     onLeave: function(retval) {
//         console.log("Ptrace Bypassed");
//         retval.replace(0);
//     }
// })
// /* Watch Child Process Forking */
// var fork = Module.findExportByName(null, "fork")
// Interceptor.attach(fork, {
//     onEnter: function(args) {},
//     onLeave: function(retval) {
//         var pid = parseInt(retval.toString(16), 16)
//         console.log("Child Process PID : ", pid)
//     }
// })
// /*
// Interceptor.attach(Module.getExportByName(null,"__android_log_print"), {
//         onEnter: function (args) {
//             console.warn(args[0],args[1].readCString(),args[2].readCString(),);
//             }
//         }
//     );
// */
// /* Screenshot Detection Bypass  */
// Java.perform(function() {
//     try {
//         var surface_view = Java.use('android.view.SurfaceView');
//         var set_secure = surface_view.setSecure.overload('boolean');
//         set_secure.implementation = function(flag) {
//             set_secure.call(false);
//         }
//         var window = Java.use('android.view.Window');
//         var SFlag = window.setFlags.overload('int', 'int');
//         var window_manager = Java.use('android.view.WindowManager');
//         var layout_params = Java.use('android.view.WindowManager$LayoutParams');
//         SFlag.implementation = function(flags, mask) {
//             flags = (flags.value & ~layout_params.FLAG_SECURE.value);
//             SFlag.call(this, flags, mask);
//         }
//     } catch (err) {
//         console.error(err);
//     }
// })
// /* Xposed Detection Bypass */
// Java.perform(function() {
//     try {
//         var cont = Java.use("java.lang.String");
//         cont.contains.overload("java.lang.CharSequence").implementation = function(checks) {
//             var check = checks.toString();
//             if (check.indexOf("libdexposed") >= 0 || check.indexOf("libsubstrate.so") >= 0 || check.indexOf("libepic.so") >= 0 || check.indexOf("libxposed") >= 0) {
//                 var BypassCheck = "libpkmkb.so";
//                 return this.contains.call(this, BypassCheck);
//             }
//             return this.contains.call(this, checks);
//         }
//     } catch (erro) {
//         console.error(erro);
//     }
//     try {
//         var StacktraceEle = Java.use("java.lang.StackTraceElement");
//         StacktraceEle.getClassName.overload().implementation = function() {
//             var Flag = false;
//             var ClazzName = this.getClassName();
//             if (ClazzName.indexOf("com.saurik.substrate.MS$2") >= 0 || ClazzName.indexOf("de.robv.android.xposed.XposedBridge") >= 0) {
//                 console.log("STE Classes : ", this.getClassName())
//                 Flag = true;
//                 if (Flag) {
//                     var StacktraceEle = Java.use("java.lang.StackTraceElement");
//                     StacktraceEle.getClassName.overload().implementation = function() {
//                         var gMN = this.getMethodName();
//                         if (gMN.indexOf("handleHookedMethod") >= 0 || gMN.indexOf("handleHookedMethod") >= 0 || gMN.indexOf("invoked") >= 0) {
//                             console.log("STE Methods : ", this.getMethodName());
//                             return "ulala.ulala";
//                         }
//                         return this.getMethodName();
//                     }
//                 }
//                 return "com.android.vending"
//             }
//             return this.getClassName();
//         }
//     } catch (errr) {
//         console.error(errr);
//     }
// })
// /* VPN Related Checks */
// Java.perform(function() {
//     var NInterface = Java.use("java.net.NetworkInterface");
//     try {
//         NInterface.isUp.overload().implementation = function() {
//             //console.log("Network Down");
//             return false;
//             // may cause connectivity lose in rare case so be careful
//         }
//     } catch (err) {
//         console.error(err);
//     }
//     try {
//         var NInterface = Java.use("java.net.NetworkInterface");
//         NInterface.getName.overload().implementation = function() {
//             var IName = this.getName();
//             if (IName == "tun0" || IName == "ppp0" || IName == "p2p0" || IName == "ccmni0" || IName == "tun") {
//                 console.log("Detected Interface Name : ", JSON.stringify(this.getName()));
//                 return "FuckYou";
//             }
//             return this.getName();
//         }
//     } catch (err) {
//         console.error(err);
//     }
//     try {
//         var GetProperty = Java.use("java.lang.System");
//         GetProperty.getProperty.overload("java.lang.String").implementation = function(getprop) {
//             if (getprop.indexOf("http.proxyHost") >= 0 || getprop.indexOf("http.proxyPort") >= 0) {
//                 var newprop = "CKMKB"
//                 return this.getProperty.call(this, newprop);
//             }
//             return this.getProperty(getprop);
//         }
//     } catch (err) {
//         console.error(err);
//     }
//     try {
//         var NCap = Java.use("android.net.NetworkCapabilities");
//         NCap.hasTransport.overload("int").implementation = function(values) {
//             console.log("HasTransport Check Detected ");
//             if (values == 4)
//                 return false;
//             else
//                 return this.hasTransport(values);
//         }
//     } catch (e) {
//         console.error(e);
//     }
// })
// /* Developer Mod Check Bypass */
// Java.perform(function() {
//     var SSecure = Java.use("android.provider.Settings$Secure");
//     SSecure.getStringForUser.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(Content, Name, Flag) {
//         if (Name.indexOf("development_settings_enabled") >= 0) {
//             console.log(Name);
//             var Fix = "fuckyou";
//             return this.getStringForUser.call(this, Content, Fix, Flag);
//         }
//         return this.getStringForUser(Content, Name, Flag);
//     }
// })