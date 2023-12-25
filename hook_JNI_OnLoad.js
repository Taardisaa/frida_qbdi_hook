// QBDI
import { VM, InstPosition, VMAction, SyncDirection, VMEvent } from "./frida-qbdi.js";

var STACK_SIZE = 0x100000
/* 
    get libraries by hooking 'android_dlopen_ext' function
 */
function load_lib(lib_name) {
    var is_loaded = false;
    var dlopen_addr = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(dlopen_addr, {
        onEnter: function(args) {
            var lib_path = Memory.readUtf8String(args[0]);
            if(lib_path.indexOf(lib_name) != -1) {
                // Found the wanted lib
                console.log("[+] Lib Loaded: " + lib_path);
                is_loaded = true;
            }
        },
        onLeave: function(retvals) {
            if(is_loaded) {
                // 
                console.log("[+] Processing JNI_OnLoad in: " + lib_name);
                process_JNI_OnLoad(lib_name);   // !TODO: lib_name or lib_path?
                is_loaded = false;  // reset after process
            }
        }
    });
}  

function process_JNI_OnLoad(lib_name) {
    var func_addr = Module.findExportByName(lib_name, "JNI_OnLoad");
    if(func_addr) {
        // attach 
        // var func_hook = Interceptor.attach(func_addr, {
        //     onEnter: function(args) {
        //         arg_vm = args[0];
        //         arg_reserved = args[1];
        //         console.log(`[+] JNI_OnLoad(${arg_vm}, ${arg_reserved}) called`);
        //     },
        //     onLeave: function(retvals) {
        //         console.log(`[+] retval from JNI_OnLoad: ${retvals}`);
        //     }
        // })

        var replace = Interceptor.replace(func_addr, new NativeCallback(function(arg_vm, arg_reserved){
            console.log(`[+] JNI_OnLoad(${arg_vm}, ${arg_reserved}) called`);
            Interceptor.revert(func_addr);
            Interceptor.flush();
            var retval = qbdi_exec(this.context, lib_name, func_addr, "JNI_OnLoad", [arg_vm, arg_reserved], true);
            process_JNI_OnLoad(lib_name);
            return retval;
        }, 'long', ['pointer', 'pointer']));

    } else {
        console.log("[!] JNI_OnLoad doesn't exist in library: " + lib_name)
    }
}

function qbdi_exec(ctx, lib_name, func_addr, func_sym, args, post_sync) {
            var mod = Process.getModuleByName(lib_name);
            // var mod_base = Module.getBaseAddress(lib_name);
            var mod_base = mod.base;
            var mod_end = mod_base.add(mod.size);

            // HINT: Initialize QBDI
            var vm = new VM();
            var state = vm.getGPRState();
            // HINT: synchronising the current CPU context with the QBDI one
            state.synchronizeContext(ctx, SyncDirection.FRIDA_TO_QBDI);
            var stack = vm.allocateVirtualStack(state, STACK_SIZE);
            // var ret = vm.addInstrumentedModuleFromAddr(func_addr);
            // HINT: defining the so's address space as an instrumented range
            console.log(`instrument range: ${mod_base} -- ${mod_end}`);
            vm.addInstrumentedRange(mod_base, mod_end);

            // HINT: declaring a callback which will be called before each instruction
            var insthook_call = vm.newInstCallback(function(vm, gpr, fpr, data) {
                var inst = vm.getInstAnalysis();
                if (inst.mnemonic.search("BLR")){
                    return VMAction.CONTINUE;
                }
                // gpr.dump(); // Display context
                console.log('ins '+ptr(inst.address).sub(mod_base) + " " + inst.disassembly);
                // !TODO
                // if (ptr(inst.address).sub(mod_base).equals(ptr(0x9b1b4))) {
                    // RegisterNatives
                    /*else if (Process.arch === 'arm64') {
                    var GPR_NAMES_ = ["X0","X1","X2","X3","X4","X5","X6","X7","X8","X9","X10","X11","X12","X13","X14","X15","X16","X17","X18","X19","X20","X21","X22","X23","X24","X25","X26","X27","X28","FP","LR","SP","NZCV","PC"];
                    var REG_RETURN_ = "X0";
                    var REG_PC_ = "PC";
                    var REG_SP_ = "SP";
                    */
                    // var x2_val = gpr.getRegister("X2");
                    // console.log(`X2:${x2_val} -> ${lib_name}@${ptr(x2_val).sub(mod_base)}`);
                // }
                return VMAction.CONTINUE;
            });
            var iid = vm.addCodeCB(InstPosition.PREINST, insthook_call);

            var vmcallhook = vm.newVMCallback(function(vm, evt, gpr, fpr, data) {
                // typeof(evt) == VMEvent;
                var mod = Process.getModuleByAddress(evt.basicBlockStart);
                var offset = ptr(evt.basicBlockStart - mod.base);
                if(evt.event & VMEvent.EXEC_TRANSFER_CALL) {
                    console.warn(`-> transfer call to ${ptr(evt.basicBlockStart)} (${mod.name}@${offset})`);
                } else if (evt.event & VMEvent.EXEC_TRANSFER_RETURN) {
                    console.warn(`-> transfer return from ${ptr(evt.basicBlockStart)} (${mod.name}@${offset})`);
                }
                return VMAction.CONTINUE;
            });
            var vid_1 = vm.addVMEventCB(VMEvent.EXEC_TRANSFER_CALL, vmcallhook);
            var vid_2 = vm.addVMEventCB(VMEvent.EXEC_TRANSFER_RETURN, vmcallhook);

            var arg_vm = ptr(args[0]);
            var arg_reserved = ptr(args[1]);
            console.log(`[+] Executing through QBDI`);
            var retval = vm.call(func_addr, [arg_vm, arg_reserved]);
            // vm.alignedFree(stack);
            console.log(`[+] retval:${retval}`);

            // if(post_sync) {
            //     state.synchronizeContext(ctx, SyncDirection.QBDI_TO_FRIDA);
            // }
            return retval.toInt32();
}

load_lib("libnative-lib.so")

// var linkermodule = Process.getModuleByName("linker64");
// var call_function = null;
// var symbols = linkermodule.enumerateSymbols();
// for(var i=0; i<symbols.length; i++){
//     var symbol = symbols[i];
//     // !TODO
//     if(symbol.name.indexOf("__dl__ZL13call_functionPKcPFviPPcS2_ES0_") != -1) {
//         call_function = symbol.address;
//         console.log("linker64 call_function @ " + call_function);
//     }
// }

// var IS_HOOKED = false;

// Interceptor.attach(call_function, {
//     onEnter: function(args) {
//         var type = ptr(args[0]).readUtf8String();
//         var address = args[1];
//         var sopath = ptr(args[2]).readUtf8String();
//         // console.log("loadso:" + sopath + "--addr:" + address + "--type:" + type);
//         if (sopath.indexOf("libnative-lib.so") != -1 && (IS_HOOKED == false)) {
//             var libnativemodule = Process.getModuleByName("libnative-lib.so");
//             qbdi_hook_jni_onload();
//         }
//     }
// })

// function qbdi_hook_jni_onload() {
//     IS_HOOKED = true;
//     // var mod_base = Module.findBaseAddress("libnative-lib.so");
//     var mod = Process.getModuleByName("libnative-lib.so");
//     var mod_base = mod.base;
//     var mod_end = mod_base + mod.size;
//     var funcPtr = Module.findExportByName("libnative-lib.so", "JNI_OnLoad");
//     if (!funcPtr) {
//         funcPtr = DebugSymbol.fromName("JNI_OnLoad").address;
//     }
//     if (!funcPtr) {
//         base_native_lib = Module.getBaseAddress("libnative-lib.so")
//         funcPtr = ptr(base_native_lib).add(0x9AC2C)
//     }
//     console.log("JNI_OnLoad:"+funcPtr);
//     Interceptor.replace(
//         funcPtr, new NativeCallback(function(arg_vm, arg_reserved){
//             Interceptor.revert(funcPtr);    // revert to the genuine implementation
//             Interceptor.flush();
            
//             // HINT: Initialize QBDI
//             var vm = new VM();
//             var state = vm.getGPRState();
//             var stack = vm.allocateVirtualStack(state, 0x1000000);
//             // var ret = vm.addInstrumentedModuleFromAddr(funcPtr);
//             // HINT: defining the so's address space as an instrumented range
//             vm.addInstrumentedRange(mod_base, mod_end);

//             // HINT: declaring a callback which will be called before each instruction
//             var insthook_call = vm.newInstCallback(function(vm, gpr, fpr, data) {
//                 var inst = vm.getInstAnalysis();
//                 if (inst.mnemonic.search("BLR")){
//                     return VMAction.CONTINUE;
//                 }
//                 gpr.dump(); // Display context
//                 console.log('ins '+ptr(inst.address).sub(mod_base) + " " + inst.disassembly);
//                 return VMAction.CONTINUE;
//             });
//             var iid = vm.addCodeCB(InstPosition.PREINST, insthook_call);

//             // HINT: synchronising the current CPU context with the QBDI one

//             var retval = vm.call(funcPtr, [arg_vm, arg_reserved]);
//             // vm.alignedFree(stack);
//             console.log(retval);
//             return retval.toInt32();
//         }, 'int', ['pointer', 'pointer'])
//     )
// }

