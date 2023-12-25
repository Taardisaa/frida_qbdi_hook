## frida_qbdi_hook

a simple project that uses Frida+QBDI to do tricks like JNI_OnLoad tracing on Android(AArch64).

Prequisitories:

1. an Android device(physical)
2. libQBDI.so compiled and pushed into /data/local/tmp/
3. `setenforce 0` through adb shell in superuser
4. installing frida script development env for easier scripting: https://github.com/oleavr/frida-agent-example
5. frida

Currently working on: 

* hook_JNI_OnLoad.js: a script that instruments QBDI to trace JNI_OnLoad. Still quite unstable right now, not sure whether it's facing anti-frida tricks or wrong scripting.

Usage:

1. open frida-server in the Android device through adb shell superuser
2. `frida-compile <script.js> -o <script_compiled.js>`
3. `frida -U -f <package_name> -l <script_compiled.js>`
