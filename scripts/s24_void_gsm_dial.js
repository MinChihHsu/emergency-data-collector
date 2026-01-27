Java.perform(function() {
    console.log("[*] Searching for CommandsInterface implementation via ClassLoaders...");
    
    function reportReady(id) {
        console.log("FRIDA_READY:" + id);
    }

    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }


    var foundImplementation = false;
    
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                // Try to find CommandsInterface in this loader
                if (loader.findClass("com.android.internal.telephony.CommandsInterface")) {
                    console.log("[+] Found CommandsInterface in loader: " + loader);
                    
                    // Now search for implementation classes
                    var implClasses = [
                        "com.android.internal.telephony.RIL",
                        "com.android.internal.telephony.SimulatedCommands",
                        "com.android.internal.telephony.SimulatedCommandsVerifier"
                    ];
                    
                    implClasses.forEach(function(implClassName) {
                        try {
                            if (loader.findClass(implClassName)) {
                                console.log("[+] Found implementation: " + implClassName);
                                
                                // Set this loader as the default
                                Java.classFactory.loader = loader;
                                
                                // Now hook the implementation
                                hookDialMethods(implClassName);
                                foundImplementation = true;
                            }
                        } catch(e) {
                            // Class not in this loader
                        }
                    });
                }
            } catch(e) {
                // Interface not in this loader
            }
        },
        onComplete: function() {
            if (!foundImplementation) {
                console.log("[-] No CommandsInterface implementation found");
                reportError("s24_void_gsm_dial", "CommandsInterface implementation not found");

            } else {
                console.log("[+] Successfully hooked CommandsInterface implementations");
                reportReady("s24_void_gsm_dial");
            }
        }
    });
    
    function hookDialMethods(className) {
        try {
            var ImplClass = Java.use(className);
            
            console.log("[*] Hooking dial() methods in: " + className);
            
            // Hook all dial overloads
            ImplClass.dial.overloads.forEach(function(overload, idx) {
                console.log("[*] Hooking overload #" + idx + " with " + overload.argumentTypes.length + " params");
                
                overload.implementation = function() {
                    console.log("[!] ===== BLOCKED: " + className + ".dial() overload #" + idx + " =====");
                    console.log("[!] Arguments: " + arguments.length);
                    
                    // Log important arguments
                    if (arguments.length > 0) console.log("[!] Address: " + arguments[0]);
                    if (arguments.length > 1) console.log("[!] Is Emergency: " + arguments[1]);
                    if (arguments.length > 2) console.log("[!] Emergency Info: " + arguments[2]);
                    
                    console.log("[+] Call blocked - voided");
                    
                    // Void the function
                    return;
                };
            });
            
            console.log("[+] Successfully hooked all dial() overloads in " + className);
            
        } catch(e) {
            console.log("[-] Failed to hook " + className + ": " + e);
        }
    }
});
