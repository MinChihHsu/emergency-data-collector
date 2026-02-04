Java.perform(function() {
    // Get Android Log class for logcat output
    var Log = Java.use("android.util.Log");
    var TAG = "frida-cs-call-blocker";

    // Helper function to output debug log to logcat
    function logInfo(message) {
        Log.i(TAG, message);
    }
    
    // Timestamp helper function
    function getTimestamp() {
        var now = new Date();
        var month = String(now.getMonth() + 1).padStart(2, '0');
        var day = String(now.getDate()).padStart(2, '0');
        var hours = String(now.getHours()).padStart(2, '0');
        var minutes = String(now.getMinutes()).padStart(2, '0');
        var seconds = String(now.getSeconds()).padStart(2, '0');
        var milliseconds = String(now.getMilliseconds()).padStart(3, '0');
        return month + "-" + day + " " + hours + ":" + minutes + ":" + seconds + "." + milliseconds;
    }
    
    function reportReady(id) {
        console.log("FRIDA_READY:" + id);
    }

    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }

    logInfo("Frida CS call blocker script started");
    
    var foundImplementation = false;
    
    // Start periodic alive message
    var aliveInterval = setInterval(function() {
        logInfo("cs-call-blocker is alive and wait.");
    }, 1000); // Every 1 second
    
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
                logInfo("No CommandsInterface implementation found");
                console.log("[-] No CommandsInterface implementation found");
                reportError("pixel9_void_gsm_dial", "No CommandsInterface implementation found");
                
                // Clear the alive interval if no implementation found
                if (aliveInterval) {
                    clearInterval(aliveInterval);
                }
            } else {
                logInfo("Successfully hooked CommandsInterface implementations - ready to block CS calls");
                console.log("[+] Successfully hooked CommandsInterface implementations");
                reportReady("pixel9_void_gsm_dial");
            }
        }
    });
    
    function hookDialMethods(className) {
        try {
            var ImplClass = Java.use(className);
            
            logInfo("Hooking dial() methods in: " + className);
            console.log("[*] Hooking dial() methods in: " + className);
            
            // Hook all dial overloads
            ImplClass.dial.overloads.forEach(function(overload, idx) {
                console.log("[*] Hooking overload #" + idx + " with " + overload.argumentTypes.length + " params");
                
                overload.implementation = function() {
                    // Output to logcat
                    logInfo("Outgoing CS call blocked!");
                    if (arguments.length > 0) logInfo("Address: " + arguments[0]);
                    if (arguments.length > 1) logInfo("Is Emergency: " + arguments[1]);

                    var timestamp = getTimestamp();
                    
                    // Output to console
                    console.log(timestamp + " [!] ===== BLOCKED: " + className + ".dial() overload #" + idx + " =====");
                    console.log(timestamp + " [!] Arguments: " + arguments.length);
                    
                    // Log important arguments
                    if (arguments.length > 0) console.log(timestamp + " [!] Address: " + arguments[0]);
                    if (arguments.length > 1) console.log(timestamp + " [!] Is Emergency: " + arguments[1]);
                    if (arguments.length > 2) console.log(timestamp + " [!] Emergency Info: " + arguments[2]);
                    
                    console.log(timestamp + " [+] Call blocked - voided");
                    // Void the function
                    return;
                };
            });
            
            logInfo("Successfully hooked all dial() overloads in " + className);
            console.log("[+] Successfully hooked all dial() overloads in " + className);
        } catch(e) {
            logInfo("Failed to hook " + className + ": " + e);
            console.log("[-] Failed to hook " + className + ": " + e);
        }
    }
});

