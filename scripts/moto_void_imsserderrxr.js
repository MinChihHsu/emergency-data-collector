Java.perform(function() {
    // Get Android Log class for logcat output
    var Log = Java.use("android.util.Log");
    var TAG = "frida-ps-call-blocker";
    
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

    logInfo("Frida PS Call blocker script started (Motorola)");

    // Start periodic alive message
    var aliveInterval = setInterval(function() {
        logInfo("ps-call-blocker is alive and wait.");
    }, 1000); // Every 1 second
    
    try {
        // Get the ImsSenderRxr class
        var ImsSenderRxr = Java.use("org.codeaurora.ims.ImsSenderRxr");
        
        // Hook the dial method - 8 parameters version
        ImsSenderRxr.dial.overload(
            'java.lang.String',                           // address
            'org.codeaurora.ims.EmergencyCallInfo',       // eInfo
            'int',                                         // clirMode
            'org.codeaurora.ims.CallDetails',             // callDetails
            'boolean',                                     // isEncrypted
            'org.codeaurora.ims.CallComposerInfo',        // ccInfo
            'org.codeaurora.ims.RedialInfo',              // redialInfo
            'android.os.Message'                          // result
        ).implementation = function(address, eInfo, clirMode, callDetails, isEncrypted, ccInfo, redialInfo, result) {

            // Output to logcat
            logInfo("Outgoing PS call blocked!");
            logInfo("Phone Number: " + address);

            var timestamp = getTimestamp();
            // Output to console
            console.log(timestamp + " [!] ===== BLOCKED: ImsSenderRxr.dial() =====");
            console.log(timestamp + " [!] Phone Number: " + address);
            console.log(timestamp + " [!] EmergencyCallInfo: " + eInfo);
            console.log(timestamp + " [!] CLIR Mode: " + clirMode);
            console.log(timestamp + " [!] CallDetails: " + callDetails);
            console.log(timestamp + " [!] Is Encrypted: " + isEncrypted);
            console.log(timestamp + " [!] CallComposerInfo: " + ccInfo);
            console.log(timestamp + " [!] RedialInfo: " + redialInfo);
            console.log(timestamp + " [!] Message: " + result);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            // Do nothing - void the function
            return;
        };

        logInfo("Successfully hooked ImsSenderRxr.dial() - ready to block PS calls");        
        console.log(getTimestamp() + " [+] Successfully hooked ImsSenderRxr.dial()");
        console.log(getTimestamp() + " [+] Dial requests will be blocked at network adaptor level");
        reportReady("moto_void_imssenderrxr");
        
    } catch(e) {
        logInfo("Failed to hook ImsSenderRxr.dial(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook ImsSenderRxr.dial(): " + e);
        console.log(getTimestamp() + " [-] Error details: " + e.stack);
        reportError("moto_void_imssenderrxr", e);
        
        // Clear the alive interval if hook failed
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }
});

