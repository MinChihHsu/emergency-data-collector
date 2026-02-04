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

    logInfo("Frida PS Call blocker script started");

    // Start periodic alive message
    var aliveInterval = setInterval(function() {
        logInfo("ps-call-blocker is alive and wait.");
    }, 1000); // Every 1 second
    
    try {
        // Get the CallSessionAdaptor class
        var CallSessionAdaptor = Java.use("com.shannon.imsservice.network.adaptor.CallSessionAdaptor");
        
        // Hook the sendDial method with three parameters
        CallSessionAdaptor.sendDial.overload('java.lang.String', 'android.telephony.ims.ImsCallProfile', 'java.lang.String').implementation = function(str, imsCallProfile, str2) {

            // Output to logcat
            logInfo("Outgoing PS call blocked!");
            logInfo("Phone Number: " + str);

            var timestamp = getTimestamp();
            // Output to console
            console.log(timestamp + " [!] ===== BLOCKED: CallSessionAdaptor.sendDial() =====");
            console.log(timestamp + " [!] Phone Number: " + str);
            console.log(timestamp + " [!] ImsCallProfile: " + imsCallProfile);
            console.log(timestamp + " [!] Emergency URN: " + str2);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            
            // Do nothing - void the function
            // The original method is not called, so no dial request will be sent to the network
            return;
        };

        logInfo("Successfully hooked CallSessionAdaptor.sendDial() - ready to block PS calls");        
        console.log(getTimestamp() + " [+] Successfully hooked CallSessionAdaptor.sendDial()");
        console.log(getTimestamp() + " [+] Dial requests will be blocked at network adaptor level");
        reportReady("pixel9_void_callsessionadaptor");
        
    } catch(e) {
        logInfo("Failed to hook CallSessionAdaptor.sendDial(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook CallSessionAdaptor.sendDial(): " + e);
        console.log(getTimestamp() + " [-] Error details: " + e.stack);
        reportError("pixel9_void_callsessionadaptor", e);
        
        // Clear the alive interval if hook failed
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }
});

