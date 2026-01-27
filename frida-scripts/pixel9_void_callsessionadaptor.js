Java.perform(function() {
    // Get Android Log class for logcat output
    var Log = Java.use("android.util.Log");
    var TAG = "frida-ps-call-blocker";
    
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

    // Helper function to output debug log to logcat
    function logDebug(message) {
        Log.d(TAG, message);
    }

    console.log(getTimestamp() + " [*] Starting Frida script to hook CallSessionAdaptor.sendDial()...");
    logDebug("Frida PS Call blocker script started");
    
    // Start periodic alive message
    var aliveInterval = setInterval(function() {
        logDebug("ps-call-blocker is alive and wait.");
    }, 1000); // Every 1 second
    
    try {
        // Get the CallSessionAdaptor class
        var CallSessionAdaptor = Java.use("com.shannon.imsservice.network.adaptor.CallSessionAdaptor");
        
        // Hook the sendDial method with three parameters
        CallSessionAdaptor.sendDial.overload('java.lang.String', 'android.telephony.ims.ImsCallProfile', 'java.lang.String').implementation = function(str, imsCallProfile, str2) {
            var timestamp = getTimestamp();
            
            // Output to console
            console.log(timestamp + " [!] ===== CallSessionAdaptor.sendDial() INTERCEPTED =====");
            console.log(timestamp + " [!] Phone Number: " + str);
            console.log(timestamp + " [!] ImsCallProfile: " + imsCallProfile);
            console.log(timestamp + " [!] Emergency URN: " + str2);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            // Output to logcat
            logDebug("Outgoing PS call blocked!");
            logDebug("Phone Number: " + str);
            logDebug("Emergency URN: " + str2);
            
            // Do nothing - void the function
            // The original method is not called, so no dial request will be sent to the network
            return;
        };
        
        console.log(getTimestamp() + " [+] Successfully hooked CallSessionAdaptor.sendDial()");
        console.log(getTimestamp() + " [+] Dial requests will be blocked at network adaptor level");
        logDebug("Successfully hooked CallSessionAdaptor.sendDial() - ready to block PS calls");
        
    } catch(e) {
        console.log(getTimestamp() + " [-] Failed to hook CallSessionAdaptor.sendDial(): " + e);
        console.log(getTimestamp() + " [-] Error details: " + e.stack);
        logDebug("Failed to hook CallSessionAdaptor.sendDial(): " + e);
        
        // Clear the alive interval if hook failed
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }
});

