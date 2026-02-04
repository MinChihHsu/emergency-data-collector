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
        // Get the UserAgent class
        var UserAgent = Java.use("com.sec.internal.ims.core.handler.secims.UserAgent");
        
        // Hook the makeCall method with the CORRECT parameter types
        UserAgent.makeCall.overload(
            'java.lang.String',
            'java.lang.String',
            'int',
            'java.lang.String',
            'java.lang.String',
            'com.sec.internal.ims.core.handler.secims.imsCommonStruc.AdditionalContents',  // CORRECTED
            'java.lang.String',
            'java.lang.String',
            'java.util.HashMap',
            'java.lang.String',
            'boolean',
            'java.util.List',
            'int',
            'android.os.Bundle',
            'java.lang.String',
            'int',
            'boolean',
            'java.lang.String',
            'java.lang.String',
            'android.os.Message'
        ).implementation = function(destUri, origUri, type, dispName, dialedNumber, additionalContents, 
            cli, pEmergencyInfo, additionalSipHeaders, alertInfo, 
            isLteEpsOnlyAttached, p2p, cmcBoundSessionId, composerData, 
            replaceCallId, cmcEdCallSlot, isGeolocReqForNormalCall, 
            idcExtra, cmcCallComposerData, message) {

                // Output to logcat
                logInfo("Outgoing PS call blocked!");
                logInfo("Phone Number: " + destUri);
                
                var timestamp = getTimestamp();
            
                console.log(timestamp + "[!] ===== BLOCKED: UserAgent.makeCall() =====");
                console.log(timestamp + "[!] Destination URI: " + destUri);
                console.log(timestamp + "[!] Origin URI: " + origUri);
                console.log(timestamp + "[!] Call Type: " + type);
                console.log(timestamp + "[!] Dialed Number: " + dialedNumber);
                console.log(timestamp + "[!] Emergency Info: " + pEmergencyInfo);
                console.log(timestamp + "[!] CLI: " + cli);
                console.log(timestamp + "[!] Display Name: " + dispName);
                console.log(timestamp + "[!] Is LTE EPS Only: " + isLteEpsOnlyAttached);
                console.log("[!] Method VOIDED - not calling original implementation");
                
                // Do nothing - void the function
                // The original method is not called, so no call will be made
                return;
            };
        
        logInfo("Successfully hooked UserAgent.makeCall() - ready to block PS calls");
        console.log("[+] Successfully hooked UserAgent.makeCall()");
        console.log("[+] Calls will be blocked at UserAgent level");
        reportReady("s25_void_useragent");
        
    } catch(e) {
        logInfo("Failed to hook UserAgent.makeCall(): " + e);
        console.log("[-] Failed to hook UserAgent.makeCall(): " + e);
        console.log("[-] Error details: " + e.stack);
        reportError("s25_void_useragent", e);

        // Clear the alive interval if hook failed
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }
});
