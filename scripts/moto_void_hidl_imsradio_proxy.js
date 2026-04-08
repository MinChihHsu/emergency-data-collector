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

    logInfo("Frida PS Call blocker script started (HIDL IImsRadio Proxy)");

    // Start periodic alive message
    var aliveInterval = setInterval(function() {
        logInfo("ps-call-blocker is alive and wait.");
    }, 1000); // Every 1 second
    
    var hookedCount = 0;
    
    // Hook V1_6.IImsRadio$Proxy.dial_1_6
    try {
        var IImsRadioProxy_V1_6 = Java.use("vendor.qti.hardware.radio.ims.V1_6.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_6.dial_1_6.implementation = function(token, dialRequest) {
            logInfo("Outgoing PS call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.6 dial_1_6");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.6 dial_1_6() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.6 dial_1_6()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.6 dial_1_6()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.6 dial_1_6(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.6 dial_1_6(): " + e);
    }
    
    // Hook V1_6.IImsRadio$Proxy.emergencyDial_1_6
    try {
        var IImsRadioProxy_V1_6 = Java.use("vendor.qti.hardware.radio.ims.V1_6.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_6.emergencyDial_1_6.implementation = function(token, dialRequest, categories, urns, routing, hasKnownUserIntentEmergency, isTesting) {
            logInfo("Outgoing emergency call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.6 emergencyDial_1_6");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.6 emergencyDial_1_6() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Categories: " + categories);
            console.log(timestamp + " [!] URNs: " + urns);
            console.log(timestamp + " [!] Routing: " + routing);
            console.log(timestamp + " [!] HasKnownUserIntentEmergency: " + hasKnownUserIntentEmergency);
            console.log(timestamp + " [!] IsTesting: " + isTesting);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.6 emergencyDial_1_6()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.6 emergencyDial_1_6()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.6 emergencyDial_1_6(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.6 emergencyDial_1_6(): " + e);
    }
    
    // Hook V1_8.IImsRadio$Proxy.dial_1_6 (if exists)
    try {
        var IImsRadioProxy_V1_8 = Java.use("vendor.qti.hardware.radio.ims.V1_8.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_8.dial_1_6.implementation = function(token, dialRequest) {
            logInfo("Outgoing PS call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.8 dial_1_6");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.8 dial_1_6() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.8 dial_1_6()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.8 dial_1_6()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.8 dial_1_6(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.8 dial_1_6(): " + e);
    }
    
    // Hook V1_7.IImsRadio$Proxy.dial_1_6 (if exists)
    try {
        var IImsRadioProxy_V1_7 = Java.use("vendor.qti.hardware.radio.ims.V1_7.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_7.dial_1_6.implementation = function(token, dialRequest) {
            logInfo("Outgoing PS call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.7 dial_1_6");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.7 dial_1_6() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.7 dial_1_6()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.7 dial_1_6()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.7 dial_1_6(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.7 dial_1_6(): " + e);
    }
    
    // Hook V1_5.IImsRadio$Proxy.emergencyDial (if exists)
    try {
        var IImsRadioProxy_V1_5 = Java.use("vendor.qti.hardware.radio.ims.V1_5.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_5.emergencyDial.implementation = function(token, dialRequest, categories, urns, routing, hasKnownUserIntentEmergency, isTesting) {
            logInfo("Outgoing emergency call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.5 emergencyDial");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.5 emergencyDial() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Categories: " + categories);
            console.log(timestamp + " [!] URNs: " + urns);
            console.log(timestamp + " [!] Routing: " + routing);
            console.log(timestamp + " [!] HasKnownUserIntentEmergency: " + hasKnownUserIntentEmergency);
            console.log(timestamp + " [!] IsTesting: " + isTesting);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.5 emergencyDial()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.5 emergencyDial()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.5 emergencyDial(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.5 emergencyDial(): " + e);
    }
    
    // Hook V1_4.IImsRadio$Proxy.dial_1_4 (if exists)
    try {
        var IImsRadioProxy_V1_4 = Java.use("vendor.qti.hardware.radio.ims.V1_4.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_4.dial_1_4.implementation = function(token, dialRequest) {
            logInfo("Outgoing PS call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.4 dial_1_4");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.4 dial_1_4() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.4 dial_1_4()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.4 dial_1_4()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.4 dial_1_4(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.4 dial_1_4(): " + e);
    }
    
    // Hook V1_0.IImsRadio$Proxy.dial (if exists)
    try {
        var IImsRadioProxy_V1_0 = Java.use("vendor.qti.hardware.radio.ims.V1_0.IImsRadio$Proxy");
        
        IImsRadioProxy_V1_0.dial.implementation = function(token, dialRequest) {
            logInfo("Outgoing PS call blocked!");
            logInfo("Method: IImsRadio$Proxy V1.0 dial");
            
            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: IImsRadio$Proxy V1.0 dial() =====");
            console.log(timestamp + " [!] Token: " + token);
            console.log(timestamp + " [!] DialRequest: " + dialRequest);
            console.log(timestamp + " [!] Method VOIDED - not calling original implementation");
            
            return;
        };
        
        logInfo("Successfully hooked IImsRadio$Proxy V1.0 dial()");
        console.log(getTimestamp() + " [+] Successfully hooked IImsRadio$Proxy V1.0 dial()");
        hookedCount++;
    } catch(e) {
        logInfo("Failed to hook IImsRadio$Proxy V1.0 dial(): " + e);
        console.log(getTimestamp() + " [-] Failed to hook IImsRadio$Proxy V1.0 dial(): " + e);
    }
    
    // Final report
    if (hookedCount > 0) {
        logInfo("Successfully hooked " + hookedCount + " method(s) - ready to block PS calls");
        console.log(getTimestamp() + " [+] Successfully hooked " + hookedCount + " HIDL IImsRadio$Proxy method(s)");
        console.log(getTimestamp() + " [+] Dial requests will be blocked at HIDL Proxy level");
        reportReady("moto_void_hidl_imsradio_proxy");
    } else {
        logInfo("Failed to hook any IImsRadio$Proxy methods");
        console.log(getTimestamp() + " [-] Failed to hook any IImsRadio$Proxy methods");
        reportError("moto_void_hidl_imsradio_proxy", new Error("No methods hooked"));
        
        // Clear the alive interval if all hooks failed
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }
});

