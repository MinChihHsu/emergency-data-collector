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
        
        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }

    // // -------------------------------------------------------------------------
    // // Strategy 1: Trigger Emergency PDN registration directly
    // // -------------------------------------------------------------------------
    // function triggerEmergencyPdn(slotId) {
    //     var ts = getTimestamp();
    //     logInfo("triggerEmergencyPdn() called for slotId=" + slotId);
    //     console.log(ts + " [EMC] ===== triggerEmergencyPdn() START =====");

    //     // ✅ Fixed: conn.ApnNetType (was apn.ApnNetType)
    //     var ApnNetType = Java.use("com.shannon.imsservice.conn.ApnNetType");

    //     // ✅ Fixed: conn.rule.ConnectivityRuleMgr (was connectivity.ConnectivityRuleMgr)
    //     var cellConnFound = null;
    //     Java.choose("com.shannon.imsservice.conn.rule.ConnectivityRuleMgr", {
    //         onMatch: function(ruleMgr) {
    //             try {
    //                 var rid = ruleMgr.mSlotId ? ruleMgr.mSlotId.value : -1;
    //                 if (rid !== slotId) return;

    //                 cellConnFound = ruleMgr.getCellConnectivity();
    //                 console.log(getTimestamp() + " [EMC] CellConnectivity: " + cellConnFound);
    //                 logInfo("triggerEmergencyPdn: CellConnectivity found: " + cellConnFound);
    //             } catch(e) {
    //                 console.log(getTimestamp() + " [EMC] Error reading ConnectivityRuleMgr: " + e);
    //                 logInfo("triggerEmergencyPdn: ConnectivityRuleMgr error: " + e);
    //             }
    //         },
    //         onComplete: function() {
    //             if (!cellConnFound) {
    //                 console.log(getTimestamp() + " [EMC] ERROR: CellConnectivity not found — aborting");
    //                 logInfo("triggerEmergencyPdn: CellConnectivity not found, abort");
    //                 return;
    //             }

    //             // ✅ ApnManager path was already correct
    //             var apnManagerFound = false;
    //             Java.choose("com.shannon.imsservice.conn.ApnManager", {
    //                 onMatch: function(apnManager) {
    //                     try {
    //                         var amid = apnManager.mSlotId ? apnManager.mSlotId.value : -1;
    //                         if (amid !== slotId) return;
    //                         if (apnManagerFound) return;

    //                         apnManagerFound = true;

    //                         // Pre-flight: log current APN_EMERGENCY state
    //                         try {
    //                             var existingEntity = apnManager.mApns.value.get(ApnNetType.APN_EMERGENCY.value);
    //                             if (existingEntity !== null) {
    //                                 var castEntity = Java.cast(existingEntity,
    //                                     Java.use("com.shannon.imsservice.conn.ApnEntity"));
    //                                 console.log(getTimestamp() + " [EMC] Existing APN_EMERGENCY state: "
    //                                     + castEntity.getServiceState()
    //                                     + " isNetworkCallback=" + castEntity.isNetworkCallback());
    //                                 logInfo("triggerEmergencyPdn: existing APN_EMERGENCY state="
    //                                     + castEntity.getServiceState());
    //                             } else {
    //                                 console.log(getTimestamp() + " [EMC] No existing APN_EMERGENCY entity");
    //                                 logInfo("triggerEmergencyPdn: no existing APN_EMERGENCY entity");
    //                             }
    //                         } catch(e) {
    //                             console.log(getTimestamp() + " [EMC] Could not read existing ApnEntity: " + e);
    //                         }

    //                         console.log(getTimestamp() + " [EMC] Calling enableApn(APN_EMERGENCY) ...");
    //                         logInfo("triggerEmergencyPdn: calling enableApn(APN_EMERGENCY)");

    //                         var result = apnManager.enableApn(
    //                             ApnNetType.APN_EMERGENCY.value,
    //                             cellConnFound,
    //                             null
    //                         );

    //                         if (result !== null) {
    //                             console.log(getTimestamp() + " [EMC] enableApn returned ApnEntity: " + result
    //                                 + " → Emergency PDN request sent to modem ✓");
    //                             logInfo("triggerEmergencyPdn: enableApn OK, ApnEntity=" + result);
    //                         } else {
    //                             console.log(getTimestamp() + " [EMC] enableApn returned null"
    //                                 + " (PDN already active or isNetworkCallback guard hit)");
    //                             logInfo("triggerEmergencyPdn: enableApn returned null");
    //                         }

    //                     } catch(e) {
    //                         console.log(getTimestamp() + " [EMC] Error in enableApn call: " + e);
    //                         console.log(getTimestamp() + " [EMC] Stack: " + e.stack);
    //                         logInfo("triggerEmergencyPdn: enableApn error: " + e);
    //                     }
    //                 },
    //                 onComplete: function() {
    //                     if (!apnManagerFound) {
    //                         console.log(getTimestamp() + " [EMC] ERROR: ApnManager not found for slotId=" + slotId);
    //                         logInfo("triggerEmergencyPdn: ApnManager not found");
    //                     }
    //                     console.log(getTimestamp() + " [EMC] ===== triggerEmergencyPdn() END =====");
    //                     logInfo("triggerEmergencyPdn() END");
    //                 }
    //             });
    //         }
    //     });
    // }

    // setTimeout(function() {
    //     try {
    //         triggerEmergencyPdn(0);
    //     } catch(e) {
    //         console.log(getTimestamp() + " [EMC] Uncaught error in triggerEmergencyPdn: " + e);
    //         logInfo("triggerEmergencyPdn uncaught: " + e);
    //     }
    // }, 3000);

});

