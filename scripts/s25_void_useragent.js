Java.perform(function() {
    console.log("[*] Starting Frida script to hook UserAgent.makeCall()...");
    
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
            console.log("[!] ===== UserAgent.makeCall() INTERCEPTED =====");
            console.log("[!] Destination URI: " + destUri);
            console.log("[!] Origin URI: " + origUri);
            console.log("[!] Call Type: " + type);
            console.log("[!] Dialed Number: " + dialedNumber);
            console.log("[!] Emergency Info: " + pEmergencyInfo);
            console.log("[!] CLI: " + cli);
            console.log("[!] Display Name: " + dispName);
            console.log("[!] Is LTE EPS Only: " + isLteEpsOnlyAttached);
            console.log("[!] Timestamp: " + new Date().toISOString());
            console.log("[!] Method VOIDED - not calling original implementation");
            
            // Do nothing - void the function
            // The original method is not called, so no call will be made
            return;
        };
        
        console.log("[+] Successfully hooked UserAgent.makeCall()");
        console.log("[+] Calls will be blocked at UserAgent level");
        
    } catch(e) {
        console.log("[-] Failed to hook UserAgent.makeCall(): " + e);
        console.log("[-] Error details: " + e.stack);
    }
});
