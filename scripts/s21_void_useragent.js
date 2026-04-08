Java.perform(function () {
    var Log = Java.use("android.util.Log");
    var TAG = "frida-ps-call-blocker";

    function logInfo(message) { Log.i(TAG, message); }

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

    function reportReady(id) { console.log("FRIDA_READY:" + id); }
    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }

    // ── Fix: set writable cache dir for Java.registerClass() ──────
    try {
        var File = Java.use("java.io.File");
        var cacheDir = File.$new("/data/local/tmp");
        Java.classFactory.cacheDir = cacheDir;
        console.log(getTimestamp() + " [INIT] classFactory.cacheDir set to /data/local/tmp");
        logInfo("classFactory.cacheDir set to /data/local/tmp");
    } catch (eCacheDir) {
        console.log(getTimestamp() + " [INIT] Warning: failed to set cacheDir: " + eCacheDir);
        logInfo("Warning: failed to set cacheDir: " + eCacheDir);
    }

    logInfo("Frida PS Call blocker script started");

    var aliveInterval = setInterval(function() {
        logInfo("ps-call-blocker is alive and wait.");
    }, 1000);

    // ── Hook: UserAgent.makeCall() ─────────────────────────────────
    try {
        var UserAgent = Java.use("com.sec.internal.ims.core.handler.secims.UserAgent");

        UserAgent.makeCall.overload(
            'java.lang.String', 'java.lang.String', 'int', 'java.lang.String',
            'java.lang.String',
            'com.sec.internal.ims.core.handler.secims.imsCommonStruc.AdditionalContents',
            'java.lang.String', 'java.lang.String', 'java.util.HashMap',
            'java.lang.String', 'boolean', 'java.util.List', 'int',
            'android.os.Bundle', 'java.lang.String', 'int', 'java.lang.String',
            'android.os.Message'
        ).implementation = function (destUri, origUri, type, dispName, dialedNumber,
            additionalContents, cli, pEmergencyInfo, additionalSipHeaders,
            alertInfo, isLteEpsOnlyAttached, p2p, cmcBoundSessionId,
            composerData, replaceCallId, cmcEdCallSlot,
            isGeolocReqForNormalCall, idcExtra, cmcCallComposerData, message) {

            logInfo("Outgoing PS call blocked!");
            logInfo("Phone Number: " + destUri);

            var timestamp = getTimestamp();
            console.log(timestamp + " [!] ===== BLOCKED: UserAgent.makeCall() =====");
            console.log(timestamp + " [!] Destination URI: " + destUri);
            console.log(timestamp + " [!] Origin URI: " + origUri);
            console.log(timestamp + " [!] Call Type: " + type);
            console.log(timestamp + " [!] Dialed Number: " + dialedNumber);
            console.log(timestamp + " [!] Emergency Info: " + pEmergencyInfo);
            console.log(timestamp + " [!] Is LTE EPS Only: " + isLteEpsOnlyAttached);
            console.log("[+] Call blocked - voided");

            return;
        };

        logInfo("Successfully hooked UserAgent.makeCall() - ready to block PS calls");
        console.log("[+] Successfully hooked UserAgent.makeCall()");
        reportReady("s21_void_useragent");

    } catch (e) {
        logInfo("Failed to hook UserAgent.makeCall(): " + e);
        console.log("[-] Failed to hook UserAgent.makeCall(): " + e);
        console.log("[-] Error details: " + e.stack);
        reportError("s21_void_useragent", e);

        if (aliveInterval) {
            clearInterval(aliveInterval);
        }
    }

});

