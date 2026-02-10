Java.perform(function() {
    console.log("[*] Hooking ImsPhoneCallTracker.processCallStateChange...");
    // Get Android Log class for logcat output
    var Log = Java.use("android.util.Log");
    var TAG = "frida-wifi-call-notifier";

    // Helper function to output debug log to logcat
    function logInfo(message) {
        Log.i(TAG, message);
    }

    function reportReady(id) {
        console.log("FRIDA_READY:" + id);
    }

    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }

    logInfo("Frida WiFi Call notifier script started");

    try {
        var ImsPhoneCallTracker = Java.use("com.android.internal.telephony.imsphone.ImsPhoneCallTracker");
        var StateClass = "com.android.internal.telephony.Call$State";
        var ImsCall = "com.android.ims.ImsCall";

        // 用來防止短時間內重複執行掛斷
        var isHangingUp = false;

        // IMS Reason Codes
        var REASON_USER_TERMINATED = 501;

        ImsPhoneCallTracker.processCallStateChange.overload(
            ImsCall,
            StateClass,
            'int'
        ).implementation = function(imsCall, state, cause) {

            var stateStr = state.toString();

            // 偵測 ALERTING (Ringing / Session Progress)
            if (stateStr.indexOf("ALERTING") > -1) {

                if (!isHangingUp) {
                    // Output to logcat
                    logInfo("Outgoing WiFi call state changed to ALERTING!");
                    console.log("[!!!] ALERTING detected! Initiating IMMEDIATE terminate...");
                    console.log("[!] ===== BLOCKED: WiFi Calling state changed to ALERTING =====");
                    isHangingUp = true;

                    try {
                        imsCall.terminate(REASON_USER_TERMINATED, REASON_USER_TERMINATED);
                        console.log("[V] SUCCESS: imsCall.terminate(501) executed.");
                    } catch (e) {
                        console.log("[X] terminate failed: " + e);

                        try {
                            imsCall.close();
                            console.log("[?] fallback to imsCall.close()");
                        } catch(e2) {
                            // ignore
                        }
                    }
                } else {
                    console.log("[i] Skipping duplicate ALERTING event (already hanging up).");
                }
            } else if (stateStr.indexOf("DISCONNECTED") > -1) {
                console.log("[*] Call Disconnected. Resetting hangup flag.");
                isHangingUp = false;
            }

            // 務必執行原始方法，維持系統運作
            this.processCallStateChange(imsCall, state, cause);
        };

        // ✅ 修正：reportReady 應該在 hook 成功後立即呼叫
        logInfo("Successfully hooked ImsPhoneCallTracker.processCallStateChange() - ready to monitor WiFi calls");
        reportReady("wifi_call_monitoring");

        // Start periodic alive message
        var aliveInterval = setInterval(function() {
            logInfo("wifi-call-notifier is alive and waiting.");
        }, 1000); // Every 1 seconds

    } catch (e) {
        reportError("wifi_call_monitoring", e);
    }
});
