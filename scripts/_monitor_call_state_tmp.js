var SCENARIO = 5;
// monitor_call_state.js
// SCENARIO is injected at the top of this file by frida_server.py before loading.
// Do NOT define SCENARIO here — it is prepended dynamically.

Java.perform(function() {
    var Log = Java.use("android.util.Log");
    var TAG = "frida-wifi-call-notifier";

    function logInfo(message) { Log.i(TAG, message); }
    function reportReady(id) { console.log("FRIDA_READY:" + id); }
    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }

    // SCENARIO is defined at file scope by the server-generated wrapper.
    // Sanity check + fallback only for direct manual invocation.
    var scenario = (typeof SCENARIO === 'number') ? SCENARIO : 3;

    logInfo("Frida WiFi Call monitor started, scenario=" + scenario);
    console.log("[*] monitor_call_state.js: scenario=" + scenario);

    var REASON_USER_TERMINATED = 501;

    try {
        var ImsPhoneCallTracker = Java.use(
            "com.android.internal.telephony.imsphone.ImsPhoneCallTracker"
        );
        var StateClass = "com.android.internal.telephony.Call$State";
        var ImsCall    = "com.android.ims.ImsCall";

        var isHangingUp = false;

        ImsPhoneCallTracker.processCallStateChange.overload(
            ImsCall, StateClass, 'int'
        ).implementation = function(imsCall, state, cause) {

            var stateStr = state.toString();

            if (scenario === 3) {
                // ── Scenario 3: terminate on ALERTING/DIALING ────────────────
                if ((stateStr.indexOf("ALERTING") > -1 ||
                     stateStr.indexOf("DIALING")  > -1) && !isHangingUp) {

                    isHangingUp = true;
                    logInfo("Scenario 3: state=" + stateStr + " → terminating");
                    console.log("[!!!] Scenario 3: terminating call on " + stateStr);
                    console.log("[!] ===== BLOCKED: WiFi Calling state=" + stateStr + " =====");

                    try {
                        imsCall.terminate(REASON_USER_TERMINATED, REASON_USER_TERMINATED);
                        console.log("[V] imsCall.terminate(501) executed.");
                    } catch(e) {
                        console.log("[X] terminate failed: " + e);
                        try { imsCall.close(); } catch(_) {}
                    }

                } else if (stateStr.indexOf("DISCONNECTED") > -1) {
                    console.log("[*] Scenario 3: DISCONNECTED → reset flag");
                    isHangingUp = false;
                }

            } else {
                // ── Scenario 5: wait for ACTIVE/CONNECTED ────────────────────
                if ((stateStr.indexOf("ACTIVE")    > -1 ||
                     stateStr.indexOf("CONNECTED") > -1) && !isHangingUp) {

                    isHangingUp = true;
                    logInfo("Scenario 5: call ACTIVE/CONNECTED");
                    console.log("[!!!] Scenario 5: call answered!");
                    console.log("[!] ===== CALL_CONNECTED: state=" + stateStr + " =====");

                } else if (stateStr.indexOf("DISCONNECTED") > -1) {
                    console.log("[*] Scenario 5: DISCONNECTED → reset flag");
                    isHangingUp = false;
                }
            }

            this.processCallStateChange(imsCall, state, cause);
        };

        logInfo("Hook ready (scenario=" + scenario + ")");
        reportReady("wifi_call_monitoring");

        setInterval(function() {
            logInfo("wifi-call-notifier alive, scenario=" + scenario);
        }, 5000);

    } catch(e) {
        reportError("wifi_call_monitoring", e);
    }
});
