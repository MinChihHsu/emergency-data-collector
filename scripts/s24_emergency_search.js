Java.perform(function () {

    var ImsPhoneCallTracker = Java.use(
        "com.android.internal.telephony.imsphone.ImsPhoneCallTracker"
    );

    // ─── Block dialInternal (4-arg) ───
    ImsPhoneCallTracker["dialInternal"].overload(
        "com.android.internal.telephony.imsphone.ImsPhoneConnection",
        "int",
        "int",
        "android.os.Bundle"
    ).implementation = function (conn, clir, videoState, bundle) {
        var phoneId = this.mPhone.value.getPhoneId();
        console.log("[BLOCKED] dialInternal (4-arg) phoneId=" + phoneId);
    };

    // ─── Block dialInternal (6-arg) ───
    ImsPhoneCallTracker["dialInternal"].overload(
        "com.android.internal.telephony.imsphone.ImsPhoneConnection",
        "int",
        "int",
        "int",
        "int",
        "android.os.Bundle"
    ).implementation = function (conn, clir, videoState, retryFailCause, retryFailNetType, bundle) {
        var phoneId = this.mPhone.value.getPhoneId();
        console.log("[BLOCKED] dialInternal (6-arg) phoneId=" + phoneId);
    };

    // ─── Block redialToCs (ImsPhoneConnection + ImsReasonInfo) ───
    ImsPhoneCallTracker["redialToCs"].overload(
        "com.android.internal.telephony.imsphone.ImsPhoneConnection",
        "android.telephony.ims.ImsReasonInfo"
    ).implementation = function (conn, reasonInfo) {
        var phoneId = this.mPhone.value.getPhoneId();
        console.log("[BLOCKED] redialToCs (conn, reasonInfo) phoneId=" + phoneId);
    };

    // ─── Block redialToCs (ImsCall + ImsReasonInfo) ───
    try {
        ImsPhoneCallTracker["redialToCs"].overload(
            "com.android.ims.ImsCall",
            "android.telephony.ims.ImsReasonInfo"
        ).implementation = function (imsCall, reasonInfo) {
            var phoneId = this.mPhone.value.getPhoneId();
            console.log("[BLOCKED] redialToCs (imsCall, reasonInfo) phoneId=" + phoneId);
        };
    } catch (e) {
        console.log("[*] redialToCs (ImsCall, ImsReasonInfo) not found, skipping: " + e);
    }

    console.log("[*] All dialInternal and redialToCs hooks installed.");

    // ─── Log handleEmergencySearchResult ───
    ImsPhoneCallTracker["handleEmergencySearchResult"]
        .implementation = function (result, imsCall, reasonInfo) {
            var phoneId = this.mPhone.value.getPhoneId();
            var resultStr = {
                1: "CS_FALLBACK",
                2: "VoLTE",
                3: "VoNR",
                4: "NO_ROUTE",
                5: "IGNORE",
                6: "NR"
            }[result] || "UNKNOWN(" + result + ")";
            console.log("[*] handleEmergencySearchResult phoneId=" + phoneId
                + " result=" + resultStr);
            return this["handleEmergencySearchResult"](result, imsCall, reasonInfo);
        };

    // ─── Trigger emergencySearch，只對 phoneId == 0 ───
    setTimeout(function () {
        Java.choose("com.android.internal.telephony.imsphone.ImsPhoneCallTracker", {
            onMatch: function (tracker) {
                try {
                    var phone   = tracker.mPhone.value;
                    var phoneId = phone.getPhoneId();

                    // ── 只處理 SIM 1 ──
                    if (phoneId !== 0) {
                        console.log("[*] Skipping tracker phoneId=" + phoneId);
                        return;
                    }

                    console.log("[*] Found tracker phoneId=" + phoneId + " : " + tracker);

                    var Pair          = Java.use("android.util.Pair");
                    var ImsReasonInfo = Java.use("android.telephony.ims.ImsReasonInfo");
                    var reasonInfo    = ImsReasonInfo.$new(0, 0, "frida_trigger");
                    var pair          = Pair.$new(null, reasonInfo);

                    // EVENT_EMERGENCY_SEARCH_RESULT = 100
                    var msg = tracker.obtainMessage(100, pair);

                    var defaultPhone = phone.mDefaultPhone.value;
                    var semCi        = defaultPhone.mSemCi.value;

                    console.log("[*] phoneId=" + phoneId + " SemCi=" + semCi);
                    semCi.emergencySearch(msg);
                    console.log("[*] phoneId=" + phoneId
                        + " emergencySearch sent. Waiting for modem result...");

                } catch (e) {
                    console.log("[!] Error on tracker: " + e);
                }
            },
            onComplete: function () {
                console.log("[*] Java.choose complete.");
            }
        });
    }, 2000);

});

