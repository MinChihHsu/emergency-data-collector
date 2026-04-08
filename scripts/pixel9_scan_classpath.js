Java.scheduleOnMainThread(function() {

    Java.choose("com.sec.internal.ims.core.RegistrationManagerBase", {
        onMatch: function(rmBase) {
            try {
                console.log("[RM] Found: " + rmBase.getClass().getName());

                var phoneId = 0;

                var imsProfile = rmBase.getEmergencyProfile(phoneId);
                if (imsProfile == null) {
                    console.log("[RM] emergencyProfile is null, abort");
                    return;
                }
                console.log("[RM] emergencyProfile: " + imsProfile.toString());

                var getField = function(obj, fieldName) {
                    var cls = obj.getClass();
                    while (cls != null) {
                        try {
                            var f = cls.getDeclaredField(fieldName);
                            f.setAccessible(true);
                            return f.get(obj);
                        } catch(e) {
                            cls = cls.getSuperclass();
                        }
                    }
                    return null;
                };

                var mTelephonyManager = getField(rmBase, "mTelephonyManager");
                var mPdnController    = getField(rmBase, "mPdnController");
                var mContext          = getField(rmBase, "mContext");
                var mVsm              = getField(rmBase, "mVsm");
                var mConfigModule     = getField(rmBase, "mConfigModule");

                var pdnClassName = mPdnController.getClass().getName();
                console.log("[PDN] PdnController class: " + pdnClassName);

                // ── 建 RegisterTask ──
                var RegisterTask = Java.use("com.sec.internal.ims.core.RegisterTask");
                var registerTask = RegisterTask.$new(
                    imsProfile,
                    rmBase,
                    mTelephonyManager,
                    mPdnController,
                    mContext,
                    mVsm,
                    mConfigModule,
                    phoneId
                );
                console.log("[RM] RegisterTask created: " + registerTask);

                // ── 建 callback Message ──
                var HandlerThread = Java.use("android.os.HandlerThread");
                var Handler       = Java.use("android.os.Handler");
                var Message       = Java.use("android.os.Message");
                var ht = HandlerThread.$new("frida-em-callback");
                ht.start();
                var handler = Handler.$new(ht.getLooper());
                var msg = Message.obtain(handler);
                registerTask.setResultMessage(msg);

                var pdnType = 15;
                registerTask.setPdnType(pdnType);

                var RegisterTaskState = Java.use(
                    "com.sec.internal.constants.ims.core.RegistrationConstants$RegisterTaskState"
                );
                registerTask.setState(RegisterTaskState.CONNECTING.value);

                // ── Hook applyEmergencyQualifiedNetowrk ──
                // 只設本地 mEPDNQN，跳過 EpdgManager binder call（EpdgImsListener 未初始化）
                var PdnControllerClass = Java.use(pdnClassName);
                //PdnControllerClass.applyEmergencyQualifiedNetowrk.implementation = function(pid) {
                //    console.log("[HOOK] applyEmergencyQualifiedNetowrk intercepted, phoneId=" + pid);
                //    this.setEmergencyQualifiedNetowrk(pid, 13);
                //    console.log("[HOOK] mEPDNQN[" + pid + "] = 13, EpdgManager skipped");
                //};

                // ── cast + 呼叫 startPdnConnectivity ──
                var pdnInstance = Java.cast(mPdnController, PdnControllerClass);
                var PdnEventListener = Java.use("com.sec.internal.interfaces.ims.core.PdnEventListener");
                var pdnListener = Java.cast(registerTask, PdnEventListener);

                console.log("[PDN] Calling startPdnConnectivity pdnType=" + pdnType + " phoneId=" + phoneId);
                pdnInstance.startPdnConnectivity.overload(
                    'int',
                    'com.sec.internal.interfaces.ims.core.PdnEventListener',
                    'int'
                ).call(pdnInstance, pdnType, pdnListener, phoneId);
                console.log("[PDN] startPdnConnectivity called successfully");

            } catch(e) {
                console.log("[RM] Error: " + e.message);
                console.log("[RM] Stack: " + e.stack);
            }
        },
        onComplete: function() {
            console.log("[RM] scan complete");
        }
    });
});

