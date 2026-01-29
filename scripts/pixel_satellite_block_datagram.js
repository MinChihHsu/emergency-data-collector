Java.perform(function() {
    console.log("[+] Starting DatagramDispatcher.handleMessage hook...");
    
    
    function reportReady(id) {
        console.log("FRIDA_READY:" + id);
    }

    function reportError(id, e) {
        var msg = (e && e.stack) ? e.stack : ("" + e);
        console.log("FRIDA_ERROR:" + id + ":" + msg);
    }
    
    try {
        var DatagramDispatcher = Java.use("com.android.internal.telephony.satellite.DatagramDispatcher");
        
        DatagramDispatcher.handleMessage.implementation = function(msg) {
            var msgWhat = msg.what.value;
            console.log("[+] DatagramDispatcher.handleMessage - what: " + msgWhat);
            
            if (msgWhat == 1) { // CMD_SEND_SATELLITE_DATAGRAM
                console.log("[+] INTERCEPTED CMD_SEND_SATELLITE_DATAGRAM - BLOCKING");
                
                try {
                    // Get the actual request object from the Field
                    var request = msg.obj.value;
                    console.log("[+] Request object: " + request);
                    console.log("[+] Request class: " + request.getClass().getName());
                    
                    // Now we can access the argument directly (it's a Java object property, not a Field)
                    var argument = request.argument;
                    console.log("[+] Argument object: " + argument);
                    //console.log("[+] Argument class: " + argument.getClass().getName());
                    
                    // Log some argument details - these are direct properties
                    //try {
                    //    console.log("[+] SubId: " + argument.subId);
                    //    console.log("[+] Datagram ID: " + argument.datagramId);
                    //    console.log("[+] Datagram Type: " + argument.datagramType);
                    //    console.log("[+] Need Full Screen UI: " + argument.needFullScreenPointingUI);
                    //} catch (e) {
                    //    console.log("[-] Error reading argument details: " + e);
                    //}
                    
                    // Set start time
                    //try {
                    //    argument.setDatagramStartTime();
                    //    console.log("[+] Set datagram start time");
                    //} catch (e) {
                    //    console.log("[-] Error setting start time: " + e);
                    //}
                    
                    // Create completion message using Message.obtain()
                    var Message = Java.use("android.os.Message");
                    var onCompleted = Message.obtain(this, 2, request); // EVENT_SEND_SATELLITE_DATAGRAM_DONE
                    console.log("[+] Created onCompleted message");
                    
                    // Simulate success
                    var AsyncResult = Java.use("android.os.AsyncResult");
                    AsyncResult.forMessage(onCompleted, Java.use("java.lang.Integer").$new(0), null);
                    console.log("[+] Created AsyncResult with SUCCESS");
                    
                    
                    //var demoTimeout = this.getDemoTimeoutDuration();
                    this.sendMessageDelayed(onCompleted, 1000);
                    console.log("[+] Sent delayed response with 1s timeout.");
                    
                    console.log("[+] SUCCESS: Blocked and simulated demo response");
                    return; // Don't call original
                    
                } catch (e) {
                    console.log("[-] Error: " + e);
                    console.log("[-] Stack: " + e.stack);
                    return; // Still block
                }
            }
            
            return this.handleMessage(msg);
        };
        
        console.log("[+] Hook installed successfully");
        reportReady("pixel_satellite_block_datagram");
        
    } catch (e) {
        console.log("[-] Hook installation failed: " + e);
        reportError("pixel_satellite_block_datagram", e);
    }
});

