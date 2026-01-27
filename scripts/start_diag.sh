resetprop ro.bootmode usbradio
resetprop ro.build.type userdebug
stop DM-daemon && start DM-daemon
setprop sys.usb.config acm,dm,adb
setprop persist.vendor.usb.usbradio.config dm
