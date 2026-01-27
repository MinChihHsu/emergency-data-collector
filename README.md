# Emergency Data Collector
## Prereqisite
### Devices
- A rooted, Android-based smartphone
- A laptop that runs ADB and SCAT (we recommand laptop running Ubuntu/MacOS)
### Applications
#### On the computer
- emergency-data-collector (this repository)
  - Pull this repository to local by `git clone https://github.com/MinChihHsu/emergency-data-collector.git`
- SCAT
  - Install / Update SCAT to latest version.
    - Please install Python >= 3.10
    - ```
      # replace pip with pip3 if needed
      sudo pip install pyusb pyserial bitstring packaging libscrc
      sudo pip install "signalcat[fastcrc]"
      ```
- Frida (client), Frida scripts and frida_server.py
  - Install with `sudo pip install frida-tools flask`
  - Set two variables: SCRIPT_DIR and SCAT_OUTPUT_DIR in `frida_server.py`

#### On the phone
- emergency-data-collector (APP)
  - You can either install the app using APK file or compile by yourself
    - APK files (TBD)
      - `adb push /PATH/TO/emergency-data-collector.apk /sdcard/Download`
      - Click the APK file in file explorer on the phone and install it.
    - Compile by yourself
      - Install Android Studio and open the repository
      - Connect the phone to the laptop, and click "Run" to compile and install the app
      - Grant all permissions required by the app.
- (For Google Pixel Series Phones) start_diag.sh
  - Push the file to the phone and grant permissions.
    - ```
      adb push /PATH/TO/scripts/start_diag.sh /data/local/tmp/
      adb shell

      ## connected to the phone
      su
      chmod 777 /data/local/tmp/start_diag.sh
      ```
- Termux and Frida
  - Install / Update Termux to latest version.
    - You MUST install / update from F-droid (https://f-droid.org/packages/com.termux/) or Github release (https://github.com/termux/termux-app/releases)
  - Grant all permissions for Termux, and run the following commands in Termux to install Frida Client
    - ```=sh
      pkg update && pkg upgrade -y
      pkg install -y build-essential python python-pip git wget binutils openssl xz-utils
      wget https://maglit.me/frida-python && bash frida-python
      ```
    - If any error happens, you can follow the Step 3 from [this post](https://github.com/frida/frida/discussions/2411) to solve the issue.
  - Download and Install Frida Server
    - Check the installed Frida Client version by `frida --version` in Termux
    - Download the server from Github release (https://github.com/frida/frida/releases) ON YOUR LAPTOP.
      - You should download the version that is corresponding to the client version and the device architecture.
        - e.g. Pixel 9 is arm64 and the `frida --version` is 17.6.2. So, you need to download `frida-server-17.6.2-android-arm64.xz`.
      - Decompressed the xz file (`untz -c`) and push the server file to the phone.
        - `adb push /PATH/TO/SERVER /data/local/tmp/frida-server`
      - Connect laptop with the phone using ADB (`adb shell`), and change give execurable permission to the server file
        - ```=sh
          su
          chmod 777 /data/local/tmp/frida-server
          ``` 



## Usage
- Connect the phone to your laptop
- Enable Diag mode
  - For **Samsung Galaxy Series** phones, dial `*#0808#` in dialer, and choose the option with both "modem" and "adb".
    - We recommand choosing the most completed option: "RMNET+DM+MODEM+ADPL+QDSS+ADB"
  - For **Google Pixel Series** phones, run `start_diag.sh` in `adb shell` with `su` permission.
    - ```
      adb shell

      ## connected to the phone
      su
      cd /data/local/tmp
      ./start_diag.sh
      
      ## should disconnect from the phone automatically
      lsusb | grep "Samsung Electronics"
      ## Check if there is any device info output
      ```
- Run `frida_server.py`
  - `sudo python frida_server.py`
  - Open another terminal tab
    - ```
      adb reverse tcp:5555 tcp:5555
      adb shell

      ## 
      ## connected to the phone
      su
      cd /data/local/tmp
      ./frida-server
      ```
- Open and Run emergency-data-collector
  - Open the app, select the scenario you need, and how many experiments per scenario, then start log collection
- Log Upload
  - **TODO**
    

## Others
### output format reference
scat file output: on PC (https://drive.google.com/drive/folders/1S8hFGQ0w7ifq2tMOEbQ3GydfZN0SV8hT?usp=drive_link)

logcat file output (only radio for now): on cellphone (https://drive.google.com/drive/folders/16EPdlb2BdcXXamf1DRTdy1U9o0sFXUjL?usp=drive_link)
