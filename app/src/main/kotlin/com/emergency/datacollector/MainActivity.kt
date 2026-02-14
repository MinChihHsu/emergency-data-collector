package com.emergency.datacollector

import android.annotation.SuppressLint
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.telecom.TelecomManager
import android.telephony.CellInfo
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.CellInfoGsm
import android.telephony.TelephonyManager
import android.util.Log
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.*
import kotlin.concurrent.thread
import kotlin.math.abs

class MainActivity : AppCompatActivity() {

    // UI Components
    private lateinit var infoTextView: TextView // default log
    private lateinit var txtLocation: TextView // log from gps
    private lateinit var txtCountryCode: TextView // telephonyManager.networkCountryIso
    private lateinit var txtMccMnc: TextView // telephonyManager.networkOperator
    private lateinit var btnRefreshGps: Button // refresh gps
    private lateinit var txtEmergencyNumber: TextView
    private lateinit var editWifiCallingNumber: EditText
    private lateinit var spinnerExperimentsCount: Spinner
    private lateinit var checkScenario1: CheckBox
    private lateinit var checkScenario2: CheckBox
    private lateinit var checkScenario3: CheckBox
    private lateinit var checkScenario4: CheckBox
    private lateinit var btnStartExperiment: Button
    private lateinit var btnStopExperiment: Button
    private lateinit var btnTestNormalCall: Button
    private lateinit var btnUpdateMccMnc: Button
    private lateinit var txtFileSize: TextView


    // Configuration
    private var dialNumber: String = ""
    private var emergencyNumber: String = "911"
    private var wifiCallingNumber: String = ""
    private var experimentsPerScenario: Int = 10
    private var gpsLocation: String = ""  // Format: {n/s}xx.xxxxxx_{e/w}xx.xxxxxx
    private var countryCode: String = "--"  // 2-letter ISO code
    private var mccMnc: String = "000000"  // MCC+MNC
    private var operatorName: String = "Unknown"  // Carrier name from PLMN lookup
    private var modelName: String = Build.MODEL  // e.g. SM-G9910
    private var deviceId: String = ""  // Device ID
    private var modemType: String = "qc"  // Modem type for scat: qc, sec, mtk
    private var enableScat: Boolean = true  // Set to true to enable SCAT recording on PC
    private val httpConnectTimeoutMs = 20000
    private val httpReadTimeoutMs = 30000


    // Scenario selection
    private var runScenario1 = true
    private var runScenario2 = true
    private var runScenario3 = true
    private var runScenario4 = true
    private var isTestNormalCallMode: Boolean = false


    // Current phase: 1 = Home Carrier, 2 = Visitor Carrier
    private var currentPhase = 1
    private var currentMeasurementCount = 0
    private var totalMeasurementsPerPhase = 10
    private var isCollectionRunning = false
    private var shouldStop = false
    
    private val handler = Handler(Looper.getMainLooper())

    // ===== Timing Configuration (Global Variables) =====
    // Timing (loaded from strings.xml in onCreate)
    private var delayAfterHangup = 2000L
    private var delayBetweenCalls = 5000L

    // ✅ NEW: Network configuration delay (6 seconds per step)
    private var delayNetworkConfigStep = 6000L

    // ✅ NEW: Wait-for-block timeout (5 minutes = 300 seconds)
    private var waitForBlockTimeoutSec: Int = 300

    // ✅ NEW: Satellite flow delays
    private var delaySatelliteAppToFirstTap = 1000L  // 1 second
    private var delaySatelliteFirstToSecondTap = 1000L  // 1 second
    private var delayBetweenSatelliteCalls = 60000L

    // ✅ NEW: Data collection tools retry delay (2 seconds)
    private var delayToolsRetry = 2000L

    // ===== NEW: IPsec monitoring =====
    private var isMonitoringIpsec = false
    private var lastIpsecOutput = ""
    private var currentIpsecBaseFileName = ""  // ✅ NEW: Store current measurement's base filename
    private val ipsecMonitorHandler = Handler(Looper.getMainLooper())

    private val ipsecMonitorRunnable = object : Runnable {
        override fun run() {
            if (isMonitoringIpsec) {
                logIpsecState()
                ipsecMonitorHandler.postDelayed(this, 1000) // Every 1 second
            }
        }
    }


    // End call button coordinates (device-specific)
    private var endCallButtonX = 0
    private var endCallButtonY = 0

    // ===== Perfetto control (root) =====
    private var perfettoPid: Int? = null
    private var perfettoTmpTracePath: String? = null

    private val perfettoTraceDir = "/data/misc/perfetto-traces"

    private var tcpdumpPid: Int? = null

    // ===== Network Info Monitoring =====
    private lateinit var wifiManager: android.net.wifi.WifiManager
    private var isMonitoringNetwork = false
    private val networkMonitorHandler = Handler(Looper.getMainLooper())

    private val ratMonitorRunnable = object : Runnable {
        override fun run() {
            if (isMonitoringNetwork) {
                logRATType()
                networkMonitorHandler.postDelayed(this, 1000)
            }
        }
    }

    private val cellInfoMonitorRunnable = object : Runnable {
        override fun run() {
            if (isMonitoringNetwork) {
                logCellInfo()
                networkMonitorHandler.postDelayed(this, 1000)
            }
        }
    }

    private val wifiInfoMonitorRunnable = object : Runnable {
        override fun run() {
            if (isMonitoringNetwork) {
                logWiFiInfo()
                networkMonitorHandler.postDelayed(this, 5000)
            }
        }
    }


    private fun runSuRoot(cmd: String): Pair<Int, String> {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        val code = p.waitFor()
        return code to (out + err)
    }

    private fun runSuShell(cmd: String): Pair<Int, String> {
        // Run command as "shell" via su to match what worked in your manual test.
        val p = Runtime.getRuntime().exec(arrayOf("su", "shell", "-c", cmd))
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        val code = p.waitFor()
        return code to (out + err)
    }
    private fun ensurePerfettoConfigPbtx(): Boolean {
        val target = "/data/local/tmp/config.pbtx"

        return try {
            // If target exists and size > 0, we're done.
            val (exit0, out0) = runSuShell("sh -c 'test -s \"$target\"; echo \$?'")
            if (out0.trim().endsWith("0")) return true

            // Copy assets/config.pbtx -> app internal file
            val local = File(filesDir, "config.pbtx")
            assets.open("config.pbtx").use { input ->
                local.outputStream().use { output ->
                    input.copyTo(output)
                }
            }

            // Sanity check: local file must be non-empty
            if (!local.exists() || local.length() <= 0L) return false

            // Copy internal file -> /data/local/tmp/config.pbtx as root, set readable perms
            val cmd = "cp \"${local.absolutePath}\" \"$target\" && chmod 644 \"$target\""
            val cpExit = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd)).waitFor()
            cpExit == 0
        } catch (e: Exception) {
            false
        }
    }

    private fun startPerfettoTraceUntilOk(
        baseFileNameNoExt: String,
        retryDelayMs: Long = delayToolsRetry,
        onStarted: (Boolean) -> Unit
    ) {
        val tmpTrace = "$perfettoTraceDir/${baseFileNameNoExt}.pftrace"
        perfettoTmpTracePath = tmpTrace

        fun attempt() {
            if (shouldStop || !isCollectionRunning) {
                handler.post { onStarted(false) }
                return
            }

            thread {
                try {
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "mkdir -p $perfettoTraceDir")).waitFor()

                    if (!ensurePerfettoConfigPbtx()) {
                        handler.post {
                            appendLog("Perfetto not ready: cannot prepare /data/local/tmp/config.pbtx. Retry in ${retryDelayMs}ms")
                            handler.postDelayed({ attempt() }, retryDelayMs)
                        }
                        return@thread
                    }

                    val cmd =
                        "sh -c '/system/bin/perfetto --txt -c /data/local/tmp/config.pbtx -o \"$tmpTrace\" >/dev/null 2>&1 & echo $!'"

                    val (exit, output) = runSuShell(cmd)
                    val pid = output.trim().toIntOrNull()

                    handler.post {
                        if (exit == 0 && pid != null && pid > 0) {
                            perfettoPid = pid
                            appendLog("Perfetto started (pid=$pid): $tmpTrace")
                            onStarted(true)
                        } else {
                            appendLog("Perfetto start failed (exit=$exit): '${output.trim().take(120)}'. Retry in ${retryDelayMs}ms")
                            handler.postDelayed({ attempt() }, retryDelayMs)
                        }
                    }
                } catch (e: Exception) {
                    handler.post {
                        appendLog("Perfetto start error: ${e.message}. Retry in ${retryDelayMs}ms")
                        handler.postDelayed({ attempt() }, retryDelayMs)
                    }
                }
            }
        }

        attempt()
    }

    private fun stopPerfettoTraceAndSave(baseFileNameNoExt: String) {
        val pid = perfettoPid
        val tmpTrace = perfettoTmpTracePath ?: "$perfettoTraceDir/${baseFileNameNoExt}.pftrace"
        perfettoPid = null
        perfettoTmpTracePath = null

        val outDir = getExternalFilesDir(null)
        if (outDir == null) {
            appendLog("Perfetto save error: external files dir is null")
            return
        }
        val outPath = "${outDir.absolutePath}/${baseFileNameNoExt}.pftrace"

        thread {
            try {
                if (pid != null) {
                    // SIGINT makes perfetto flush/close trace nicely
                    val stopCmd =
                        "sh -c 'kill -INT $pid 2>/dev/null; " +
                                "for i in \$(seq 1 120); do kill -0 $pid 2>/dev/null || break; sleep 0.1; done'"
                    runSuShell(stopCmd)
                }

                // If trace missing/empty, skip saving (not an error)
                val (_, testOut) = runSuShell("sh -c 'test -s \"$tmpTrace\"; echo \$?'")
                if (!testOut.trim().endsWith("0")) {
                    handler.post { appendLog("Perfetto save skip: trace missing/empty: $tmpTrace") }
                    return@thread
                }

                // Copy trace out to app external files dir
                val cpExit =
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "cp \"$tmpTrace\" \"$outPath\"")).waitFor()

                // ✅ Ensure adb pull can read it
                val chmodExit = if (cpExit == 0) {
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod +r \"$outPath\"")).waitFor()
                } else {
                    -1
                }

                val rmExit =
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "rm -f \"$tmpTrace\"")).waitFor()

                handler.post {
                    if (cpExit == 0) {
                        appendLog("Perfetto saved: ${baseFileNameNoExt}.pftrace")
                        if (chmodExit != 0) {
                            appendLog("Perfetto chmod warning (exit: $chmodExit) path=$outPath")
                        }
                        if (rmExit != 0) {
                            appendLog("Perfetto temp cleanup warning (exit: $rmExit)")
                        }
                    } else {
                        appendLog("Perfetto save error: cp failed (exit: $cpExit) tmp=$tmpTrace")
                    }
                }

            } catch (e: Exception) {
                handler.post { appendLog("Perfetto stop/save error: ${e.message}") }
            }
        }
    }


    private fun initEndCallButtonCoordinates() {
        // Set coordinates based on device model
        when {
            modelName.contains("Pixel", ignoreCase = true) -> {
                // Pixel 10
                endCallButtonX = 542
                endCallButtonY = 2207
            }
            modelName.contains("SM-G99", ignoreCase = true) -> {
                // Samsung S21
                endCallButtonX = 585
                endCallButtonY = 2012
            }
            else -> {
                // Default (Samsung S21)
                endCallButtonX = 585
                endCallButtonY = 2012
            }
        }
        appendLog("End call button: ($endCallButtonX, $endCallButtonY) for $modelName")
    }
    
    private lateinit var prefs: SharedPreferences

    private val PERMISSION_REQUEST_CODE = 100
    private val requiredPermissions = arrayOf(
        Manifest.permission.CALL_PHONE,
        Manifest.permission.ACCESS_WIFI_STATE,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.ANSWER_PHONE_CALLS
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        thread {
            try {
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "setprop persist.log.tag D"))
                val exitCode = process.waitFor()
                handler.post {
                    if (exitCode == 0) {
                        appendLog("Logcat level set to DEBUG")
                    } else {
                        appendLog("Warning: Failed to set logcat level (exit: $exitCode)")
                    }
                }
            } catch (e: Exception) {
                handler.post {
                    appendLog("Logcat level setting error: ${e.message}")
                }
            }
        }

        prefs = getSharedPreferences("AppConfig", MODE_PRIVATE)

        // Bind UI Components
        infoTextView = findViewById(R.id.infoTextView)
        txtLocation = findViewById(R.id.txtLocation)
        txtCountryCode = findViewById(R.id.txtCountryCode)
        txtMccMnc = findViewById(R.id.txtMccMnc)
        btnRefreshGps = findViewById(R.id.btnRefreshGps)
        txtEmergencyNumber = findViewById(R.id.txtEmergencyNumber)
        editWifiCallingNumber = findViewById(R.id.editWifiCallingNumber)
        spinnerExperimentsCount = findViewById(R.id.spinnerExperimentsCount)
        checkScenario1 = findViewById(R.id.checkScenario1)
        checkScenario2 = findViewById(R.id.checkScenario2)
        checkScenario3 = findViewById(R.id.checkScenario3)
        checkScenario4 = findViewById(R.id.checkScenario4)
        btnStartExperiment = findViewById(R.id.btnStartExperiment)
        btnStopExperiment = findViewById(R.id.btnStopExperiment)
        btnTestNormalCall = findViewById(R.id.btnTestNormalCall)
        btnUpdateMccMnc = findViewById(R.id.btnUpdateMccMnc)
        txtFileSize = findViewById(R.id.txtFileSize)


        val experimentOptions = (1..10).toList()
        val spinnerAdapter = ArrayAdapter(this, R.layout.spinner_item, experimentOptions)
        spinnerAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerExperimentsCount.adapter = spinnerAdapter
        spinnerExperimentsCount.setSelection(9)


        // Load MCC-MNC database for operator lookup
        MccMncLookup.load(this)
        
        // Load emergency number from strings.xml
        emergencyNumber = getString(R.string.emergency_number)
        dialNumber = emergencyNumber
        
        // Load timing configuration from strings.xml
        delayAfterHangup = getString(R.string.delay_after_hangup).toLong()
        delayBetweenCalls = getString(R.string.delay_between_calls).toLong()
        
        // Get device ID: IMEI hashed with MD5 (first 12 chars)
        deviceId = getHashedImei()
        
        // Initialize device-specific end call button coordinates
        initEndCallButtonCoordinates()
        
        updateMccMnc()
        updateFileSize()

        // tcpdump binary
        val allAbis = Build.SUPPORTED_ABIS.joinToString(", ")
        appendLog("Supported ABIs: $allAbis")
        appendLog("Primary ABI: ${Build.SUPPORTED_ABIS[0]}")
        // Initialize WiFi Manager
        wifiManager = getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager

        thread {
            val result = ensureTcpdumpBinary()
            handler.post {
                if (result) {
                    appendLog("✅ tcpdump binary test: SUCCESS")
                } else {
                    appendLog("❌ tcpdump binary test: FAILED")
                }
            }
        }
        
        // GPS refresh button
        btnRefreshGps.setOnClickListener {
            refreshGpsLocation()
            updateFileSize()
        }

        btnUpdateMccMnc.setOnClickListener {
            updateMccMnc()
            updateFileSize()
        }
        
        btnStartExperiment.setOnClickListener {
            updateFileSize()
            if (checkPermissions()) {
                // Update config from UI
                experimentsPerScenario = spinnerExperimentsCount.selectedItem as Int
                totalMeasurementsPerPhase = experimentsPerScenario
                wifiCallingNumber = editWifiCallingNumber.text.toString()
                runScenario1 = checkScenario1.isChecked
                runScenario2 = checkScenario2.isChecked
                runScenario3 = checkScenario3.isChecked
                runScenario4 = checkScenario4.isChecked
                isTestNormalCallMode = false
                if (runScenario3 && isEmergencyLikeNumber(wifiCallingNumber)) {
                    Toast.makeText(this, "WiFi Calling number cannot be an emergency number.", Toast.LENGTH_LONG).show()
                    appendLog("Abort: WiFi Calling number is emergency-like: '${normalizeDialNumber(wifiCallingNumber)}'")
                    return@setOnClickListener
                }

                setInputsEnabled(false)
                startFullCollection()
            } else {
                requestPermissions()
            }
        }

        btnTestNormalCall.setOnClickListener {
            updateFileSize()
            if (checkPermissions()) {
                // Update config from UI
                experimentsPerScenario = spinnerExperimentsCount.selectedItem as Int
                totalMeasurementsPerPhase = experimentsPerScenario
                wifiCallingNumber = editWifiCallingNumber.text.toString()

                runScenario1 = checkScenario1.isChecked
                runScenario2 = false // ✅ Test mode ignores Scenario 2
                runScenario3 = checkScenario3.isChecked
                runScenario4 = checkScenario4.isChecked

                // Scenario 1 test needs WiFi Calling number (normal CALL)
                if (runScenario1 && wifiCallingNumber.isBlank()) {
                    Toast.makeText(this, "Please input WiFi Calling number for Scenario #1 normal call test", Toast.LENGTH_LONG).show()
                    appendLog("Test mode aborted: Scenario #1 checked but WiFi Calling number is empty")
                    return@setOnClickListener
                }
                if ((runScenario1 || runScenario3) && isEmergencyLikeNumber(wifiCallingNumber)) {
                    Toast.makeText(this, "Test blocked: WiFi Calling number cannot be an emergency number.", Toast.LENGTH_LONG).show()
                    appendLog("Test blocked: WiFi Calling number is emergency-like: '${normalizeDialNumber(wifiCallingNumber)}'")
                    return@setOnClickListener
                }
                setInputsEnabled(false)
                isTestNormalCallMode = true
                startFullCollection()
            } else {
                requestPermissions()
            }
        }


        btnStopExperiment.setOnClickListener {
            stopCollection()
            updateFileSize()
        }

        if (!checkPermissions()) {
            requestPermissions()
        } else {
            // get gps automatically
            refreshGpsLocation()
        }
        
        infoTextView.text = "Ready. Configure settings and press Start.\n"
        
        // Ensure SIM is enabled when app starts
        ensureSimEnabled()
    }
    
    override fun onResume() {
        super.onResume()
        // Ensure SIM is enabled when app resumes, but NOT during measurement
        if (!isCollectionRunning) {
            ensureSimEnabled()
        }
    }
    
    private fun ensureSimEnabled() {
        try {
            val tm = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (tm.simState != TelephonyManager.SIM_STATE_READY) {
                appendLog("SIM not ready, enabling...")
                enableSim()
            }
        } catch (e: Exception) {
            appendLog("SIM check error: ${e.message}")
        }
    }

    // ===== GPS Location =====

    private fun refreshGpsLocation() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) 
            != PackageManager.PERMISSION_GRANTED) {
            txtLocation.text = "No GPS permission"
            return
        }
        
        txtLocation.text = "Getting GPS..."
        
        try {
            val locationManager = getSystemService(Context.LOCATION_SERVICE) as LocationManager
            
            // get last known location
            val lastKnown = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: locationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            
            if (lastKnown != null) {
                updateLocationDisplay(lastKnown)
            }
            
            // gps update
            val locationListener = object : LocationListener {
                override fun onLocationChanged(location: Location) {
                    updateLocationDisplay(location)
                    locationManager.removeUpdates(this)
                }
                override fun onProviderEnabled(provider: String) {}
                override fun onProviderDisabled(provider: String) {}
                @Deprecated("Deprecated in Java")
                override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
            }
            
            if (locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                locationManager.requestLocationUpdates(
                    LocationManager.GPS_PROVIDER, 0, 0f, locationListener
                )
            } else if (locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                locationManager.requestLocationUpdates(
                    LocationManager.NETWORK_PROVIDER, 0, 0f, locationListener
                )
            }
            
            // stop request after 5s
            handler.postDelayed({
                locationManager.removeUpdates(locationListener)
            }, 5000)
            
        } catch (e: Exception) {
            txtLocation.text = "GPS Error: ${e.message}"
        }
    }
    
    private fun updateLocationDisplay(location: Location) {
        // format: {n/s}xx.xxxxxx_{e/w}xx.xxxxxx
        val latDir = if (location.latitude >= 0) "n" else "s"
        val lonDir = if (location.longitude >= 0) "e" else "w"
        val lat = abs(location.latitude)
        val lon = abs(location.longitude)
        
        gpsLocation = "${latDir}${String.format("%.6f", lat)}_${lonDir}${String.format("%.6f", lon)}"
        txtLocation.text = gpsLocation
    }
    
    // ===== MCC/MNC and Country Code =====

    private fun updateMccMnc() {
        try {
            val telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            
            // MCC+MNC
            val networkOperator = telephonyManager.networkOperator
            if (networkOperator.isNotEmpty() && networkOperator.length >= 5) {
                mccMnc = networkOperator
            } else {
                mccMnc = "000000"
            }
            txtMccMnc.text = mccMnc
            
            // operator name: first try CSV lookup, fallback to TelephonyManager
            val csvBrand = MccMncLookup.getBrand(mccMnc)
            val netOpName = telephonyManager.networkOperatorName
            operatorName = csvBrand ?: (if (netOpName.isNotEmpty()) netOpName else "Unknown")
            
            // get country code (2-letter ISO)
            val networkCountry = telephonyManager.networkCountryIso
            if (networkCountry.isNotEmpty()) {
                countryCode = networkCountry.uppercase()
            } else {
                countryCode = "--"
            }
            txtCountryCode.text = countryCode
            
        } catch (e: Exception) {
            mccMnc = "000000"
            countryCode = "--"
            txtMccMnc.text = mccMnc
            txtCountryCode.text = countryCode
        }
    }
    
    // ===== Main Collection Flow =====
    
    private fun startFullCollection() {
        if (isCollectionRunning) {
            Toast.makeText(this, "Collection already running", Toast.LENGTH_SHORT).show()
            return
        }
        
        isCollectionRunning = true
        shouldStop = false
        currentMeasurementCount = 0

        btnStartExperiment.isEnabled = false
        btnStopExperiment.isEnabled = true
        btnTestNormalCall.isEnabled = false

        setInputsEnabled(false)
        
        appendLog("=== Starting Full Collection ===")
        appendLog("Selected scenarios: " + 
            listOfNotNull(
                if (runScenario1) "1" else null,
                if (runScenario2) "2" else null,
                if (runScenario3) "3" else null,
                if (runScenario4) "4" else null
            ).joinToString(", "))
        appendLog("Measurements per scenario: $totalMeasurementsPerPhase")
        
        // get first scenario to experiment
        val firstPhase = getFirstEnabledPhase()
        if (firstPhase == null) {
            finishCollection("No scenarios selected!")
            return
        }

        // no need of CellularPro now, so skip here
        // updateProgress("Launching Cellular Pro...")
        // launchCellularPro()
        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }

        when (firstPhase) {
            1 -> startPhase1()
            2 -> startPhase2()
            3 -> startPhase3()
            4 -> startPhase4()
        }
    }
    
    // first scenario to experiment
    private fun getFirstEnabledPhase(): Int? {
        if (runScenario1) return 1
        if (runScenario2) return 2
        if (runScenario3) return 3
        if (runScenario4) return 4
        return null
    }
    
    // next scenario to experiment
    private fun getNextEnabledPhase(currentPhase: Int): Int? {
        for (phase in (currentPhase + 1)..4) {
            when (phase) {
                2 -> if (runScenario2) return 2
                3 -> if (runScenario3) return 3
                4 -> if (runScenario4) return 4
            }
        }
        return null
    }
    
    // ===== Frida control (HTTP) =====
    // Flask server on 127.0.0.1:5555 (Termux)(this one still need to run manually)
    // need to run python mobile_frida_server.py (Termux)
    
    private val fridaServerUrl = "http://127.0.0.1:5555"
    
    private fun sendFridaCommand(endpoint: String, jsonBody: String? = null, callback: (Boolean) -> Unit) {
        thread {
            try {
                val url = URL("$fridaServerUrl$endpoint")
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = httpConnectTimeoutMs
                connection.readTimeout = httpReadTimeoutMs

                
                if (jsonBody != null) {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.bufferedWriter().use { it.write(jsonBody) }
                }
                
                val responseCode = connection.responseCode
                connection.disconnect()
                
                handler.post {
                    if (responseCode == 200) {
                        appendLog("HTTP $endpoint: OK")
                        callback(true)
                    } else {
                        appendLog("HTTP $endpoint: Failed ($responseCode)")
                        callback(false)
                    }
                }
            } catch (e: Exception) {
                handler.post {
                    appendLog("HTTP error: ${e.message}")
                    callback(false)
                }
            }
        }
    }

    private fun waitForBlockMinWindow(timeoutSec: Int, callback: (Boolean) -> Unit) {
        thread {
            val startMs = System.currentTimeMillis()
            fun finish(blocked: Boolean) {
                val elapsed = System.currentTimeMillis() - startMs
                val targetMs = timeoutSec * 1000L
                val remaining = targetMs - elapsed

                // ✅ If we got a quick "not blocked" (including immediate 500), wait out the window.
                if (!blocked && remaining > 0) {
                    try { Thread.sleep(remaining) } catch (_: Exception) {}
                }
                handler.post { callback(blocked) }
            }

            try {
                val url = URL("$fridaServerUrl/wait-for-block")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = httpConnectTimeoutMs
                    // Let the server-side timeout drive duration; give a little slack.
                    readTimeout = maxOf(httpReadTimeoutMs, timeoutSec * 1000 + 5000)
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                }

                val body = """{"timeout": $timeoutSec}"""
                conn.outputStream.bufferedWriter().use { it.write(body) }

                val code = conn.responseCode
                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                val resp = stream?.bufferedReader()?.readText().orEmpty()
                conn.disconnect()

                val blocked = Regex("\"blocked\"\\s*:\\s*(true|false)", RegexOption.IGNORE_CASE)
                    .find(resp)
                    ?.groupValues
                    ?.get(1)
                    ?.lowercase() == "true"

                handler.post {
                    appendLog("HTTP /wait-for-block: code=$code blocked=$blocked")
                    if (code !in 200..299) {
                        appendLog("wait-for-block non-200, will wait out ${timeoutSec}s window before proceeding")
                    }
                }

                finish(blocked)
            } catch (e: Exception) {
                handler.post {
                    appendLog("wait-for-block error: ${e.message}")
                    appendLog("wait-for-block error, will wait out ${timeoutSec}s window before proceeding")
                }
                finish(false)
            }
        }
    }


    private fun getDeviceType(): String {
        // Determine device type for Frida scripts (samsung or pixel)
        return when {
            modelName.contains("Pixel", ignoreCase = true) -> "pixel"
            else -> "samsung"
        }
    }
    
    private fun sendScatCommand(endpoint: String, jsonBody: String?, callback: (Boolean) -> Unit) {
        thread {
            try {
                val url = URL("$fridaServerUrl$endpoint")
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = httpConnectTimeoutMs
                connection.readTimeout = httpReadTimeoutMs

                
                if (jsonBody != null) {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.bufferedWriter().use { it.write(jsonBody) }
                }
                
                val responseCode = connection.responseCode
                connection.disconnect()
                
                handler.post {
                    if (responseCode == 200) {
                        appendLog("SCAT $endpoint: OK")
                        callback(true)
                    } else {
                        appendLog("SCAT $endpoint: Failed ($responseCode)")
                        callback(false)
                    }
                }
            } catch (e: Exception) {
                handler.post {
                    appendLog("SCAT error: ${e.message}")
                    callback(false)
                }
            }
        }
    }
    
    private fun getModemType(): String {
        // Determine modem type based on device model
        return when {
            modelName.contains("SM-G98", ignoreCase = true) -> "sec" // S20 series (Exynos in some regions)
            modelName.contains("SM-G99", ignoreCase = true) -> "qc"  // S21 series
            modelName.contains("SM-S90", ignoreCase = true) -> "qc"  // S22 series
            modelName.contains("SM-S91", ignoreCase = true) -> "qc"  // S23 series
            modelName.contains("SM-S92", ignoreCase = true) -> "qc"  // S24 series
            modelName.contains("SM-S93", ignoreCase = true) -> "qc"  // S25 series
            modelName.contains("Pixel", ignoreCase = true) -> "sec"   // Google Pixel
            else -> "qc"  // Default to Qualcomm
        }
    }

    private fun startPhase1() {
        appendLog("\n=== Scenario 1: Home Carrier (SIM Enabled, WiFi Disabled) ===")
        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }
        currentPhase = 1
        currentMeasurementCount = 0
        performMeasurement()
    }
    
    private fun startPhase2() {
        appendLog("\n=== Scenario 2: Visitor Carrier (SIM Disabled, WiFi Disabled) ===")
        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }

        currentPhase = 2
        currentMeasurementCount = 0
        performMeasurement()
    }
    
    private fun startPhase3() {
        appendLog("\n=== Scenario 3: WiFi Calling (SIM Enabled, WiFi Enabled, WiFi Calling Enabled) ===")
        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }

        currentPhase = 3
        currentMeasurementCount = 0
        performMeasurement()
    }

    private fun startPhase4() {
        appendLog("\n=== Scenario 4: Satellite SOS ===")

        // Disable WiFi for satellite scenario
        disableWifi()

        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }

        currentPhase = 4
        currentMeasurementCount = 0
        performMeasurement()
    }

    private fun performMeasurement() {
        if (shouldStop || !isCollectionRunning) {
            finishCollection("Stopped by user")
            return
        }

        currentMeasurementCount++
        val phaseLabel = currentPhase.toString()  // "1", "2", "3", or "4"

        appendLog("--- Measurement #$currentMeasurementCount (Scenario $currentPhase) ---")

        // Generate filename for this measurement (used for both logcat and scat)
        val baseFileName = generateFileName(phaseLabel).replace(".txt", "")
        val pcapFileName = "$baseFileName.pcap"

        thread {
            try {
                when (currentPhase) {
                    1 -> {
                        appendLog("Scenario 1: Configuring network for experiment #$currentMeasurementCount...")
                        disableWifi()
                        Thread.sleep(delayNetworkConfigStep)
                        enableAirplaneMode()
                        Thread.sleep(delayNetworkConfigStep)
                        disableAirplaneMode()
                        Thread.sleep(delayNetworkConfigStep)
                        enableSim()
                        Thread.sleep(delayNetworkConfigStep)

                    }
                    2 -> {
                        appendLog("Scenario 2: Configuring network for experiment #$currentMeasurementCount...")
                        disableWifi()
                        Thread.sleep(delayNetworkConfigStep)
                        enableAirplaneMode()
                        Thread.sleep(delayNetworkConfigStep)
                        disableAirplaneMode()
                        Thread.sleep(delayNetworkConfigStep)
                        disableSim()
                        Thread.sleep(delayNetworkConfigStep)

                    }
                    3 -> {
                        if (currentMeasurementCount == 1) {
                            appendLog("Scenario 3: Configuring WiFi Calling (first experiment only)...")
                            enableAirplaneMode()
                            Thread.sleep(delayNetworkConfigStep)
                            disableAirplaneMode()
                            Thread.sleep(delayNetworkConfigStep)
                            enableSim()
                            Thread.sleep(delayNetworkConfigStep)
                            enableWifi()
                            Thread.sleep(delayNetworkConfigStep)
                            enableWifiCalling()
                            Thread.sleep(delayNetworkConfigStep)
                        } else {
                            appendLog("Scenario 3: Skipping network config (not first experiment)")
                        }
                    }
                    4 -> {
                        appendLog("Scenario 4: No network config needed")
                    }
                }

                // ✅ After network config completes, continue on main thread
                handler.post {
                    continueAfterNetworkConfig(baseFileName, pcapFileName)
                }

            } catch (e: Exception) {
                handler.post {
                    appendLog("Network config error: ${e.message}")
                    finishCollection("Network config failed")
                }
            }
        }



    }
    private fun continueAfterNetworkConfig(baseFileName: String, pcapFileName: String) {
        // Step 1: Clear logcat buffer
        clearLogcat()

        val measurementStartTimeStr = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())

        // ---- Gate config (Frida + SCAT must return HTTP 200 before we proceed) ----
        val fridaEndpoint = if (currentPhase == 4) "/start-frida-satellite" else "/start-frida"
        val deviceTypeBody = """{"device_type": "${getDeviceType()}"}"""
        val scatBody = """{"modem_type": "${getModemType()}", "filename": "$pcapFileName"}"""

        val retryDelayMs = delayToolsRetry

        // Function to proceed to making the call (for phases 1, 2, 3)
        val proceedToMakeCall: () -> Unit = proceedToMakeCall@{

            if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@proceedToMakeCall }
            // ✅ 在撥號前啟動網絡監控
            startNetworkMonitoring()
            startIpsecMonitoring(baseFileName)

            // Make the call
            appendLog("Dialing...")
            if (isTestNormalCallMode && currentPhase == 1) {
                makeNormalCallToWifiCallingNumberForTestScenario1()
            } else {
                makeCall()
            }


            // Wait for blocker to intercept, then hang up immediately
            appendLog("Waiting for call to be blocked...")

            // TODO: Timeout should be 5 minutes. Change when the app is ready.
            waitForBlockMinWindow(timeoutSec = waitForBlockTimeoutSec) { blocked ->
                // ✅ 停止網絡監控
                stopNetworkMonitoring()
                stopIpsecMonitoring()

                if (blocked) {
                    appendLog("Call blocked! Waiting 2s for UI...")
                    Log.d("DataCollector", "=== CALL_BLOCKED: Waiting 2s before hangup ===" )
                } else {
                    appendLog("Block timeout, hanging up anyway...")
                    Log.d("DataCollector", "=== BLOCK_TIMEOUT: Hanging up anyway ===")
                }


                // ✅ Scenario #3 特殊處理：只有在 blocked 失敗時才 pkill
                val shouldPkill = !(currentPhase == 3 && blocked)

                handler.postDelayed({
                    if (shouldPkill) {
                        appendLog("Ending call via tap...")
                        thread {
                            tapScreen(endCallButtonX, endCallButtonY)
                        }
                        sendFridaCommand("/pkill-phone") { _ ->
                            appendLog("Quick pkill sent to prevent redial")
                            stopPerfettoTraceAndSave(baseFileName)
                        }
                    } else {
                        appendLog("Scenario #3: Call blocked successfully, skipping pkill")
                        stopPerfettoTraceAndSave(baseFileName)
                    }
                }, 500)  // 500ms after tap

                // Wait after hangup, then stop SCAT and capture logcat
                handler.postDelayed({
                    if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                    // Function to proceed after capturing logs
                    val proceedToNext: () -> Unit = {
                        appendLog("Proceeding to next measurement...")

                        val nextDelay = if (currentPhase == 4) {
                            delayBetweenSatelliteCalls  // 60 秒
                        } else {
                            delayBetweenCalls  // 5 秒
                        }

                        if (currentPhase == 4) {
                            appendLog("Waiting ${nextDelay/1000}s for Satellite to fully disconnect...")
                        }

                        // Next measurement or next scenario
                        handler.postDelayed({
                            if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                            if (currentMeasurementCount < totalMeasurementsPerPhase) {
                                performMeasurement()
                            } else {
                                appendLog("Scenario $currentPhase Complete!")
                                val nextPhase = getNextEnabledPhase(currentPhase)
                                if (nextPhase != null) {
                                    when (nextPhase) {
                                        1 -> startPhase1()
                                        2 -> startPhase2()
                                        3 -> startPhase3()
                                        4 -> startPhase4()
                                    }
                                } else {
                                    finishCollection("All measurements complete!")
                                }
                            }
                        }, nextDelay)
                    }

                    // Function to capture logcat
                    val captureLogcat: () -> Unit = {
                        appendLog("Capturing logcat (multiple buffers)...")
                        saveLogcatMultiBuffer(baseFileName, measurementStartTimeStr)
                        appendLog("Saved: ${baseFileName}_*.txt")
                        proceedToNext()
                    }

                    // Stop SCAT first, then capture logcat
                    stopTcpdump(baseFileName)
                    if (enableScat) {
                        appendLog("Stopping SCAT recording...")
                        sendScatCommand("/stop-scat", null) { scatStopSuccess ->
                            if (scatStopSuccess) {
                                appendLog("SCAT stopped successfully")
                            } else {
                                appendLog("Warning: SCAT stop failed")
                            }
                            // After SCAT stops, capture logcat
                            captureLogcat()
                        }
                    } else {
                        captureLogcat()
                    }
                }, delayAfterHangup)
            }

        }

        // Function for Satellite flow (Phase 4)
        val proceedToSatellite: () -> Unit = proceedToSatellite@{
            if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@proceedToSatellite }
            // ✅ 在啟動 Satellite 前啟動網絡監控
            startNetworkMonitoring()
            appendLog("Launching Satellite SOS questionnaire...")

            try {
                // Launch Satellite SOS app
                val cmd =
                    "am start -n com.google.android.apps.stargate/.questionnaire.QuestionnaireHomeActivity -a com.google.android.apps.stargate.ACTION_ESOS_QUESTIONNAIRE"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()

                if (exitCode == 0) {
                    appendLog("Satellite app launched successfully")
                } else {
                    appendLog("Warning: Satellite app launch exit code: $exitCode")
                }

                // Wait 2 seconds for app to open
                handler.postDelayed({
                    appendLog("Tapping first button (912, 2268)...")
                    tapScreen(912, 2268)

                    // Wait 2 seconds
                    handler.postDelayed({
                        appendLog("Tapping second button (540, 1752)...")
                        tapScreen(540, 1752)

                        fun startScatUntilOkThenMonitor() {
                            val myMeasurement = currentMeasurementCount
                            if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return }

                            val scatStarted = java.util.concurrent.atomic.AtomicBoolean(false)

                            // If enableScat=true, try to start SCAT in background until success (does NOT block monitoring)
                            if (enableScat) {
                                thread {
                                    while (!shouldStop && isCollectionRunning && currentMeasurementCount == myMeasurement && !scatStarted.get()) {
                                        try {
                                            val latch = java.util.concurrent.CountDownLatch(1)
                                            var ok = false

                                            sendScatCommand("/start-scat", scatBody) { success ->
                                                ok = success
                                                latch.countDown()
                                            }

                                            // Wait a bit for HTTP callback; then decide retry/success
                                            latch.await((httpConnectTimeoutMs + httpReadTimeoutMs + 5000L),java.util.concurrent.TimeUnit.MILLISECONDS)

                                            if (ok) {
                                                scatStarted.set(true)
                                                handler.post { appendLog("SCAT started successfully: $pcapFileName") }
                                            } else {
                                                Thread.sleep(retryDelayMs)
                                            }
                                        } catch (_: Exception) {
                                            try { Thread.sleep(retryDelayMs) } catch (_: Exception) {}
                                        }
                                    }
                                }
                            }

                            appendLog("Monitoring satellite connection...")
                            monitorSatelliteConnected { connected ->
                                // ✅ 停止網絡監控
                                stopNetworkMonitoring()


                                stopPerfettoTraceAndSave(baseFileName)

                                if (!connected) {
                                    appendLog("Satellite connection failed or timeout (measurement=$currentMeasurementCount). Continue next.")
                                    stopTcpdump(baseFileName)
                                    if (enableScat && scatStarted.get()) {
                                        appendLog("Stopping SCAT recording...")
                                        sendScatCommand("/stop-scat", null) { scatStopSuccess ->
                                            if (scatStopSuccess) {
                                                appendLog("SCAT stopped successfully")
                                            } else {
                                                appendLog("Warning: SCAT stop failed")
                                            }
                                        }
                                    }
                                    sendFridaCommand("/pkill-phone") { _ ->
                                        appendLog("Phone app killed after timeout")
                                    }

                                    handler.postDelayed({
                                        appendLog("Capturing logcat (timeout case)...")
                                        saveLogcatMultiBuffer(baseFileName, measurementStartTimeStr)
                                        appendLog("Saved: ${baseFileName}_*.txt")

                                        // Wait before next measurement
                                        val nextDelay = delayBetweenSatelliteCalls
                                        appendLog("Waiting ${nextDelay/1000}s before next measurement...")
                                        // 這裡照你成功時的 cleanup 做（至少要 stopScat / pkill / 保存 log）
                                        // 然後進下一次 measurement 或結束 scenario
                                        handler.postDelayed({
                                            if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                                            if (currentMeasurementCount < totalMeasurementsPerPhase) {
                                                performMeasurement()
                                            } else {
                                                appendLog("Scenario $currentPhase Complete!")
                                                val nextPhase = getNextEnabledPhase(currentPhase)
                                                if (nextPhase != null) {
                                                    when (nextPhase) {
                                                        1 -> startPhase1()
                                                        2 -> startPhase2()
                                                        3 -> startPhase3()
                                                        4 -> startPhase4()
                                                    }
                                                } else {
                                                    finishCollection("All measurements complete!")
                                                }
                                            }
                                        }, nextDelay)
                                    }, 1000)
                                    return@monitorSatelliteConnected
                                }

                                appendLog("Satellite connected! Proceeding...")

                                handler.postDelayed({
                                    if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                                    fun afterStopScat() {
                                        // Kill phone app (double pkill)
                                        handler.postDelayed({
                                            appendLog("Killing phone app...")
                                            sendFridaCommand("/pkill-phone") { _ ->
                                                // Capture logcat
                                                handler.postDelayed({
                                                    if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                                                    appendLog("Capturing logcat (multiple buffers)...")
                                                    saveLogcatMultiBuffer(baseFileName, measurementStartTimeStr)
                                                    appendLog("Saved: ${baseFileName}_*.txt")

                                                    val nextDelay = delayBetweenSatelliteCalls
                                                    appendLog("Waiting ${nextDelay/1000}s for Satellite to fully disconnect...")

                                                    // Next measurement / scenario
                                                    handler.postDelayed({
                                                        if (shouldStop || !isCollectionRunning) { finishCollection("Stopped by user"); return@postDelayed }

                                                        if (currentMeasurementCount < totalMeasurementsPerPhase) {
                                                            performMeasurement()
                                                        } else {
                                                            appendLog("Scenario $currentPhase Complete!")
                                                            val nextPhase = getNextEnabledPhase(currentPhase)
                                                            if (nextPhase != null) {
                                                                when (nextPhase) {
                                                                    1 -> startPhase1()
                                                                    2 -> startPhase2()
                                                                    3 -> startPhase3()
                                                                    4 -> startPhase4()
                                                                }
                                                            } else {
                                                                finishCollection("All measurements complete!")
                                                            }
                                                        }
                                                    }, nextDelay)
                                                }, 1000)  // brief wait after kill

                                            }
                                        }, 1000)
                                    }

                                    stopTcpdump(baseFileName)
                                    // Stop SCAT only if we actually started it
                                    if (enableScat && scatStarted.get()) {
                                        appendLog("Stopping SCAT recording...")
                                        sendScatCommand("/stop-scat", null) { scatStopSuccess ->
                                            if (scatStopSuccess) {
                                                appendLog("SCAT stopped successfully")
                                            } else {
                                                appendLog("Warning: SCAT stop failed")
                                            }
                                            afterStopScat()
                                        }
                                    } else {
                                        afterStopScat()
                                    }
                                }, delayAfterHangup)
                            }
                        }

                        startScatUntilOkThenMonitor()
                    }, delaySatelliteFirstToSecondTap)  // Wait 2 seconds after first tap
                }, delaySatelliteAppToFirstTap)  // Wait 2 seconds for app to open

            } catch (e: Exception) {
                stopNetworkMonitoring()
                appendLog("Satellite launch error: ${e.message}")
                finishCollection("Satellite launch failed")
            }
        }


        // ---- Gate logic: retry until HTTP 200 ----
        fun startScatUntilOkThenProceed() {
            if (shouldStop) { finishCollection("Stopped by user"); return }

            if (!enableScat) {
                // ✅ Start tcpdump even if SCAT is disabled
                startTcpdumpUntilOk(baseFileName) { tcpdumpOk ->
                    if (!tcpdumpOk) { finishCollection("Stopped"); return@startTcpdumpUntilOk }
                    if (currentPhase == 4) proceedToSatellite() else proceedToMakeCall()
                }
                return
            }

            appendLog("Starting SCAT recording...")
            sendScatCommand("/start-scat", scatBody) { scatOk ->
                if (scatOk) {
                    appendLog("SCAT started successfully: $pcapFileName")

                    // ✅ Start tcpdump after SCAT
                    startTcpdumpUntilOk(baseFileName) { tcpdumpOk ->
                        if (!tcpdumpOk) { finishCollection("Stopped"); return@startTcpdumpUntilOk }

                        startPerfettoTraceUntilOk(baseFileName) { ok ->
                            if (!ok) { finishCollection("Stopped"); return@startPerfettoTraceUntilOk }
                            if (currentPhase == 4) proceedToSatellite() else proceedToMakeCall()
                        }
                    }
                } else {
                    appendLog("SCAT start not ready (no HTTP 200). Retrying in ${retryDelayMs}ms...")
                    handler.postDelayed({ startScatUntilOkThenProceed() }, retryDelayMs)
                }
            }
        }

        fun startFridaUntilOkThenStartScat() {
            if (shouldStop) { finishCollection("Stopped by user"); return }

            appendLog("Starting Frida blocker...")
            sendFridaCommand(fridaEndpoint, deviceTypeBody) { fridaOk ->
                if (fridaOk) {
                    appendLog("Frida blocker started")

                    if (currentPhase == 4) {
                        // ✅ Phase 4: start Perfetto right after Frida is ready
                        startPerfettoTraceUntilOk(baseFileName) { ok ->
                            if (!ok) { finishCollection("Stopped by user"); return@startPerfettoTraceUntilOk }
                            proceedToSatellite()
                        }
                    } else {
                        startScatUntilOkThenProceed()
                    }
                } else {
                    appendLog("Frida start not ready (no HTTP 200). Retrying in ${retryDelayMs}ms...")
                    handler.postDelayed({ startFridaUntilOkThenStartScat() }, retryDelayMs)
                }
            }
        }
        fun startFridaWifiCallingThenStartScat() {
            if (shouldStop) { finishCollection("Stopped by user"); return }

            appendLog("Starting Frida WiFi calling monitor...")
            sendFridaCommand("/start-frida-wificalling", null) { fridaOk ->
                if (fridaOk) {
                    appendLog("Frida WiFi calling monitor started")
                    startScatUntilOkThenProceed()
                } else {
                    appendLog("Frida WiFi calling start not ready. Retrying in ${retryDelayMs}ms...")
                    handler.postDelayed({ startFridaWifiCallingThenStartScat() }, retryDelayMs)
                }
            }
        }



        // Step 2: Start Frida blocker (must be before SCAT) - now enforced
        // Step 2: Start Frida blocker (must be before SCAT) - now enforced
        // ✅ Scenario 3: skip starting frida script (/start-frida)
        if (currentPhase == 3) {
            appendLog("Scenario 3: starting WiFi calling monitor...")
            startFridaWifiCallingThenStartScat()
        } else {
            startFridaUntilOkThenStartScat()
        }
    }

    private fun monitorSatelliteConnected(callback: (Boolean) -> Unit) {
        appendLog("Starting satellite monitoring service (timeout: 5 minutes)...")

        // ✅ 確保舊的Service已停止（防止重複啟動）
        SatelliteMonitorService.stop(this)

        // ✅ 等待100ms確保舊Service完全停止
        handler.postDelayed({
            // 使用 Foreground Service 進行監控
            SatelliteMonitorService.start(this) { foundKeyword ->
                handler.post {
                    val reason = if (foundKeyword) "Satellite connected" else "Timeout reached"
                    appendLog("Satellite monitoring stopped: $reason")

                    appendLog("Satellite connection monitoring complete")
                    callback(foundKeyword)
                }
            }
        }, 100)
    }


    private fun stopCollection() {
        shouldStop = true
        appendLog("Stopping collection...")

        // ✅ 停止 satellite monitoring service
        SatelliteMonitorService.stop(this)
        stopIpsecMonitoring()
    }


    private fun finishCollection(message: String) {
        isCollectionRunning = false
        stopNetworkMonitoring()
        stopIpsecMonitoring()
        // ✅ 確保 service 被停止（雙重保險）
        SatelliteMonitorService.stop(this)

        // Ensure phone app is killed
        appendLog("Killing phone app on exit...")
        sendFridaCommand("/pkill-phone") { _ ->
            handler.postDelayed({
                sendFridaCommand("/pkill-phone") { _ ->
                    appendLog("Phone app killed")
                }
            }, 500)
        }

        // restoring setting
        appendLog("Restoring settings...")
        enableSim()
        disableWifiCalling()

        appendLog("=== $message ===")

        runOnUiThread {
            btnStartExperiment.isEnabled = true
            btnStopExperiment.isEnabled = false
            btnTestNormalCall.isEnabled = true
            setInputsEnabled(true)
        }
    }


    private fun setInputsEnabled(enabled: Boolean) {
        btnRefreshGps.isEnabled = enabled
        btnUpdateMccMnc.isEnabled = enabled
        editWifiCallingNumber.isEnabled = enabled
        spinnerExperimentsCount.isEnabled = enabled
        checkScenario1.isEnabled = enabled
        checkScenario2.isEnabled = enabled
        checkScenario3.isEnabled = enabled
        checkScenario4.isEnabled = enabled
    }


    // ===== SIM Control =====
    
    /**
     * Get the service call code for SIM enable/disable based on device model
     * Different Samsung models use different service call codes
     */
    private fun getSimServiceCallCode(): Int {
        return when {
            // S25 series
            modelName.contains("SM-S93", ignoreCase = true) -> 185
            // S24 series
            modelName.contains("SM-S92", ignoreCase = true) -> 186
            // NOT TESTED
            // S23 series
            modelName.contains("SM-S91", ignoreCase = true) -> 185
            // NOT TESTED
            // S22 series
            modelName.contains("SM-S90", ignoreCase = true) -> 193
            // S21 series
            modelName.contains("SM-G99", ignoreCase = true) -> 193
            // NOT TESTED
            // S20 series
            modelName.contains("SM-G98", ignoreCase = true) -> 193
            // Pixel 10
            modelName.contains("Pixel 10", ignoreCase = true) -> 185
            // Pixel 9
            modelName.contains("Pixel 9", ignoreCase = true) -> 185
            // Pixel 7
            modelName.contains("Pixel 7", ignoreCase = true) -> 182
            // For other models, default to S21 code
            else -> 193
        }
    }
    
    private fun enableSim(slot: Int = 0) {
        appendLog("Enabling SIM slot $slot...")
        try {
            val serviceCode = getSimServiceCallCode()
            val cmd = "service call phone $serviceCode i32 $slot i32 1"
            appendLog("Running: su shell -c '$cmd' (model: $modelName)")
            
            val process = Runtime.getRuntime().exec(arrayOf("su", "shell", "-c", cmd))
            val exitCode = process.waitFor()
            
            val result = process.inputStream.bufferedReader().readText()
            appendLog("Exit: $exitCode, Result: ${result.take(50)}")
            
            if (exitCode == 0) {
                appendLog("SIM enable command sent successfully")
            }
        } catch (e: Exception) {
            appendLog("SIM enable error: ${e.message}")
        }
    }
    
    private fun disableSim(slot: Int = 0) {
        appendLog("Disabling SIM slot $slot...")
        
        try {
            val serviceCode = getSimServiceCallCode()
            val cmd = "service call phone $serviceCode i32 $slot i32 0"
            appendLog("Running: su shell -c '$cmd' (model: $modelName)")
            
            val process = Runtime.getRuntime().exec(arrayOf("su", "shell", "-c", cmd))
            val exitCode = process.waitFor()
            
            val result = process.inputStream.bufferedReader().readText()
            val error = process.errorStream.bufferedReader().readText()
            
            appendLog("Exit: $exitCode, Result: ${result.take(50)}")
            if (error.isNotEmpty()) {
                appendLog("Error: ${error.take(50)}")
            }
            
            if (exitCode == 0) {
                appendLog("SIM disable command sent successfully")
            }
        } catch (e: Exception) {
            appendLog("SIM disable error: ${e.message}")
        }
    }
    
    // ===== WiFi Control =====
    
    private fun enableWifi() {
        appendLog("Enabling WiFi...")
        try {
            // Tested on Samsung S21, Samsung S25, Pixel 10
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "svc wifi enable")) 
            val exitCode = process.waitFor()
            appendLog("WiFi enable: exit code $exitCode")
        } catch (e: Exception) {
            appendLog("WiFi enable error: ${e.message}")
        }
    }
    
    private fun disableWifi() {
        appendLog("Disabling WiFi...")
        try {
            // Tested on Samsung S21, Samsung S25, Pixel 10
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "svc wifi disable"))
            val exitCode = process.waitFor()
            appendLog("WiFi disable: exit code $exitCode")
        } catch (e: Exception) {
            appendLog("WiFi disable error: ${e.message}")
        }
    }
    
    // ===== WiFi Calling Control =====
    
    private fun enableWifiCalling() {
        appendLog("Enabling WiFi Calling...")
        try {
            // Enable WiFi Calling
            // TODO: add method for Pixel
            Runtime.getRuntime().exec(arrayOf("su", "-c", "settings put system wifi_call_enable1 1")).waitFor() // Samsung S21, Samsung S25
            // Set preference to WiFi Calling (1 = WiFi preferred)
            Runtime.getRuntime().exec(arrayOf("su", "-c", "settings put system wifi_call_preferred1 1")).waitFor() // Samsung S21, Samsung S25
            // Tested on Pixel 10 (but need to set wifi call preferred manually)
            appendLog("WiFi Calling enabled")
        } catch (e: Exception) {
            appendLog("WiFi Calling enable error: ${e.message}")
        }
    }
    
    private fun disableWifiCalling() {
        appendLog("Disabling WiFi Calling...")
        try {
            // Keep enabled but set preference to cellular (2 = Cellular preferred)
            // TODO: add method for Pixel
            Runtime.getRuntime().exec(arrayOf("su", "-c", "settings put system wifi_call_enable1 1")).waitFor() // Samsung S21, Samsung S25
            Runtime.getRuntime().exec(arrayOf("su", "-c", "settings put system wifi_call_preferred1 2")).waitFor() // Samsung S21, Samsung S25
            // Tested on Pixel 10 (but need to set wifi call preferred manually)
            appendLog("WiFi Calling disabled (set to cellular preferred)")
        } catch (e: Exception) {
            appendLog("WiFi Calling disable error: ${e.message}")
        }
    }
    
    // ===== Screen Tap (Root) =====
    
    private fun tapScreen(x: Int, y: Int) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "input tap $x $y"))
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                appendLog("Tap failed at ($x, $y)")
            }
        } catch (e: Exception) {
            appendLog("Tap error: ${e.message}")
        }
    }
    
    // ===== Call Functions =====

    private fun normalizeDialNumber(s: String): String {
        return s.trim().filter { it.isDigit() }
    }

    private fun isEmergencyLikeNumber(s: String): Boolean {
        val n = normalizeDialNumber(s)
        return n in setOf("911", "112", "110", "119", "999")
    }

    private fun makeNormalCallToWifiCallingNumberForTestScenario1() {
        val numberToCall = wifiCallingNumber.trim()
        appendLog("TEST MODE: Scenario 1 normal CALL to: $numberToCall")

        try {
            Log.d("DataCollector", "=== START_DIALING_TEST_NORMAL: $numberToCall (Scenario 1) ===")
            val cmd = "am start -a android.intent.action.CALL -d tel:$numberToCall"
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
            val exitCode = process.waitFor()

            if (exitCode == 0) {
                Log.d("DataCollector", "=== START_DIALING_TEST_NORMAL: Dialed ===")
                appendLog("Test normal CALL command sent successfully")
            } else {
                Log.d("DataCollector", "=== START_DIALING_TEST_NORMAL: ERROR ===")
                appendLog("Test normal CALL failed (exit: $exitCode). Falling back to Intent...")
                fallbackCallWithIntent(numberToCall)
            }
        } catch (e: Exception) {
            appendLog("Test normal CALL error: ${e.message}. Falling back to Intent...")
            fallbackCallWithIntent(numberToCall)
        }
    }


    private fun makeCall() {
        // Scenario 3 uses WiFi Calling number, other use emergency number
        val numberToCall = if (currentPhase == 3 && wifiCallingNumber.isNotEmpty()) {
            wifiCallingNumber
        } else {
            emergencyNumber.ifEmpty { "911" }
        }
        appendLog("Attempting to call: $numberToCall (Scenario $currentPhase)")
        
        
        
        try {
            // if it's emergency number, need to use CALL_EMERGENCY
            val isEmergency = numberToCall in listOf("911", "110", "112", "119", "999")
            
            if (isEmergency) {
                appendLog("Using emergency call method...")
                // use CALL_EMERGENCY
                val cmd = "am start -a android.intent.action.CALL_EMERGENCY -d tel:$numberToCall"
                
                // Write to logcat for timing analysis
                Log.d("DataCollector", "=== START_DIALING: $numberToCall (Scenario $currentPhase) ===")

                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()
                val errorOutput = process.errorStream.bufferedReader().readText()
                appendLog("Running: su -c '$cmd'")
                appendLog("Exit code: $exitCode")
                if (exitCode != 0) {
                    // Write to logcat for timing analysis
                    Log.d("DataCollector", "=== START_DIALING: ERROR ===")
                    if (errorOutput.isNotEmpty()) {
                        appendLog("Error: ${errorOutput.take(100)}")
                    }

                    // Try alternative: su shell -c (some devices need this)
                    appendLog("Trying: su shell -c...")

                    // Write to logcat for timing analysis
                    Log.d("DataCollector", "=== START_DIALING_2: $numberToCall (Scenario $currentPhase) ===")
                    val process2 = Runtime.getRuntime().exec(arrayOf("su", "shell", "-c", cmd))
                    val exitCode2 = process2.waitFor()
                    appendLog("su shell -c exit: $exitCode2")
                    
                    if (exitCode2 != 0) {
                        // fallback: normal CALL (still via su)
                        Log.d("DataCollector", "=== START_DIALING_2: ERROR ===")
                        appendLog("Trying regular CALL for emergency...")

                        val cmd2 = "am start -a android.intent.action.CALL -d tel:$numberToCall"
                        Log.d("DataCollector", "=== START_DIALING_3: $numberToCall (Scenario $currentPhase) ===")

                        val process3 = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd2))
                        val exitCode3 = process3.waitFor()
                        val errorOutput3 = process3.errorStream.bufferedReader().readText()

                        appendLog("Running: su -c '$cmd2'")
                        appendLog("Exit code: $exitCode3")

                        if (exitCode3 != 0) {
                            Log.d("DataCollector", "=== START_DIALING_3: ERROR ===")
                            if (errorOutput3.isNotEmpty()) {
                                appendLog("Error: ${errorOutput3.take(100)}")
                            }

                            // Final fallback: Intent method
                            fallbackCallWithIntent(numberToCall)
                        } else {
                            Log.d("DataCollector", "=== START_DIALING_3: Dialed ===")
                            appendLog("Emergency call command sent (regular CALL)")
                        }
                    } else {
                        Log.d("DataCollector", "=== START_DIALING_2: Dialed ===")
                        appendLog("Emergency call command sent")
                    }

                } else {
                    // Write to logcat for timing analysis
                    Log.d("DataCollector", "=== START_DIALING: Dialed ===")
                    appendLog("Emergency call command sent")
                }
            } else {
                // use CALL
                // Write to logcat for timing analysis
                Log.d("DataCollector", "=== START_DIALING_NORMAL: $numberToCall (Scenario $currentPhase) ===")

                val cmd = "am start -a android.intent.action.CALL -d tel:$numberToCall"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()
                
                if (exitCode == 0) {
                    Log.d("DataCollector", "=== START_DIALING_NORMAL: Dialed ===")
                    appendLog("Call command sent successfully")
                } else {
                    Log.d("DataCollector", "=== START_DIALING_NORMAL: ERROR ===")
                    appendLog("Call command failed (exit: $exitCode)")
                    fallbackCallWithIntent(numberToCall)
                }
            }
        } catch (e: Exception) {
            appendLog("Call error: ${e.message}")
            fallbackCallWithIntent(numberToCall)
        }
    }
    
    private fun fallbackCallWithIntent(number: String) {
        try {
            appendLog("Trying fallback Intent method...")
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.CALL_PHONE) 
                == PackageManager.PERMISSION_GRANTED) {
                val callIntent = Intent(Intent.ACTION_CALL).apply {
                    data = Uri.parse("tel:$number")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                Log.d("DataCollector", "=== START_DIALING_FALLBACK: $number ===")
                startActivity(callIntent)
                Log.d("DataCollector", "=== START_DIALING_FALLBACK: Dialed ===")
                appendLog("Fallback call initiated")
            }
        } catch (e: Exception) {
            Log.d("DataCollector", "=== START_DIALING_FALLBACK: ERROR ===")
            appendLog("Fallback call error: ${e.message}")
        }
    }
    
    // ===== File Operations =====
    // {country_operator_modelName_deviceID_date_scenario#_experiment#_time_location}.{txt/pcap}
    private fun generateFileName(scenarioNum: String): String {
        val dateFormat = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
        val timeFormat = SimpleDateFormat("HHmmss", Locale.getDefault())
        val now = Date()
        val datePart = dateFormat.format(now)
        val timePart = timeFormat.format(now)
        val loc = if (gpsLocation.isEmpty()) "unknown" else gpsLocation
        val safeOperator = operatorName.replace(" ", "").replace("/", "_")
        val safeModel = modelName.replace(" ", "_")
        // Format: {country}_{operator}_{model}_{deviceId}_{date}_{scenario}_{experiment}_{time}_{location}.txt
        return "${countryCode}_${safeOperator}_${safeModel}_${deviceId}_${datePart}_${scenarioNum}_${currentMeasurementCount}_${timePart}_${loc}.txt"
    }
    
    private fun saveDataToFile(data: String, fileName: String) {
        try {
            val file = File(getExternalFilesDir(null), fileName)
            file.writeText(data)
        } catch (e: Exception) {
            appendLog("Save error: ${e.message}")
        }
    }
    
    // ===== Logcat Collection =====
    private fun clearLogcat() {
        try {
            // Increase buffer size and clear all buffers that we capture
            // Using su -c because some devices require root for these operations
            val buffers = listOf("radio", "events", "main", "system", "crash", "kernel")
            for (buffer in buffers) {
                // Increase buffer size to 16MB to avoid log rotation (needs root on some devices)
                Runtime.getRuntime().exec(arrayOf("su", "-c", "logcat -G 16M -b $buffer")).waitFor()
                // Clear the buffer
                Runtime.getRuntime().exec(arrayOf("su", "-c", "logcat -b $buffer -c")).waitFor()
            }
            appendLog("Logcat cleared and buffer size increased to 16MB")
        } catch (e: Exception) {
            appendLog("Clear logcat error: ${e.message}")
        }
    }

    /**
     * Capture multiple logcat buffers to separate temp files under /data/local/tmp
     * Returns a map of buffer name to temp file path (or Error:...)
     */
    private fun captureLogcatMultiBuffer(startTimeStr: String): Map<String, String> {
        val buffers = listOf("radio", "events", "main", "system", "crash", "kernel")
        val results = mutableMapOf<String, String>()

        appendLog("Logcat capture startTime=-T '$startTimeStr'")

        for (buffer in buffers) {
            try {
                val dumpPath = "/data/local/tmp/logcat_${buffer}.txt"
                appendLog("Capturing logcat -b $buffer since $startTimeStr...")

                val cmd = "logcat -b $buffer -T '$startTimeStr' -d > $dumpPath"
                val writeProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val writeExit = writeProcess.waitFor()

                if (writeExit == 0) {
                    results[buffer] = dumpPath
                } else {
                    results[buffer] = "Error capturing buffer (exit: $writeExit)"
                }
            } catch (e: Exception) {
                results[buffer] = "Error: ${e.message}"
            }
        }

        return results
    }



    /**
     * Save multiple logcat buffers to separate files without reading them into memory.
     * Copies /data/local/tmp/logcat_<buffer>.txt -> app external files dir.
     */
    private fun saveLogcatMultiBuffer(baseFileName: String, startTimeStr: String) {
        val bufferData = captureLogcatMultiBuffer(startTimeStr)
        val outDir = getExternalFilesDir(null)

        if (outDir == null) {
            appendLog("Save error: external files dir is null")
            return
        }

        val outDirPath = outDir.absolutePath

        for ((buffer, tmpPath) in bufferData) {
            if (tmpPath.startsWith("Error")) {
                appendLog("Skip $buffer: $tmpPath")
                continue
            }

            val outPath = "$outDirPath/${baseFileName}_${buffer}.txt"

            try {
                val cpExit = Runtime.getRuntime().exec(
                    arrayOf("su", "-c", "cp $tmpPath $outPath")
                ).waitFor()

                if (cpExit == 0) {
                    appendLog("Saved: ${baseFileName}_${buffer}.txt")
                } else {
                    appendLog("Save error: cp failed for $buffer (exit: $cpExit)")
                }

                Runtime.getRuntime().exec(arrayOf("su", "-c", "rm -f $tmpPath")).waitFor()
            } catch (e: Exception) {
                appendLog("Save error ($buffer): ${e.message}")
            }
        }
    }


    // ===== Utilities =====
    
    private fun appendLog(message: String) {
        runOnUiThread {
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            infoTextView.text = "[$timestamp] $message\n${infoTextView.text}"
        }
    }
    
    // ===== Permissions =====
    
    private fun checkPermissions(): Boolean {
        return requiredPermissions.all {
            ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }
    }
    
    private fun requestPermissions() {
        ActivityCompat.requestPermissions(this, requiredPermissions, PERMISSION_REQUEST_CODE)
    }
    
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                appendLog("All permissions granted")
            } else {
                Toast.makeText(this, "Some permissions denied", Toast.LENGTH_LONG).show()
            }
        }
    }
    
    @SuppressLint("HardwareIds")
    private fun getHashedImei(): String {
        // Try to get IMEI via root (required for Android 10+)
        val imei = getImeiViaRoot()
        
        return if (imei.isNotEmpty()) {
            // MD5 hash
            val md = java.security.MessageDigest.getInstance("MD5")
            val digest = md.digest(imei.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        } else {
            // Fallback to ANDROID_ID
            Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        }
    }
    
    private fun getImeiViaRoot(): String {
        // Method 1: Try dumpsys iphonesubinfo
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "dumpsys iphonesubinfo"))
            val reader = process.inputStream.bufferedReader()
            val output = reader.readText()
            reader.close()
            process.waitFor()
            
            // Look for "Device ID" or "IMEI" line
            val regex = "(?:Device ID|IMEI)\\s*[=:]?\\s*(\\d{15})".toRegex(RegexOption.IGNORE_CASE)
            val match = regex.find(output)
            if (match != null) {
                return match.groupValues[1]
            }
        } catch (e: Exception) { }
        
        // Method 2: Try getprop
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "getprop persist.radio.imei"))
            val reader = process.inputStream.bufferedReader()
            val output = reader.readText().trim()
            reader.close()
            process.waitFor()
            
            if (output.length >= 15 && output.all { it.isDigit() }) {
                return output.take(15)
            }
        } catch (e: Exception) { }
        
        // Method 3: Try reading from efs (Samsung specific)
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "cat /efs/FactoryApp/serial_no"))
            val reader = process.inputStream.bufferedReader()
            val output = reader.readText().trim()
            reader.close()
            process.waitFor()
            
            if (output.length >= 15) {
                return output.take(15)
            }
        } catch (e: Exception) { }
        
        return ""
    }
    // ===== File Size Calculation =====

    /**
     * Calculate total size of files in /sdcard/Android/data/com.emergency.datacollector/files
     * and update txtFileSize TextView
     */
    private fun updateFileSize() {
        thread {
            try {
                val dir = getExternalFilesDir(null)
                if (dir == null || !dir.exists()) {
                    handler.post { txtFileSize.text = "Total log size: 0.00 MB" }
                    return@thread
                }

                val totalBytes = dir.walkTopDown()
                    .filter { it.isFile }
                    .sumOf { it.length() }

                val gb = totalBytes / (1024.0 * 1024.0 * 1024.0)
                val display = if (gb >= 1.0) {
                    String.format("%.2f GB", gb)
                } else {
                    val mb = totalBytes / (1024.0 * 1024.0)
                    String.format("%.2f MB", mb)
                }

                handler.post {
                    txtFileSize.text = "Total log size: $display"
                }
            } catch (e: Exception) {
                handler.post {
                    txtFileSize.text = "Total log size: Error"
                    appendLog("File size calculation error: ${e.message}")
                }
            }
        }
    }

    // ===== tcpdump Control =====

    /**
     * Ensure tcpdump binary exists in /data/local/tmp
     * Copy from assets (tcpdump_64 or tcpdump_32) based on CPU architecture
     * Uses the same method as Perfetto config
     */
    private fun ensureTcpdumpBinary(): Boolean {
        val target = "/data/local/tmp/tcpdump"

        return try {
            // 1) If tcpdump already exists and is executable (check as root)
            val (_, outCheck) = runSuRoot("sh -c 'test -x \"$target\"; echo \$?'")
            if (outCheck.trim().endsWith("0")) {
                appendLog("tcpdump binary already exists: $target")
                return true
            }

            // 2) Pick asset by ABI
            val cpuAbi = Build.SUPPORTED_ABIS[0]
            appendLog("Device CPU ABI: $cpuAbi")

            val assetFileName = when {
                cpuAbi.contains("arm64", ignoreCase = true) || cpuAbi.contains("v8a", ignoreCase = true) -> {
                    appendLog("Using 64-bit tcpdump binary")
                    "tcpdump_64"
                }
                cpuAbi.contains("armeabi", ignoreCase = true) || cpuAbi.contains("v7a", ignoreCase = true) -> {
                    appendLog("Using 32-bit tcpdump binary")
                    "tcpdump_32"
                }
                cpuAbi.contains("x86_64", ignoreCase = true) -> {
                    appendLog("x86_64 detected, using 64-bit binary")
                    "tcpdump_64"
                }
                cpuAbi.contains("x86", ignoreCase = true) -> {
                    appendLog("x86 detected, using 32-bit binary")
                    "tcpdump_32"
                }
                else -> {
                    appendLog("tcpdump error: Unsupported CPU architecture: $cpuAbi")
                    return false
                }
            }

            // 3) Copy assets -> internal temp file
            val localFile = File(filesDir, "tcpdump_temp")
            try {
                assets.open(assetFileName).use { input ->
                    localFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
            } catch (e: Exception) {
                appendLog("tcpdump error: Failed to copy asset '$assetFileName': ${e.message}")
                return false
            }

            if (!localFile.exists() || localFile.length() <= 0L) {
                appendLog("tcpdump error: Failed to copy from assets (empty temp file)")
                return false
            }
            appendLog("tcpdump copied to internal storage (${localFile.length()} bytes)")

            // 4) Copy internal -> /data/local/tmp/tcpdump as root + chmod
            val cmd = "cp \"${localFile.absolutePath}\" \"$target\" && chmod 755 \"$target\""
            val cpExit = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd)).waitFor()
            if (cpExit != 0) {
                appendLog("tcpdump error: Failed to copy to $target (exit: $cpExit)")
                return false
            }

            // 5) Verify executable as root
            val (_, outVerify) = runSuRoot("sh -c 'test -x \"$target\"; echo \$?'")
            if (!outVerify.trim().endsWith("0")) {
                appendLog("tcpdump error: Binary not executable after setup")
                val (_, outLs) = runSuRoot("ls -l \"$target\" 2>&1")
                appendLog("Debug ls: ${outLs.take(200)}")
                return false
            }

            appendLog("tcpdump binary ready: $target")

            // 6) Optional: version check as root
            val (exitTest, outTest) = runSuRoot("sh -c '$target --version 2>&1 | head -1'")
            if (exitTest == 0 && outTest.isNotBlank()) {
                appendLog("tcpdump version: ${outTest.trim().take(80)}")
            } else {
                appendLog("tcpdump version check: exit=$exitTest")
            }

            // 7) Cleanup temp
            try {
                localFile.delete()
            } catch (_: Exception) {
            }

            true
        } catch (e: Exception) {
            appendLog("tcpdump setup error: ${e.message}")
            e.printStackTrace()
            false
        }
    }

    /**
     * Start tcpdump to capture all interfaces
     * Filename: {baseFileName}_tcpdump.pcap
     */
    private fun startTcpdumpUntilOk(
        baseFileName: String,
        retryDelayMs: Long = delayToolsRetry,
        onStarted: (Boolean) -> Unit
    ) {
        val pcapPath = "/sdcard/${baseFileName}_tcpdump.pcap"
        val tcpdumpBin = "/data/local/tmp/tcpdump"

        fun attempt() {
            if (shouldStop || !isCollectionRunning) {
                handler.post { onStarted(false) }
                return
            }

            thread {
                try {
                    if (!ensureTcpdumpBinary()) {
                        handler.post {
                            appendLog("tcpdump not ready. Retry in ${retryDelayMs}ms")
                            handler.postDelayed({ attempt() }, retryDelayMs)
                        }
                        return@thread
                    }

                    // Delete old file (root)
                    runSuRoot("rm -f \"$pcapPath\"")

                    // Start tcpdump as ROOT (important)
                    // Use sh -c so "&" and "$!" are handled reliably.
                    val cmd = "sh -c '$tcpdumpBin -i any -w \"$pcapPath\" >/dev/null 2>&1 & echo \$!'"
                    val (exit, output) = runSuRoot(cmd)

                    val pid = output.trim().lines().lastOrNull()?.trim()?.toIntOrNull()
                    if (exit != 0 || pid == null || pid <= 0) {
                        handler.post {
                            appendLog("tcpdump start failed (exit=$exit): ${output.trim().take(200)}")
                            handler.postDelayed({ attempt() }, retryDelayMs)
                        }
                        return@thread
                    }

                    // Wait 1s then confirm it's still alive
                    Thread.sleep(1000)

                    val (_, outPs) = runSuRoot("sh -c 'ps -A 2>/dev/null | grep \" $pid \" | grep tcpdump | grep -v grep'")
                    if (outPs.isBlank()) {
                        handler.post {
                            appendLog("tcpdump died immediately (pid=$pid). Retry in ${retryDelayMs}ms")
                            handler.postDelayed({ attempt() }, retryDelayMs)
                        }
                        return@thread
                    }

                    handler.post {
                        tcpdumpPid = pid
                        appendLog("tcpdump started (pid=$pid): ${baseFileName}_tcpdump.pcap")
                        onStarted(true)
                    }
                } catch (e: Exception) {
                    handler.post {
                        appendLog("tcpdump start error: ${e.message}. Retry in ${retryDelayMs}ms")
                        handler.postDelayed({ attempt() }, retryDelayMs)
                    }
                }
            }
        }

        attempt()
    }


    private fun stopTcpdump(baseFileName: String) {
        val pid = tcpdumpPid
        tcpdumpPid = null

        val pcapPath = "/sdcard/${baseFileName}_tcpdump.pcap"
        val outDir = getExternalFilesDir(null)
        if (outDir == null) {
            appendLog("tcpdump stop error: external files dir is null")
            return
        }
        val finalPath = "${outDir.absolutePath}/${baseFileName}_tcpdump.pcap"

        thread {
            try {
                if (pid != null) {
                    handler.post { appendLog("Stopping tcpdump (pid=$pid)...") }

                    // TERM first (root)
                    runSuRoot("kill -TERM $pid 2>/dev/null")

                    // Wait up to 5s for exit
                    var waited = 0
                    while (waited < 50) {
                        val (_, psOut) = runSuRoot("sh -c 'ps -A 2>/dev/null | grep \" $pid \" | grep tcpdump | grep -v grep'")
                        if (psOut.isBlank()) break
                        Thread.sleep(100)
                        waited++
                    }

                    // Hard kill if still alive
                    if (waited >= 50) {
                        runSuRoot("kill -9 $pid 2>/dev/null")
                    }

                    // Give filesystem a moment to flush
                    Thread.sleep(800)
                }

                // Check /sdcard file exists and non-empty (root)
                val (_, outCheck) = runSuRoot("sh -c 'test -s \"$pcapPath\"; echo \$?'")
                if (!outCheck.trim().endsWith("0")) {
                    handler.post { appendLog("tcpdump warning: pcap file missing or empty: $pcapPath") }
                    return@thread
                }

                // Copy to app external dir + chmod for adb pull
                val cpExit = Runtime.getRuntime().exec(
                    arrayOf("su", "-c", "cp \"$pcapPath\" \"$finalPath\" && chmod 644 \"$finalPath\"")
                ).waitFor()

                if (cpExit != 0) {
                    handler.post { appendLog("tcpdump copy failed (exit=$cpExit)") }
                    return@thread
                }

                // Remove temp file
                runSuRoot("rm -f \"$pcapPath\"")

                // Get size (root)
                val (_, outSize) = runSuRoot("sh -c 'stat -c %s \"$finalPath\" 2>/dev/null || wc -c < \"$finalPath\"'")
                val fileSize = outSize.trim().toLongOrNull() ?: 0L
                val fileSizeKB = fileSize / 1024.0

                handler.post {
                    appendLog("tcpdump stopped: ${baseFileName}_tcpdump.pcap (%.2f KB)".format(fileSizeKB))
                }
            } catch (e: Exception) {
                handler.post { appendLog("tcpdump stop error: ${e.message}") }
            }
        }
    }
    // ===== Network Monitoring Functions =====

    private fun startNetworkMonitoring() {
        if (isMonitoringNetwork) return

        isMonitoringNetwork = true
        appendLog("📡 Starting network monitoring...")
        Log.d("NetworkMonitor", "=== NETWORK_MONITORING_STARTED ===")

        networkMonitorHandler.post(ratMonitorRunnable)
        networkMonitorHandler.post(cellInfoMonitorRunnable)
        networkMonitorHandler.post(wifiInfoMonitorRunnable)
    }

    private fun stopNetworkMonitoring() {
        if (!isMonitoringNetwork) return

        isMonitoringNetwork = false
        appendLog("📡 Stopping network monitoring...")
        Log.d("NetworkMonitor", "=== NETWORK_MONITORING_STOPPED ===")

        networkMonitorHandler.removeCallbacks(ratMonitorRunnable)
        networkMonitorHandler.removeCallbacks(cellInfoMonitorRunnable)
        networkMonitorHandler.removeCallbacks(wifiInfoMonitorRunnable)
    }

    private fun logRATType() {
        try {
            val telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            val voiceNetworkType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                getNetworkTypeString(telephonyManager.voiceNetworkType)
            } else {
                "N/A"
            }

            val dataNetworkType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                getNetworkTypeString(telephonyManager.dataNetworkType)
            } else {
                "N/A"
            }

            Log.d("NetworkMonitor", "Current RAT type: {VoiceNetwork: $voiceNetworkType, DataNetwork: $dataNetworkType}")
        } catch (e: Exception) {
            Log.e("NetworkMonitor", "RAT type error: ${e.message}")
        }
    }

    private fun logCellInfo() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    this,
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                return
            }

            val telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            telephonyManager.requestCellInfoUpdate(
                java.util.concurrent.Executor { runnable -> networkMonitorHandler.post(runnable) },
                object : TelephonyManager.CellInfoCallback() {
                    override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                        val cellInfoStr = cellInfo.joinToString(", ") { cell ->
                            "registered=${cell.isRegistered}, timestamp=${cell.timeStamp}, $cell"
                        }
                        Log.d("NetworkMonitor", "Cell Info for current subscription: [$cellInfoStr]")
                    }

                    override fun onError(errorCode: Int, detail: Throwable?) {
                        Log.e("NetworkMonitor", "Cell info error: code=$errorCode, detail=${detail?.message}")
                    }
                }
            )
        } catch (e: Exception) {
            Log.e("NetworkMonitor", "Cell info error: ${e.message}")
        }
    }

    private fun logWiFiInfo() {
        try {
            if (ActivityCompat.checkSelfPermission(
                    this,
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                return
            }

            val isWiFiEnabled = wifiManager.isWifiEnabled
            val results = wifiManager.scanResults

            if (results == null || results.isEmpty()) {
                Log.d("NetworkMonitor", "Nearby WiFi Info: [WiFi Enabled: $isWiFiEnabled, No networks found]")
            } else {
                val wifiInfoStr = results.joinToString(", ") { it.toString() }
                 Log.d("NetworkMonitor", "Nearby WiFi Info: [$wifiInfoStr]")
            }
        } catch (e: Exception) {
            Log.e("NetworkMonitor", "WiFi info error: ${e.message}")
        }
    }

    private fun getNetworkTypeString(networkType: Int): String {
        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_UNKNOWN -> "UNKNOWN"
            TelephonyManager.NETWORK_TYPE_GPRS -> "GPRS"
            TelephonyManager.NETWORK_TYPE_EDGE -> "EDGE"
            TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS"
            TelephonyManager.NETWORK_TYPE_CDMA -> "CDMA"
            TelephonyManager.NETWORK_TYPE_EVDO_0 -> "EVDO_0"
            TelephonyManager.NETWORK_TYPE_EVDO_A -> "EVDO_A"
            TelephonyManager.NETWORK_TYPE_1xRTT -> "1xRTT"
            TelephonyManager.NETWORK_TYPE_HSDPA -> "HSDPA"
            TelephonyManager.NETWORK_TYPE_HSUPA -> "HSUPA"
            TelephonyManager.NETWORK_TYPE_HSPA -> "HSPA"
            TelephonyManager.NETWORK_TYPE_IDEN -> "IDEN"
            TelephonyManager.NETWORK_TYPE_EVDO_B -> "EVDO_B"
            TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
            TelephonyManager.NETWORK_TYPE_EHRPD -> "EHRPD"
            TelephonyManager.NETWORK_TYPE_HSPAP -> "HSPAP"
            TelephonyManager.NETWORK_TYPE_GSM -> "GSM"
            TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "TD_SCDMA"
            TelephonyManager.NETWORK_TYPE_IWLAN -> "IWLAN"
            else -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && networkType == TelephonyManager.NETWORK_TYPE_NR) {
                    "NR"
                } else {
                    "UNKNOWN($networkType)"
                }
            }
        }
    }

    // ===== Airplane Mode Control =====

    private fun enableAirplaneMode() {
        appendLog("Enabling Airplane Mode...")
        try {
            Runtime.getRuntime().exec(arrayOf("su", "-c", "cmd connectivity airplane-mode enable")).waitFor()
            appendLog("Airplane Mode enabled")
        } catch (e: Exception) {
            appendLog("Airplane Mode enable error: ${e.message}")
        }
    }

    private fun disableAirplaneMode() {
        appendLog("Disabling Airplane Mode...")
        try {
            Runtime.getRuntime().exec(arrayOf("su", "-c", "cmd connectivity airplane-mode disable")).waitFor()
            appendLog("Airplane Mode disabled")
        } catch (e: Exception) {
            appendLog("Airplane Mode disable error: ${e.message}")
        }
    }


    private fun startIpsecMonitoring(baseFileName: String) {
        // Check if we should monitor IPsec for this scenario
        val shouldMonitor = when (currentPhase) {
            3 -> true  // Always monitor for Scenario #3
            1, 2 -> modelName.startsWith("SM-", ignoreCase = true)  // Only Samsung for Scenario #1 & #2
            else -> false
        }

        if (!shouldMonitor) {
            appendLog("IPsec monitoring skipped for this scenario/device")
            return
        }

        // ✅ Store the base filename for this measurement
        currentIpsecBaseFileName = baseFileName

        isMonitoringIpsec = true
        lastIpsecOutput = ""
        appendLog("🔐 Starting IPsec state monitoring...")
        Log.d("IpsecMonitor", "=== IPSEC_MONITORING_STARTED ===")

        // Create/clear the IPsec log file
        val outDir = getExternalFilesDir(null)
        if (outDir != null) {
            val ipsecFile = File(outDir, "${baseFileName}_ipsec_info.txt")
            try {
                ipsecFile.writeText("")  // Clear file
                appendLog("IPsec log file created: ${baseFileName}_ipsec_info.txt")
            } catch (e: Exception) {
                appendLog("IPsec file creation error: ${e.message}")
            }
        }

        ipsecMonitorHandler.post(ipsecMonitorRunnable)
    }

    private fun stopIpsecMonitoring() {
        if (!isMonitoringIpsec) return

        isMonitoringIpsec = false
        lastIpsecOutput = ""
        currentIpsecBaseFileName = ""  // ✅ Clear the stored filename
        appendLog("🔐 Stopping IPsec state monitoring...")
        Log.d("IpsecMonitor", "=== IPSEC_MONITORING_STOPPED ===")

        ipsecMonitorHandler.removeCallbacks(ipsecMonitorRunnable)
    }

    private fun logIpsecState() {
        // ✅ Check if we have a valid base filename
        if (currentIpsecBaseFileName.isEmpty()) {
            Log.e("IpsecMonitor", "IPsec monitoring error: no base filename set")
            return
        }

        thread {
            try {
                val cmd = "ip --json xfrm state"
                val (exitCode, output) = runSuRoot(cmd)

                if (exitCode != 0) {
                    handler.post {
                        Log.e("IpsecMonitor", "IPsec state query failed: exit=$exitCode")
                    }
                    return@thread
                }

                val trimmedOutput = output.trim()

                // Skip if output is empty or "[]"
                if (trimmedOutput.isEmpty() || trimmedOutput == "[]") {
                    return@thread
                }

                // Only log if output changed
                if (trimmedOutput != lastIpsecOutput) {
                    lastIpsecOutput = trimmedOutput

                    val timestamp = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
                    val logEntry = "$timestamp\n$trimmedOutput\n\n"

                    // Append to file
                    val outDir = getExternalFilesDir(null)
                    if (outDir != null) {
                        // ✅ Use the stored base filename instead of generating a new one
                        val ipsecFile = File(outDir, "${currentIpsecBaseFileName}_ipsec_info.txt")

                        try {
                            ipsecFile.appendText(logEntry)
                            Log.d("IpsecMonitor", "IPsec state changed and logged")
                        } catch (e: Exception) {
                            handler.post {
                                Log.e("IpsecMonitor", "IPsec file write error: ${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                handler.post {
                    Log.e("IpsecMonitor", "IPsec monitoring error: ${e.message}")
                }
            }
        }
    }


}
