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
    
    // Scenario selection
    private var runScenario1 = true
    private var runScenario2 = true
    private var runScenario3 = true
    private var runScenario4 = true
    
    // Current phase: 1 = Home Carrier, 2 = Visitor Carrier
    private var currentPhase = 1
    private var currentMeasurementCount = 0
    private var totalMeasurementsPerPhase = 10
    private var isCollectionRunning = false
    private var shouldStop = false
    
    private val handler = Handler(Looper.getMainLooper())
    
    // Timing (loaded from strings.xml in onCreate)
    private var delayFridaReady = 3000L
    private var delayCallDuration = 8000L
    private var delayAfterHangup = 2000L
    private var delayBetweenCalls = 5000L
    
    // End call button coordinates (device-specific)
    private var endCallButtonX = 0
    private var endCallButtonY = 0
    
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

        
        // Setup experiments spinner (1-10)
        val experimentOptions = (1..10).toList()
        val spinnerAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, experimentOptions)
        spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerExperimentsCount.adapter = spinnerAdapter
        spinnerExperimentsCount.setSelection(9)  // Default to 10 (index 9)
        
        // Load MCC-MNC database for operator lookup
        MccMncLookup.load(this)
        
        // Load emergency number from strings.xml
        emergencyNumber = getString(R.string.emergency_number)
        dialNumber = emergencyNumber
        
        // Load timing configuration from strings.xml
        delayFridaReady = getString(R.string.delay_frida_ready).toLong()
        delayCallDuration = getString(R.string.delay_call_duration).toLong()
        delayAfterHangup = getString(R.string.delay_after_hangup).toLong()
        delayBetweenCalls = getString(R.string.delay_between_calls).toLong()
        
        // Get device ID: IMEI hashed with MD5 (first 12 chars)
        deviceId = getHashedImei()
        
        // Initialize device-specific end call button coordinates
        initEndCallButtonCoordinates()
        
        updateMccMnc()
        
        // GPS refresh button
        btnRefreshGps.setOnClickListener {
            refreshGpsLocation()
        }
        
        btnStartExperiment.setOnClickListener {
            if (checkPermissions()) {
                // Update config from UI
                experimentsPerScenario = spinnerExperimentsCount.selectedItem as Int
                totalMeasurementsPerPhase = experimentsPerScenario
                wifiCallingNumber = editWifiCallingNumber.text.toString()
                runScenario1 = checkScenario1.isChecked
                runScenario2 = checkScenario2.isChecked
                runScenario3 = checkScenario3.isChecked
                runScenario4 = checkScenario4.isChecked
                
                startFullCollection()
            } else {
                requestPermissions()
            }
        }
        
        btnStopExperiment.setOnClickListener {
            stopCollection()
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
        // Ensure SIM is enabled when app resumes
        ensureSimEnabled()
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
        
        handler.postDelayed({
            if (shouldStop) {
                finishCollection("Stopped by user")
                return@postDelayed
            }
            
            when (firstPhase) {
                1 -> startPhase1Measurements()
                2 -> startPhase2()
                3 -> startPhase3()
                4 -> startPhase4()
            }
        }, 3000)
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
                connection.connectTimeout = 10000
                connection.readTimeout = 15000
                
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
                connection.connectTimeout = 10000
                connection.readTimeout = 15000
                
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

    private fun startPhase1Measurements() {
        appendLog("\n=== Scenario 1: Home Carrier (SIM Enabled, WiFi Disabled) ===")
        
        // Scenario #1: Enable SIM slot 0 and disable WiFi connection
        enableSim()
        disableWifi()
        disableWifiCalling()
        
        handler.postDelayed({
            if (shouldStop) {
                finishCollection("Stopped by user")
                return@postDelayed
            }
            currentPhase = 1
            currentMeasurementCount = 0
            performMeasurement()
        }, 3000)
    }
    
    private fun startPhase2() {
        appendLog("\n=== Scenario 2: Visitor Carrier (SIM Disabled, WiFi Disabled) ===")
        // updateProgress("Scenario 2: Configuring...")
        
        // Scenario #2, Disable SIM slot 0 and disable WiFi connection
        disableSim()
        disableWifi()
        disableWifiCalling()
        
        handler.postDelayed({
            if (shouldStop) {
                finishCollection("Stopped by user")
                return@postDelayed
            }
            
            currentPhase = 2
            currentMeasurementCount = 0
            performMeasurement()
        }, 3000)
    }
    
    private fun startPhase3() {
        appendLog("\n=== Scenario 3: WiFi Calling (SIM Enabled, WiFi Enabled, WiFi Calling Enabled) ===")
        // updateProgress("Scenario 3: Configuring WiFi Calling...")
        
        // Scenario #3: Enable WiFi connection and WiFi calling
        enableSim()
        
        handler.postDelayed({
            enableWifi()
            appendLog("Waiting for WiFi to connect...")
            
            handler.postDelayed({
                enableWifiCalling()
                appendLog("Waiting for WiFi Calling to register...")
                
                handler.postDelayed({
                    if (shouldStop) {
                        finishCollection("Stopped by user")
                        return@postDelayed
                    }
                    
                    currentPhase = 3
                    currentMeasurementCount = 0
                    performMeasurement()
                }, 5000)  // Wait for WiFi Calling to register (increased from 2000)
            }, 8000)  // Wait for WiFi to connect (increased from 3000)
        }, 2000)  // Wait for SIM
    }

    private fun startPhase4() {
        appendLog("\n=== Scenario 4: Satellite SOS ===")

        // Disable WiFi for satellite scenario
        disableWifi()

        handler.postDelayed({
            if (shouldStop) {
                finishCollection("Stopped by user")
                return@postDelayed
            }

            currentPhase = 4
            currentMeasurementCount = 0
            performMeasurement()
        }, 3000)
    }
    
    private fun performMeasurement() {
        if (shouldStop) {
            finishCollection("Stopped by user")
            return
        }
        
        currentMeasurementCount++
        val phaseLabel = currentPhase.toString()  // "1", "2", "3", or "4"
        
        appendLog("--- Measurement #$currentMeasurementCount (Scenario $currentPhase) ---")
        
        // Generate filename for this measurement (used for both logcat and scat)
        val baseFileName = generateFileName(phaseLabel).replace(".txt", "")
        val pcapFileName = "$baseFileName.pcap"
        
        // Step 1: Clear logcat buffer
        clearLogcat()
        
        // Step 2: Start Frida blocker (must be before SCAT)
        appendLog("Starting Frida blocker...")

        val fridaEndpoint = if (currentPhase == 4) "/start-frida-satellite" else "/start-frida"
        val deviceTypeBody = """{"device_type": "${getDeviceType()}"}"""
        sendFridaCommand(fridaEndpoint, deviceTypeBody) { success ->
            if (!success) {
                appendLog("Warning: Frida start failed, continuing anyway")
            } else {
                appendLog("Frida blocker started")
            }

            // Function to proceed to making the call (for phases 1, 2, 3)
            val proceedToMakeCall: () -> Unit = {
                handler.postDelayed({
                    if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                    // Step 4: Make the call
                    appendLog("Dialing...")
                    makeCall()

                    // Step 5: Wait for call duration, then hang up using tapScreen
                    handler.postDelayed({
                        if (shouldStop) { endCall(); finishCollection("Stopped by user"); return@postDelayed }

                        appendLog("Ending call via tap...")
                        tapScreen(endCallButtonX, endCallButtonY)

                        // Step 6: Wait after hangup, then stop SCAT first
                        handler.postDelayed({
                            if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                            // Function to proceed to kill phone app
                            val proceedToKillPhone: () -> Unit = {
                                // Step 7: Kill phone app
                                handler.postDelayed({
                                    appendLog("Killing phone app...")
                                    sendFridaCommand("/pkill-phone") { _ ->
                                        // Wait 500ms then send second pkill
                                        handler.postDelayed({
                                            sendFridaCommand("/pkill-phone") { _ ->
                                                appendLog("Phone app killed")

                                                // Step 8: Capture logcat and save (multiple buffers)
                                                handler.postDelayed({
                                                    if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                                                    appendLog("Capturing logcat (multiple buffers)...")
                                                    
                                                    // Generate base filename (without .txt extension)
                                                    val baseFileName = generateFileName(phaseLabel).replace(".txt", "")
                                                    
                                                    // Save each logcat buffer to separate file
                                                    saveLogcatMultiBuffer(baseFileName)
                                                    
                                                    appendLog("Saved: ${baseFileName}_*.txt")

                                                    // Step 9: Next measurement or next scenario
                                                    handler.postDelayed({
                                                        if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                                                        if (currentMeasurementCount < totalMeasurementsPerPhase) {
                                                            performMeasurement()
                                                        } else {
                                                            appendLog("Scenario $currentPhase Complete!")
                                                            val nextPhase = getNextEnabledPhase(currentPhase)
                                                            if (nextPhase != null) {
                                                                when (nextPhase) {
                                                                    1 -> startPhase1Measurements()
                                                                    2 -> startPhase2()
                                                                    3 -> startPhase3()
                                                                    4 -> startPhase4()
                                                                }
                                                            } else {
                                                                finishCollection("All measurements complete!")
                                                            }
                                                        }
                                                    }, delayBetweenCalls)
                                                }, 1000)  // Brief wait after kill
                                            }
                                        }, 500)  // Delay between pkills
                                    }
                                }, 1000)  // Wait 1s before pkill
                            }

                            // Step 6.5: Stop SCAT and WAIT for response before killing phone
                            if (enableScat) {
                                appendLog("Stopping SCAT recording...")
                                sendScatCommand("/stop-scat", null) { scatStopSuccess ->
                                    if (scatStopSuccess) {
                                        appendLog("SCAT stopped successfully")
                                    } else {
                                        appendLog("Warning: SCAT stop failed")
                                    }
                                    // WAIT for scat callback to return, then proceed
                                    proceedToKillPhone()
                                }
                            } else {
                                proceedToKillPhone()
                            }
                        }, delayAfterHangup)
                    }, delayCallDuration)
                }, delayFridaReady)
            }

            // Function for Satellite flow (Phase 4)
            val proceedToSatellite: () -> Unit = {
                handler.postDelayed({
                    if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                    appendLog("Launching Satellite SOS questionnaire...")

                    try {
                        // Launch Satellite SOS app
                        val cmd = "am start -n com.google.android.apps.stargate/.questionnaire.QuestionnaireHomeActivity -a com.google.android.apps.stargate.ACTION_ESOS_QUESTIONNAIRE"
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

                                // Monitor satellite connection
                                appendLog("Monitoring satellite connection...")
                                monitorSatelliteConnected { connected ->
                                    if (connected) {
                                        appendLog("Satellite connected! Proceeding...")

                                        // Step 5: Wait after hangup, then stop SCAT first
                                        handler.postDelayed({
                                            if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                                            // Function to proceed to kill phone app
                                            val proceedToKillPhone: () -> Unit = {
                                                // Step 7: Kill phone app
                                                handler.postDelayed({
                                                    appendLog("Killing phone app...")
                                                    sendFridaCommand("/pkill-phone") { _ ->
                                                        // Wait 500ms then send second pkill
                                                        handler.postDelayed({
                                                            sendFridaCommand("/pkill-phone") { _ ->
                                                                appendLog("Phone app killed")

                                                                // Step 8: Capture logcat and save (multiple buffers)
                                                                handler.postDelayed({
                                                                    if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                                                                    appendLog("Capturing logcat (multiple buffers)...")
                                                                    
                                                                    // Generate base filename (without .txt extension)
                                                                    val baseFileName = generateFileName(phaseLabel).replace(".txt", "")
                                                                    
                                                                    // Save each logcat buffer to separate file
                                                                    saveLogcatMultiBuffer(baseFileName)
                                                                    
                                                                    appendLog("Saved: ${baseFileName}_*.txt")

                                                                    // Next measurement or next scenario
                                                                    handler.postDelayed({
                                                                        if (shouldStop) { finishCollection("Stopped by user"); return@postDelayed }

                                                                        if (currentMeasurementCount < totalMeasurementsPerPhase) {
                                                                            performMeasurement()
                                                                        } else {
                                                                            appendLog("Scenario $currentPhase Complete!")
                                                                            val nextPhase = getNextEnabledPhase(currentPhase)
                                                                            if (nextPhase != null) {
                                                                                when (nextPhase) {
                                                                                    1 -> startPhase1Measurements()
                                                                                    2 -> startPhase2()
                                                                                    3 -> startPhase3()
                                                                                    4 -> startPhase4()
                                                                                }
                                                                            } else {
                                                                                finishCollection("All measurements complete!")
                                                                            }
                                                                        }
                                                                    }, delayBetweenCalls)
                                                                }, 1000)  // Brief wait after kill
                                                            }
                                                        }, 500)  // Delay between pkills
                                                    }
                                                }, 1000)  // Wait 1s before pkill
                                            }

                                            // Stop SCAT and WAIT for response before killing phone
                                            if (enableScat) {
                                                appendLog("Stopping SCAT recording...")
                                                sendScatCommand("/stop-scat", null) { scatStopSuccess ->
                                                    if (scatStopSuccess) {
                                                        appendLog("SCAT stopped successfully")
                                                    } else {
                                                        appendLog("Warning: SCAT stop failed")
                                                    }
                                                    proceedToKillPhone()
                                                }
                                            } else {
                                                proceedToKillPhone()
                                            }
                                        }, delayAfterHangup)
                                    } else {
                                        appendLog("Satellite connection failed or timeout")
                                        finishCollection("Satellite connection failed")
                                    }
                                }
                            }, 2000)  // Wait 2 seconds after first tap
                        }, 2000)  // Wait 2 seconds for app to open

                    } catch (e: Exception) {
                        appendLog("Satellite launch error: ${e.message}")
                        finishCollection("Satellite launch failed")
                    }
                }, delayFridaReady)
            }
            
            // Step 3: Start SCAT and WAIT for response before making call
            // Step 3: Start SCAT and choose flow based on phase
            if (enableScat) {
                appendLog("Starting SCAT recording...")
                val scatBody = """{"modem_type": "${getModemType()}", "filename": "$pcapFileName"}"""
                sendScatCommand("/start-scat", scatBody) { scatStartSuccess ->
                    if (scatStartSuccess) {
                        appendLog("SCAT started successfully: $pcapFileName")
                    } else {
                        appendLog("Warning: SCAT start failed, continuing anyway")
                    }

                    // Choose flow based on phase
                    if (currentPhase == 4) {
                        proceedToSatellite()
                    } else {
                        proceedToMakeCall()
                    }
                }
            } else {
                // Choose flow based on phase
                if (currentPhase == 4) {
                    proceedToSatellite()
                } else {
                    proceedToMakeCall()
                }
            }
        }
    }

    private fun monitorSatelliteConnected(callback: (Boolean) -> Unit) {
        appendLog("Monitoring satellite connection (timeout: 5 minutes)...")

        val startTime = System.currentTimeMillis()
        val timeoutMillis = 5 * 60 * 1000L  // 5 minutes
        val checkIntervalMillis = 2000L  // Check every 2 seconds

        var isMonitoring = true
        var lastCheckTime = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())

        // Function to stop monitoring and cleanup
        fun stopMonitoring(foundKeyword: Boolean) {
            if (!isMonitoring) return
            isMonitoring = false

            val reason = if (foundKeyword) "Satellite connected" else "Timeout reached (5 minutes)"
            appendLog("Satellite monitoring stopped: $reason")

            // Force stop Stargate app
            appendLog("Force stopping Stargate app...")
            try {
                val cmd = "am force-stop com.google.android.apps.stargate"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()

                if (exitCode == 0) {
                    appendLog("Stargate app force-stopped successfully")
                } else {
                    appendLog("Warning: Force-stop exit code: $exitCode")
                }
            } catch (e: Exception) {
                appendLog("Force-stop error: ${e.message}")
            }

            // Wait 1 minute before returning true
            appendLog("Waiting 1 minute before proceeding...")
            handler.postDelayed({
                appendLog("Satellite connection monitoring complete")
                callback(true)
            }, 60000L)  // 1 minute = 60000ms
        }

        // Function to check logcat periodically
        fun checkLogcat() {
            if (!isMonitoring) return

            // Check if timeout reached
            val elapsedTime = System.currentTimeMillis() - startTime
            if (elapsedTime >= timeoutMillis) {
                appendLog("Satellite monitoring timeout reached (5 minutes)")
                stopMonitoring(false)
                return
            }

            // Check logcat for keyword in background thread
            thread {
                try {
                    // Use -T (time filter) to only read logs since last check
                    // Use -e (regex) to filter for our patterns
                    // This is much more efficient and won't miss logs
                    val cmd = "logcat -T '$lastCheckTime' -d -e 'SATELLITE_MODEM_STATE_CONNECTED|Entering ConnectedState'"
                    val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
                    val reader = process.inputStream.bufferedReader()
                    val logcatOutput = reader.readText()
                    reader.close()
                    process.waitFor()

                    // Update last check time for next iteration
                    lastCheckTime = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())

                    // Check if we found the satellite connection indicators
                    if (logcatOutput.contains("SATELLITE_MODEM_STATE_CONNECTED") ||
                        logcatOutput.contains("Entering ConnectedState")) {
                        handler.post {
                            if (isMonitoring) {
                                appendLog("Satellite connection detected in logcat!")
                                val matchedLine = logcatOutput.lines().firstOrNull {
                                    it.contains("SATELLITE_MODEM_STATE_CONNECTED") ||
                                            it.contains("Entering ConnectedState")
                                }
                                if (matchedLine != null) {
                                    appendLog("Match: ${matchedLine.take(150)}")
                                }
                                stopMonitoring(true)
                            }
                        }
                        return@thread
                    }

                    // Schedule next check
                    handler.postDelayed({
                        if (isMonitoring) {
                            checkLogcat()
                        }
                    }, checkIntervalMillis)

                } catch (e: Exception) {
                    handler.post {
                        appendLog("Logcat check error: ${e.message}")
                        // Continue monitoring despite error
                        handler.postDelayed({
                            if (isMonitoring) {
                                checkLogcat()
                            }
                        }, checkIntervalMillis)
                    }
                }
            }
        }

        // Start monitoring
        checkLogcat()
    }





    private fun stopCollection() {
        shouldStop = true
        appendLog("Stopping collection...")
        // updateProgress("Stopping...")
    }
    
    private fun finishCollection(message: String) {
        isCollectionRunning = false
        shouldStop = false
        
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
        
        // updateProgress(message)
        appendLog("=== $message ===")
        
        runOnUiThread {
            btnStartExperiment.isEnabled = true
            btnStopExperiment.isEnabled = false
            setInputsEnabled(true)
        }
    }
    
    private fun setInputsEnabled(enabled: Boolean) {
        //editDialNumber.isEnabled = enabled
        btnRefreshGps.isEnabled = enabled
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
            modelName.contains("SM-S92", ignoreCase = true) -> 185
            // S23 series
            modelName.contains("SM-S91", ignoreCase = true) -> 185
            // S22 series
            modelName.contains("SM-S90", ignoreCase = true) -> 193
            // S21 series
            modelName.contains("SM-G99", ignoreCase = true) -> 193
            // S20 series
            modelName.contains("SM-G98", ignoreCase = true) -> 193
            // Pixel 10
            modelName.contains("Pixel", ignoreCase = true) -> 185
            // Default to S21 code
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
                appendLog("Running: su -c '$cmd'")
                
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()
                val errorOutput = process.errorStream.bufferedReader().readText()
                
                appendLog("Exit code: $exitCode")
                if (errorOutput.isNotEmpty()) {
                    appendLog("Error: ${errorOutput.take(100)}")
                }
                
                if (exitCode != 0) {
                    // Try alternative: su shell -c (some devices need this)
                    appendLog("Trying: su shell -c...")
                    val process2 = Runtime.getRuntime().exec(arrayOf("su", "shell", "-c", cmd))
                    val exitCode2 = process2.waitFor()
                    appendLog("su shell -c exit: $exitCode2")
                    
                    if (exitCode2 != 0) {
                        // fallback: normal call
                        appendLog("Trying regular CALL for emergency...")
                        val cmd2 = "am start -a android.intent.action.CALL -d tel:$numberToCall"
                        Runtime.getRuntime().exec(arrayOf("su", "-c", cmd2)).waitFor()
                    }
                } else {
                    appendLog("Emergency call command sent")
                }
            } else {
                // use CALL
                val cmd = "am start -a android.intent.action.CALL -d tel:$numberToCall"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                val exitCode = process.waitFor()
                
                if (exitCode == 0) {
                    appendLog("Call command sent successfully")
                } else {
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
                startActivity(callIntent)
                appendLog("Fallback call initiated")
            }
        } catch (e: Exception) {
            appendLog("Fallback call error: ${e.message}")
        }
    }
    
    private fun endCall() {
        appendLog("Ending call via tap...")
        try {
            // use tapScreen
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "input tap $endCallButtonX $endCallButtonY"))
            val exitCode = process.waitFor()
            
            if (exitCode == 0) {
                appendLog("End call tap sent at ($endCallButtonX, $endCallButtonY)")
            } else {
                appendLog("Tap failed (exit: $exitCode), trying keyevent...")
                // Fallback to keyevent
                Runtime.getRuntime().exec(arrayOf("su", "-c", "input keyevent ENDCALL")).waitFor()
            }
        } catch (e: Exception) {
            appendLog("End call error: ${e.message}")
        }
    }
    
    // ===== Cellular Pro (removed - will use scat) =====
    // TODO: scat
    
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
    // TODO: just radio for now, crash when using -b all
    private fun clearLogcat() {
        try {
            // Clear all buffers that we capture
            val buffers = listOf("radio", "events", "main", "system")
            for (buffer in buffers) {
                Runtime.getRuntime().exec(arrayOf("logcat", "-b", buffer, "-c")).waitFor()
            }
            appendLog("Logcat cleared (radio, events, main, system)")
        } catch (e: Exception) {
            appendLog("Clear logcat error: ${e.message}")
        }
    }
    
    /**
     * Capture multiple logcat buffers to separate files
     * Returns a map of buffer name to content
     */
    private fun captureLogcatMultiBuffer(): Map<String, String> {
        val buffers = listOf("radio", "events", "main", "system")
        val results = mutableMapOf<String, String>()
        
        for (buffer in buffers) {
            try {
                val dumpPath = "/data/local/tmp/logcat_${buffer}.txt"
                
                appendLog("Capturing logcat -b $buffer...")
                
                // Write to file
                val writeProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "logcat -b $buffer -d > $dumpPath"))
                val writeExit = writeProcess.waitFor()
                
                if (writeExit == 0) {
                    // Read from file
                    val readProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "cat $dumpPath"))
                    val output = readProcess.inputStream.bufferedReader().readText()
                    readProcess.waitFor()
                    
                    results[buffer] = output
                    appendLog("Buffer $buffer: ${output.length} chars")
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
     * Save multiple logcat buffers to separate files
     */
    private fun saveLogcatMultiBuffer(baseFileName: String) {
        val bufferData = captureLogcatMultiBuffer()
        
        for ((buffer, content) in bufferData) {
            if (content.isNotEmpty() && !content.startsWith("Error")) {
                val fileName = "${baseFileName}_${buffer}.txt"
                saveDataToFile(content, fileName)
                appendLog("Saved: $fileName")
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
}
