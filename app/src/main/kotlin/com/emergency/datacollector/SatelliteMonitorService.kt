package com.emergency.datacollector

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import java.text.SimpleDateFormat
import java.util.*
import kotlin.concurrent.thread

class SatelliteMonitorService : Service() {

    companion object {
        const val CHANNEL_ID = "SatelliteMonitorChannel"
        const val NOTIFICATION_ID = 1001

        private var isRunning = false
        private var callback: ((Boolean) -> Unit)? = null

        fun start(context: Context, onComplete: (Boolean) -> Unit) {
            callback = onComplete
            val intent = Intent(context, SatelliteMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            isRunning = false
            context.stopService(Intent(context, SatelliteMonitorService::class.java))
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private var startTime: Long = 0
    private val timeoutMillis = 5 * 60 * 1000L  // 5 minutes
    private val checkIntervalMillis = 30_000L   // 30 seconds
    private var lastCheckTime = ""

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification("Monitoring satellite connection..."))

        isRunning = true
        startTime = System.currentTimeMillis()
        lastCheckTime = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())

        Log.d("SatelliteMonitor", "Service started, will check every ${checkIntervalMillis/1000}s")

        // 開始監控
        checkLogcat()

        return START_STICKY
    }

    private fun checkLogcat() {
        if (!isRunning) return

        // 檢查超時
        val elapsedTime = System.currentTimeMillis() - startTime
        if (elapsedTime >= timeoutMillis) {
            Log.d("SatelliteMonitor", "Timeout reached (5 minutes)")
            stopMonitoring(false)
            return
        }

        Log.d("SatelliteMonitor", "Logcat poll... (elapsed: ${elapsedTime/1000}s)")

        // 在 background thread 中執行 logcat 檢查
        thread {
            try {
                val cmd = "logcat -T '$lastCheckTime' -d -e 'SATELLITE_MODEM_STATE_CONNECTED|Entering ConnectedState'"
                val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
                val logcatOutput = process.inputStream.bufferedReader().readText()
                process.waitFor()

                Log.d("SatelliteMonitor", "Logcat poll done, len=${logcatOutput.length}")

                // 更新下次檢查的起始時間
                lastCheckTime = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
                    .format(Date(System.currentTimeMillis() - 500))

                // 檢查是否找到關鍵字
                if (logcatOutput.contains("SATELLITE_MODEM_STATE_CONNECTED") ||
                    logcatOutput.contains("Entering ConnectedState")) {

                    Log.d("SatelliteMonitor", "Satellite connection detected!")
                    stopMonitoring(true)
                    return@thread
                }

                // ✅ 關鍵修復：在主線程調度下一次檢查
                handler.postDelayed({
                    if (isRunning) {
                        checkLogcat()
                    }
                }, checkIntervalMillis)

            } catch (e: Exception) {
                Log.e("SatelliteMonitor", "Logcat check error: ${e.message}")

                // 即使出錯也繼續監控
                handler.postDelayed({
                    if (isRunning) {
                        checkLogcat()
                    }
                }, checkIntervalMillis)
            }
        }
    }

    private fun stopMonitoring(foundKeyword: Boolean) {
        if (!isRunning) return
        isRunning = false

        Log.d("SatelliteMonitor", "Stopping monitoring, found=$foundKeyword")

        // Force stop Stargate app
        try {
            val cmd = "am force-stop com.google.android.apps.stargate"
            Runtime.getRuntime().exec(arrayOf("su", "-c", cmd)).waitFor()
            Log.d("SatelliteMonitor", "Stargate app force-stopped")
        } catch (e: Exception) {
            Log.e("SatelliteMonitor", "Force-stop error: ${e.message}")
        }

        // 等待1分鐘後回調
        val waitMs = if (foundKeyword) 60000L else 0L
        handler.postDelayed({
            callback?.invoke(foundKeyword)
            callback = null
            stopSelf()
        }, waitMs)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Satellite Monitor",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitoring satellite connection in background"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Emergency Data Collector")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        Log.d("SatelliteMonitor", "Service destroyed")
    }
}
