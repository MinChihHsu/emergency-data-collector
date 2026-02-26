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
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class WaitForBlockService : Service() {

    companion object {
        const val CHANNEL_ID = "WaitForBlockChannel"
        const val NOTIFICATION_ID = 2001

        private var isRunning = false
        private var callback: ((Boolean) -> Unit)? = null

        fun start(context: Context, timeoutSec: Int, onComplete: (Boolean) -> Unit) {
            if (isRunning) {
                Log.w("WaitForBlockService", "Service already running, ignoring start request")
                return
            }

            callback = onComplete
            val intent = Intent(context, WaitForBlockService::class.java).apply {
                putExtra("timeout", timeoutSec)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            isRunning = false
            callback = null
            context.stopService(Intent(context, WaitForBlockService::class.java))
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private val fridaServerUrl = "http://127.0.0.1:5555"
    private val httpConnectTimeoutMs = 20000
    private val httpReadTimeoutMs = 30000

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val timeoutSec = intent?.getIntExtra("timeout", 300) ?: 300

        startForeground(NOTIFICATION_ID, createNotification("Waiting for call block (0s / ${timeoutSec}s)"))

        isRunning = true
        Log.d("WaitForBlockService", "=== SERVICE_STARTED: timeout=${timeoutSec}s ===")

        // Start monitoring in background thread
        thread {
            waitForBlock(timeoutSec)
        }

        return START_NOT_STICKY
    }

    private fun waitForBlock(timeoutSec: Int) {
        val startMs = System.currentTimeMillis()
        Log.d("WaitForBlock", "=== WAIT_START: timeout=${timeoutSec}s ===")

        // Keep-alive thread: update notification every 10 seconds
        val keepAliveThread = thread {
            var count = 0
            try {
                while (!Thread.currentThread().isInterrupted && isRunning) {
                    Thread.sleep(10000)  // 10 seconds
                    count++
                    val elapsed = (System.currentTimeMillis() - startMs) / 1000
                    Log.d("WaitForBlock", "=== STILL_ALIVE: ${count * 10}s elapsed (${elapsed}s total) ===")

                    // Update notification
                    handler.post {
                        updateNotification("Waiting for call block (${elapsed}s / ${timeoutSec}s)")
                    }
                }
            } catch (e: InterruptedException) {
                Log.d("WaitForBlock", "=== KEEP_ALIVE_STOPPED ===")
            }
        }

        fun finish(blocked: Boolean) {
            keepAliveThread.interrupt()

            val elapsed = System.currentTimeMillis() - startMs
            val targetMs = timeoutSec * 1000L
            val remaining = targetMs - elapsed

            Log.d("WaitForBlock", "=== FINISH_CALLED: blocked=$blocked, elapsed=${elapsed}ms, remaining=${remaining}ms ===")

            if (!blocked && remaining > 0) {
                Log.d("WaitForBlock", "=== SLEEPING: ${remaining}ms ===")
                try { Thread.sleep(remaining) } catch (_: Exception) {}
            }

            Log.d("WaitForBlock", "=== INVOKING_CALLBACK ===")
            callback?.invoke(blocked)

            Log.d("WaitForBlockService", "=== SERVICE_STOPPING ===")
            isRunning = false
            stopSelf()
        }

        try {
            val url = URL("$fridaServerUrl/wait-for-block")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = httpConnectTimeoutMs
                readTimeout = maxOf(httpReadTimeoutMs, timeoutSec * 1000 + 5000)
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }

            val body = """{"timeout": $timeoutSec}"""
            Log.d("WaitForBlock", "=== HTTP_REQUEST_SENT ===")

            conn.outputStream.bufferedWriter().use { it.write(body) }

            val code = conn.responseCode
            Log.d("WaitForBlock", "=== HTTP_RESPONSE: code=$code ===")

            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val resp = stream?.bufferedReader()?.readText().orEmpty()
            conn.disconnect()

            Log.d("WaitForBlock", "=== HTTP_BODY: ${resp.take(200)} ===")

            val blocked = Regex("\"blocked\"\\s*:\\s*(true|false)", RegexOption.IGNORE_CASE)
                .find(resp)
                ?.groupValues
                ?.get(1)
                ?.lowercase() == "true"

            Log.d("WaitForBlock", "=== PARSED: blocked=$blocked ===")

            finish(blocked)
        } catch (e: Exception) {
            Log.e("WaitForBlock", "=== EXCEPTION: ${e.message} ===", e)
            finish(false)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Wait For Block Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitoring call block status"
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
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = createNotification(text)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        callback = null
        Log.d("WaitForBlockService", "=== SERVICE_DESTROYED ===")
    }
}
