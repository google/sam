package com.example.sam_agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import android.util.Log

class SamNodeForegroundService : Service() {

    private val CHANNEL_ID = "SAM_NODE_CHANNEL"
    private val NOTIFICATION_ID = 1
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        
        // Acquire partial wake lock to keep CPU running
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SamNode::WakeLock")
        wakeLock?.acquire()
        
        Log.d("SAM_SERVICE", "Foreground Service Created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        
        Log.d("SAM_SERVICE", "Foreground Service Started")
        
        return START_STICKY // Restart if killed
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onDestroy() {
        super.onDestroy()
        wakeLock?.release()
        Log.d("SAM_SERVICE", "Foreground Service Destroyed")
    }

    private fun createNotification(): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SAM Node Running")
            .setContentText("Maintaining mesh connection in background")
            .setSmallIcon(android.R.drawable.ic_menu_share) // Placeholder icon
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW) // Low priority to avoid annoying user, but enough for Foreground
            
        return builder.build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "SAM Node Service"
            val descriptionText = "Keeps SAM Node alive in background"
            val importance = NotificationManager.IMPORTANCE_LOW
            val channel = NotificationChannel(CHANNEL_ID, name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}
