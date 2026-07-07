package com.example.sam_agent

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.util.Log
import android.content.Context

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.example.sam_agent/mesh_expose"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startBackgroundService" -> {
                    try {
                        val intent = android.content.Intent(this, SamNodeForegroundService::class.java)
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                            startForegroundService(intent)
                        } else {
                            startService(intent)
                        }
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("SERVICE_START_ERROR", "Failed to start background service: ${e.message}", null)
                    }
                }
                "stopBackgroundService" -> {
                    try {
                        val intent = android.content.Intent(this, SamNodeForegroundService::class.java)
                        stopService(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("SERVICE_STOP_ERROR", "Failed to stop background service: ${e.message}", null)
                    }
                }
                "setExposeBattery" -> {
                    val enabled = call.argument<Boolean>("enabled") ?: false
                    Log.d("SAM_NODE", "setExposeBattery: $enabled")
                    // TODO: Start/Stop Battery service and register with SAM
                    result.success(true)
                }
                "setExposeLocation" -> {
                    val enabled = call.argument<Boolean>("enabled") ?: false
                    Log.d("SAM_NODE", "setExposeLocation: $enabled")
                    if (enabled) {
                        if (androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.ACCESS_COARSE_LOCATION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                            androidx.core.app.ActivityCompat.requestPermissions(this, arrayOf(android.Manifest.permission.ACCESS_COARSE_LOCATION, android.Manifest.permission.ACCESS_FINE_LOCATION), 1001)
                        }
                    }
                    result.success(true)
                }
                "getBatteryData" -> {
                    try {
                        val batteryManager = getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager
                        val batteryLevel = batteryManager.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
                        
                        val intent = registerReceiver(null, android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED))
                        val status = intent?.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1) ?: -1
                        val isCharging = status == android.os.BatteryManager.BATTERY_STATUS_CHARGING || status == android.os.BatteryManager.BATTERY_STATUS_FULL
                        
                        result.success("{\"battery_level\": $batteryLevel, \"charging\": $isCharging}")
                    } catch (e: Exception) {
                        result.error("BATTERY_ERROR", "Failed to get battery data: ${e.message}", null)
                    }
                }
                "getLocationData" -> {
                    try {
                        if (androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.ACCESS_COARSE_LOCATION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                            result.success("{\"error\": \"Location permission not granted\"}")
                            return@setMethodCallHandler
                        }
                        
                        val hasFineLocation = androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.ACCESS_FINE_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED
                        val locationManager = getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
                        val location: android.location.Location? = if (hasFineLocation) {
                            locationManager.getLastKnownLocation(android.location.LocationManager.GPS_PROVIDER) 
                                ?: locationManager.getLastKnownLocation(android.location.LocationManager.NETWORK_PROVIDER)
                        } else {
                            locationManager.getLastKnownLocation(android.location.LocationManager.NETWORK_PROVIDER)
                        }
                            
                        if (location != null) {
                            result.success("{\"latitude\": ${location.latitude}, \"longitude\": ${location.longitude}}")
                        } else {
                            result.success("{\"error\": \"No location available\"}")
                        }
                    } catch (e: Exception) {
                        result.error("LOCATION_ERROR", "Failed to get location data: ${e.message}", null)
                    }
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }
}
