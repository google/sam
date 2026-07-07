package com.example.sam_agent

import io.flutter.app.FlutterApplication
import androidx.appfunctions.service.AppFunctionConfiguration

class SamApplication : FlutterApplication(), AppFunctionConfiguration.Provider {
    
    // Instantiate SamFunctions lazily or eagerly
    private val samFunctions by lazy { SamFunctions() }

    override val appFunctionConfiguration: AppFunctionConfiguration
        get() = AppFunctionConfiguration.Builder()
            .addEnclosingClassFactory(SamFunctions::class.java) { samFunctions }
            .build()
}
