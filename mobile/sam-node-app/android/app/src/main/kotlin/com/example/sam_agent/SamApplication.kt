package com.example.sam_agent

import android.app.Application
import androidx.appfunctions.service.AppFunctionConfiguration

class SamApplication : Application(), AppFunctionConfiguration.Provider {
    
    // Instantiate SamFunctions lazily or eagerly
    private val samFunctions by lazy { SamFunctions() }

    override val appFunctionConfiguration: AppFunctionConfiguration
        get() = AppFunctionConfiguration.Builder()
            .addEnclosingClassFactory(SamFunctions::class.java) { samFunctions }
            .build()
}
