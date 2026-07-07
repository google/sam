plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
    id("com.google.gms.google-services")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.example.sam_agent"
    compileSdk = 37 // Keep as 37, Gradle usually maps this correctly, but let's check if it needs to be 37
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.example.sam_agent"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

ksp {
    arg("appfunctions:aggregateAppFunctions", "true")
}

dependencies {
    val appFunctionsVersion = "1.0.0-alpha09" // alpha10 seems missing or restricted

    implementation("androidx.appfunctions:appfunctions:$appFunctionsVersion")
    implementation("androidx.appfunctions:appfunctions-service:$appFunctionsVersion")
    ksp("androidx.appfunctions:appfunctions-compiler:$appFunctionsVersion")

    // JNA for calling Go C exports
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
