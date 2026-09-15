plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "io.github.ir0nbyte.pifdetector"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.ir0nbyte.pifdetector"
        minSdk = 24

        targetSdk = 35
        versionCode = 9
        versionName = "2.7"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    signingConfigs {
        create("release") {
            val keystore = System.getenv("RELEASE_KEYSTORE_PATH")
            if (!keystore.isNullOrEmpty()) {
                storeFile = file(keystore)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            externalNativeBuild {
                cmake {
                    cppFlags += "-DIS_DEBUG_BUILD"
                }
            }
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false

            System.getenv("RELEASE_CERT_SHA256")?.takeIf { it.isNotBlank() }?.let { hash ->
                externalNativeBuild {
                    cmake {
                        cppFlags += "-DEXPECTED_CERT_SHA256=$hash"
                    }
                }
            }

            val keystore = System.getenv("RELEASE_KEYSTORE_PATH")
            if (!keystore.isNullOrEmpty()) {
                signingConfig = signingConfigs.getByName("release")
            }

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            ndk {
                debugSymbolLevel = "NONE"
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
}

tasks.withType<Test>().configureEach {
    inputs.file("src/main/AndroidManifest.xml")
        .withPropertyName("manifestForQueriesSyncTest")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file("src/main/cpp/native-lib.cpp")
        .withPropertyName("nativeSourceForQueriesSyncTest")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.constraintlayout)
    implementation(libs.recyclerview)
    implementation(libs.core.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
