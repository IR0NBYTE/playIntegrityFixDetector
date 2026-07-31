plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "io.github.ir0nbyte.pifdetector"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.ir0nbyte.pifdetector"
        minSdk = 24
        targetSdk = 35
        versionCode = 6
        versionName = "2.4"

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

            /*
             * SHA-256 of the release signing certificate, lowercase hex with no
             * separators, supplied by whoever builds the release:
             *   keytool -list -v -keystore <ks> -alias <alias> \
             *     | grep SHA256: | sed 's/.*SHA256: //' | tr -d ':' | tr 'A-Z' 'a-z'
             *
             * Left unset, the APK signature check compiles out entirely. It used
             * to be a constant baked into the source, which silently pinned every
             * release to whichever machine last edited it; a build signed with any
             * other key then reported its own signature as tampered. Absent is
             * better than wrong here, because a wrong pin is a guaranteed false
             * positive and this check is deliberately fail-closed.
             */
            System.getenv("RELEASE_CERT_SHA256")?.takeIf { it.isNotBlank() }?.let { hash ->
                externalNativeBuild {
                    cmake {
                        // Passed as a bare token; native-lib.cpp stringizes it.
                        // Quoting here does not survive the Gradle/CMake chain.
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

