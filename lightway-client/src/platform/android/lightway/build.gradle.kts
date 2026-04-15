import org.gradle.configurationcache.extensions.capitalized


plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    compileSdk = 36

    ndkVersion = System.getenv("ANDROID_NDK_VERSION")

    namespace = "lightway"

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release")
    }

    lint {
        lintConfig = file("lint.xml")
    }
}

androidComponents {
    val debug = selector().withBuildType("debug")
    beforeVariants(debug) { variantBuilder ->
        // Disable building debug variant
        variantBuilder.enable = false
    }
}

dependencies {
    implementation(libs.jna) {
        artifact {
            type = "aar"
        }
    }
}

android.libraryVariants.all {
    val variant = this
    val variantNameCapitalized = variant.name.capitalized()

    afterEvaluate {
        tasks.named("compile${variantNameCapitalized}Kotlin") {
        }
        tasks.named("assembleRelease") {
        }
    }

    android.sourceSets {
        getByName(variant.name) {
            java.srcDirs(System.getenv("ANDROID_UNIFFI_BINDINGS_DIR"))
            jniLibs.srcDirs(System.getenv("ANDROID_UNIFFI_JNI_LIBS_DIR"))
        }
    }
}
