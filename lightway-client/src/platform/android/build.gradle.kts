import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Top-level build file where you can add configuration options common to all sub-projects/modules.

buildscript {
    repositories {
        google()
        mavenCentral()
        maven("https://plugins.gradle.org/m2/")
    }
    dependencies {
        classpath(libs.gradle)
        classpath(kotlin("gradle-plugin", version = "2.2.0"))
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }

    tasks.withType(JavaCompile::class).configureEach {
        // https://docs.oracle.com/javase/8/docs/technotes/tools/unix/javac.html
        options.compilerArgs.add("-Xlint:all")
    }

    tasks.withType(org.jetbrains.kotlin.gradle.tasks.KotlinCompile::class).all {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }
}
