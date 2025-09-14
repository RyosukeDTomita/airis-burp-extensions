plugins {
    id("java")
    id("application")
    id("com.diffplug.spotless") version "6.25.0"
}

group = "com.airis.burp"
version = "0.0.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21) // Montoya API supports Java 21 or lower
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Montoya API for Burp Suite extensions
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.7")
    
    // HTTP Client
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    
    // JSON Processing
    implementation("com.google.code.gson:gson:2.10.1")
    
    // Logging
    implementation("org.slf4j:slf4j-api:2.0.9")
    implementation("ch.qos.logback:logback-classic:1.4.11")
    
    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.7.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.7.0")
    testImplementation("net.portswigger.burp.extensions:montoya-api:+")
}

spotless {
    java {
        googleJavaFormat("1.19.2")
        target("src/**/*.java")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
        indentWithSpaces(4)
    }
}

// Create fmt task as alias for spotlessApply
tasks.register("fmt") {
    dependsOn("spotlessApply")
    description = "Format Java code using Spotless"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.jar {
    archiveFileName.set("airis-burp.jar")
    manifest {
        attributes(
            "Main-Class" to "com.airis.burp.ai.Extension",
            "Implementation-Title" to "airis",
            "Implementation-Version" to version,
            "Implementation-Vendor" to "AIRIS"
        )
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}