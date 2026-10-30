// A Kotlin DSL build script.
plugins {
    java
}

val jacksonVersion = "2.9.10.1"

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("org.yaml:snakeyaml:1.29")
    implementation(group = "com.google.guava", name = "guava", version = "24.1.1-jre")

    // version catalog accessor: no literal coordinate to read
    implementation(libs.commons.text)

    testImplementation("junit:junit:4.13.1")
}
