plugins {
    `java-library`
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    // add common scoped dependencies here
    compileOnly("com.inductiveautomation.ignitionsdk:ignition-common:${rootProject.extra["sdk_version"]}")
    // https://mvnrepository.com/artifact/org.snmp4j/snmp4j
	modlImplementation("org.snmp4j:snmp4j:3.7.8")
}
