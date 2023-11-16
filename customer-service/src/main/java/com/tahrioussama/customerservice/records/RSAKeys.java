package com.tahrioussama.customerservice.records;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
public record RSAKeys(RSAPublicKey publicKey) {
}
