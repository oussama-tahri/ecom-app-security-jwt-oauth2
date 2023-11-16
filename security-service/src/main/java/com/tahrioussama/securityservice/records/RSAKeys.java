package com.tahrioussama.securityservice.records;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
public record RSAKeys(RSAPrivateKey PrivateKey, RSAPublicKey PublicKey) {
}
