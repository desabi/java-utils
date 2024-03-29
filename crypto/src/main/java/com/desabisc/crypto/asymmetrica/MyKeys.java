package com.desabisc.crypto.asymmetrica;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.PrivateKey;
import java.security.PublicKey;

@AllArgsConstructor
@Getter
public class MyKeys {
    private PublicKey publicKey;
    private PrivateKey privateKey;
}
