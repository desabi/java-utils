package com.desabisc.crypto.asymmetrica;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RSAMain {
    public static void main(String[] args) {
        String message = "Hello World!";
        RSAEncryption rsaEncryption = new RSAEncryption();

        try {
            MyKeys myKeys = rsaEncryption.generateKeys();

            String encryptedMessage = rsaEncryption.encrypt(myKeys.getPublicKey(), message);
            log.info("encryptedMessage: {}", encryptedMessage);
            String decryptedMessage = rsaEncryption.decrypt(myKeys.getPrivateKey(), encryptedMessage);
            log.info("decryptedMessage: {}", decryptedMessage);
        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
        }

    }
}
