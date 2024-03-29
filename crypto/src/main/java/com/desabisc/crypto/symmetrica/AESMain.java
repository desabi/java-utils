package com.desabisc.crypto.symmetrica;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AESMain {
    public static void main(String[] args) {
        String message = "Hello World!";

        AESEncryption aesEncryption = new AESEncryption();

        try {
            aesEncryption.init();

            String encryptedMessage = aesEncryption.encrypt(message);
            String decryptedMessage = aesEncryption.decrypt(encryptedMessage);
            log.info("encryptedMessage: {}", encryptedMessage);
            log.info("decryptedMessage: {}", decryptedMessage);

        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
        }
    }
}
