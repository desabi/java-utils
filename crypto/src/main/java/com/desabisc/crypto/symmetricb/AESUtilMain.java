package com.desabisc.crypto.symmetricb;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Slf4j
public class AESUtilMain {
    public static void main(String[] args) {

        String messageToEncrypt = "Hello World!";
        AESUtil aesUtil = new AESUtil();

        try {
            SecretKey secretKey = aesUtil.getSecretKey(128);
            IvParameterSpec ivParameterSpec = aesUtil.getIvParameterSpec();

            String encryptedMessage = aesUtil.encrypt(secretKey, ivParameterSpec, messageToEncrypt);
            String decryptedMessage = aesUtil.decrypt(secretKey, ivParameterSpec, encryptedMessage);

            log.info("encryptedMessage: {}", encryptedMessage);
            log.info("decryptedMessage: {}", decryptedMessage);
        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
            e.printStackTrace();
        }

    }
}
