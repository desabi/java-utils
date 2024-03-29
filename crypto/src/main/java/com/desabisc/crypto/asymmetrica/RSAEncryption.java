package com.desabisc.crypto.asymmetrica;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * https://xmind.app/embed/J4Da/
 * A type of cipher that uses a pair of different keys to encrypt and decrypt data.
 *  --> public key: Encrypts data
 *  --> private key: decrypts data
 *  Examples of asymmetric encryption algorithms: RSA, DH, EI-GAMAL, DSA, ECC
 * */
@Slf4j
public class RSAEncryption {
    private String algorithm = "RSA";
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String transformation = "RSA/ECB/PKCS1Padding";

    public MyKeys generateKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        //log.info("public key: {}", encodeToString(publicKey.getEncoded()));
        //log.info("private key: {}", encodeToString(privateKey.getEncoded()));
        return new MyKeys(publicKey, privateKey);
    }

    private String encodeToString(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public String encrypt(PublicKey publicKey, String messageToEncrypt) throws Exception {
        String publicKeyString = encodeToString(publicKey.getEncoded());

        byte[] publicKeyBites = Base64.getDecoder().decode(publicKeyString.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBites);
        PublicKey publicKey1 = keyFactory.generatePublic(publicKeySpec);

        Cipher cipherEncrypt = Cipher.getInstance(transformation);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, publicKey1);
        byte[] encryptedBytes = cipherEncrypt.doFinal(messageToEncrypt.getBytes(StandardCharsets.UTF_8));
        return encodeToString(encryptedBytes);
    }

    public String decrypt(PrivateKey privateKey, String messageToDecrypt) throws Exception {
        String privateKeyString = encodeToString(privateKey.getEncoded());

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString.getBytes());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        PrivateKey privateKey1 = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipherDecrypt = Cipher.getInstance(transformation);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, privateKey1);
        byte[] decryptedBytes = cipherDecrypt.doFinal(Base64.getDecoder().decode(messageToDecrypt));
        return new String(decryptedBytes);
    }


}
