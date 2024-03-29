package com.desabisc.crypto.symmetrica;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

/**
 * https://xmind.app/embed/J4Da/
 * A class of cipher that uses identical keys for encryption and decryption.
 * A symmetric key may be referred to as: secret key, or private key, or shared key
 * Examples: DES, 3DES, RC, AES
 * */
public class AESEncryption {

    // 1. Create encryption key
    //    1.1 use a KeyGenerator to generate a Key: it requires an algorithm
    // encryption algorithm and the corresponding encryption mode
    private String algorithm = "AES";
    private String encryptionMode = "AES/GCM/NoPadding";
    private int T_LEN = 128;
    private SecretKey secretKey;
    private Cipher encryptionCipher ;

    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        secretKey = keyGenerator.generateKey();
    }

    public String encrypt(String message) throws Exception {
        byte[] messageBytes = message.getBytes();

        // create an encryption cipher
        encryptionCipher = Cipher.getInstance(encryptionMode);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = encryptionCipher.doFinal(messageBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageBytes = decode(encryptedMessage);

        Cipher decryptionCipher = Cipher.getInstance(encryptionMode);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedBytes = decryptionCipher.doFinal(messageBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] encryptedBytes) {
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private byte[] decode(String encryptedMessage) {
        return Base64.getDecoder().decode(encryptedMessage);
    }
}
