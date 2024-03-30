package com.desabisc.crypto.symmetricb;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * https://www.baeldung.com/java-aes-encryption-decryption
 * */
public class AESUtil {

    private final String ALGORITHM = "AES";
    private final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public SecretKey getSecretKey(int bitsSize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(bitsSize);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public IvParameterSpec getIvParameterSpec() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public String encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, String messageToEncrypt)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipherEncrypt = Cipher.getInstance(TRANSFORMATION);
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] messageEncryptedBytes = cipherEncrypt.doFinal(messageToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(messageEncryptedBytes);
    }

    public String decrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, String messageToDecrypt)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipherDecrypt = Cipher.getInstance(TRANSFORMATION);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] messageDecryptedBytes = cipherDecrypt.doFinal(Base64.getDecoder().decode(messageToDecrypt));
        return new String(messageDecryptedBytes);
    }
}
