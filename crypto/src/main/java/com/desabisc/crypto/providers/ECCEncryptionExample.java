package com.desabisc.crypto.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryptionExample {
    public static void main(String[] args) throws Exception {
        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate key pair for Alice
        KeyPair aliceKeyPair = generateKeyPair();
        PublicKey alicePublicKey = aliceKeyPair.getPublic();
        PrivateKey alicePrivateKey = aliceKeyPair.getPrivate();

        // Generate key pair for Bob
        KeyPair bobKeyPair = generateKeyPair();
        PublicKey bobPublicKey = bobKeyPair.getPublic();
        PrivateKey bobPrivateKey = bobKeyPair.getPrivate();

        // Alice and Bob exchange public keys (in a real scenario, this exchange would happen securely)

        // Alice computes shared secret
        byte[] aliceSharedSecret = computeSharedSecret(alicePrivateKey, bobPublicKey);

        // Bob computes shared secret
        byte[] bobSharedSecret = computeSharedSecret(bobPrivateKey, alicePublicKey);

        // Encrypt data with Alice's shared secret
        String plaintext = "Hello, Bob!";
        byte[] encryptedData = encrypt(plaintext, aliceSharedSecret);

        // Decrypt data with Bob's shared secret
        String decryptedData = decrypt(encryptedData, bobSharedSecret);

        // Print results
        System.out.println("Original data: " + plaintext);
        System.out.println("Encrypted data: " + new String(encryptedData));
        System.out.println("Decrypted data: " + decryptedData);
    }

    // Method to generate ECC key pair
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1"); // Using secp256r1 curve
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    // Method to compute shared secret
    private static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    // Method to encrypt data using AES symmetric encryption
    private static byte[] encrypt(String plaintext, byte[] sharedSecret) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    // Method to decrypt data using AES symmetric decryption
    private static String decrypt(byte[] encryptedData, byte[] sharedSecret) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
