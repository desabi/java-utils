package com.desabisc.crypto.providers;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;

//chatgpt
public class ECCExample {
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
        KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        aliceKeyAgreement.init(alicePrivateKey);
        aliceKeyAgreement.doPhase(bobPublicKey, true);
        byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();
        
        // Bob computes shared secret
        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        bobKeyAgreement.init(bobPrivateKey);
        bobKeyAgreement.doPhase(alicePublicKey, true);
        byte[] bobSharedSecret = bobKeyAgreement.generateSecret();
        
        // Alice and Bob should now have the same shared secret
        System.out.println("Alice's shared secret: " + bytesToHex(aliceSharedSecret));
        System.out.println("Bob's shared secret: " + bytesToHex(bobSharedSecret));
    }
    
    // Method to generate ECC key pair
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1"); // Using secp256r1 curve
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }
    
    // Method to convert byte array to hexadecimal string (for printing)
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
