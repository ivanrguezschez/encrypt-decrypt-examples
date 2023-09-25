package com.irs.encryptdecryptexamples;

import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase de información de encriptación y desencriptación simétrica (clave única 
 * de cifrado y descrifrado).
 *
 * @autor IRS
 * @version 1.0.0
 */
public class SymmetricMain {
    
    public static void main(String[] args) {
        try {
            System.out.println("Symmetric encryption");
            symmetricEncrypt();
        } catch (Exception ex) {
           ex.printStackTrace();
        }
    }
    
     private static void symmetricEncrypt() throws Exception {
        Set<String> keyGenerators = Security.getAlgorithms("KeyGenerator");
        System.out.println("Supported key generators: " + keyGenerators.stream().sorted().collect(Collectors.joining(", ")));

        Set<String> secretKeyFactories = Security.getAlgorithms("SecretKeyFactory");
        System.out.println("Supported key factory: " + secretKeyFactories.stream().sorted().collect(Collectors.joining(", ")));

        Set<String> ciphers = Security.getAlgorithms("Cipher");
        System.out.println("Supported ciphers: " + ciphers.stream().sorted().collect(Collectors.joining(", ")));

        Set<String> macs = Security.getAlgorithms("Mac");
        System.out.println("Supported macs: " + macs.stream().sorted().collect(Collectors.joining(", ")));

        String text = "En un lugar de la Mancha de cuyo nombre no quiero acordarme";
        String password = "mypassword";
        String salt = "abcdefghijklmnopqrstuvwxyz0123456789";

        SecretKey key = generateKey();
        SecretKey passwordKey = generateKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] keyEncrypted = encrypt(key, text);
        byte[] passwordEncrypted = encrypt(passwordKey, text);
        byte[] inputStreamEncrypted = encrypt(key, SymmetricMain.class.getResourceAsStream("/text.txt"));

        System.out.println("Plain text: " + password);
        System.out.println("Key encrypted: " + HexFormat.of().formatHex(keyEncrypted));
        System.out.println("Password key encrypted: " + HexFormat.of().formatHex(passwordEncrypted));
        System.out.println("InputStream key encrypted: " + HexFormat.of().formatHex(inputStreamEncrypted));
        System.out.println("Key decrypted: " + new String(decrypt(key, keyEncrypted)));
        System.out.println("Password Key decrypted: " + new String(decrypt(passwordKey, passwordEncrypted)));
        System.out.println("HMAC: " + calculateHmac(key, text));
    }
     
     // Dos formas de generar la clave, una generar un número de forma aleatoria
    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    // Dos formas de generar la clave, la segunda forma es generar la clave como una derivada de una contraseña
    private static SecretKey generateKey(String password, String salt) throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        return new SecretKeySpec(secretKeyFactory.generateSecret(spec).getEncoded(), "AES");
    }
    
     private static byte[] encrypt(SecretKey key, String text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text.getBytes());
    }

    private static byte[] decrypt(SecretKey key, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }

    private static byte[] encrypt(SecretKey key, InputStream stream) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        CipherInputStream cipherInputStream = new CipherInputStream(stream, cipher);
        return cipherInputStream.readAllBytes();
    }

    public static String calculateHmac(SecretKey key, String text) throws Exception {
        Mac mac = Mac.getInstance("HMACSHA256");
        mac.init(key);
        byte[] bytes = mac.doFinal(text.getBytes());
        return HexFormat.of().formatHex(bytes);
    }
}
