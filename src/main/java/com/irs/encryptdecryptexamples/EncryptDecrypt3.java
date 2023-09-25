package com.irs.encryptdecryptexamples;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Clase que encripta y desencripta un texto pasado usando una clave. 
 * encrypt1 / decrypt1 usa el algoritmo AES/GCM/NoPadding. 
 * encrypt2 / decrypt2 usa el algoritmo AES/CBC/PKCS5Padding.
 *
 * @autor IRS
 * @version 1.0.0
 */
public class EncryptDecrypt3 {

    private final static int GCM_IV_LENGTH = 12;
    private final static int GCM_TAG_LENGTH = 16;
    private final static String AES_GCM_NOPADDING = "AES/GCM/NoPadding";

    private final static int CBC_IV_LENGTH = 16;
    private final static String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";

    public EncryptDecrypt3() {
        super();
    }

    public SecretKey getKey1(String clave) {
        // clave de 16 bytes
        SecretKey key = new SecretKeySpec(clave.getBytes(), "AES");

        return key;
    }

    public SecretKey getKey2(String clave) throws Exception {
        String salt = "deadbeef";

        PBEKeySpec keySpec = new PBEKeySpec(clave.toCharArray(), toBinary(salt), 1024, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = factory.generateSecret(keySpec);
        SecretKey secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        return secretKeySpec;
    }

    public String encrypt1(String textoClaro, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(textoClaro.getBytes("UTF8"));
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

        //String encoded = toHex(encrypted);
        String encoded = Base64.getEncoder().encodeToString(encrypted);

        return encoded;
    }

    public String decrypt1(String textoCifradoB64, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(textoCifradoB64);

        byte[] iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(decoded, GCM_IV_LENGTH, decoded.length - GCM_IV_LENGTH);

        String result = new String(ciphertext, "UTF8");

        return result;
    }

    public String encrypt2(String textoClaro, SecretKey key) throws Exception {
        byte[] iv = new byte[CBC_IV_LENGTH];
        (new SecureRandom()).nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(textoClaro.getBytes("UTF8"));
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

        // String encoded = toHex(encrypted);
        String encoded = Base64.getEncoder().encodeToString(encrypted);

        return encoded;
    }

    public String decrypt2(String textoCifradoB64, SecretKey key) throws Exception {
        // byte[] decoded = toBinary(textoCifradoHx);
        byte[] decoded = Base64.getDecoder().decode(textoCifradoB64);

        byte[] iv = Arrays.copyOfRange(decoded, 0, CBC_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(decoded, CBC_IV_LENGTH, decoded.length - CBC_IV_LENGTH);

        String result = new String(ciphertext, "UTF8");

        return result;
    }

    private static String toHex(byte[] bytes) {
        /*
	StringBuilder sb = new StringBuilder();  
	for (byte b : bytes) {  
            sb.append(String.format("%02X ", b));  
	}  
		
	return sb.toString().toUpperCase();
        */
        return DatatypeConverter.printHexBinary(bytes);
    }

    private static byte[] toBinary(String bytes) {
        /*
	int len = bytes.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(bytes.charAt(i), 16) << 4)
	                         + Character.digit(bytes.charAt(i+1), 16));
	}
	return data;
        */
        return DatatypeConverter.parseHexBinary(bytes);
    }
}
