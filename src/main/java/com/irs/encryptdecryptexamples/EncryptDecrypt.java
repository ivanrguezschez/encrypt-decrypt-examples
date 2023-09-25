package com.irs.encryptdecryptexamples;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase que encripta y desencripta un texto pasado.
 *
 * @autor IRS
 * @version 1.0.0
 */
public class EncryptDecrypt {

    public static final String ALGORITHM_SHA1PRNG = "SHA1PRNG";
    public static final String TRANSFORMATION_AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
    public static final String ALGORITHM_PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
    public static final int ITERATION_COUNT = 65536;
    public static final int KEY_LEGTH_128 = 128;

    private IvParameterSpec iv;

    public EncryptDecrypt() {
        this.iv = null;
    }

    public String securePassword(String password)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        return securePassword(password, getSalt());
    }

    public String securePassword(String password, byte[] salt)
            throws NoSuchAlgorithmException {
        String passwordSecure = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] bytes = md.digest(password.getBytes());
        passwordSecure = toHex(bytes);

        return passwordSecure;
    }

    public byte[] encrypt(SecretKey secretKey, byte[] text)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            UnsupportedEncodingException {
        //byte[] salt = getSalt();
        //SecretKey secretKey = getKey(password, salt);

        Cipher cipher = Cipher.getInstance(
                EncryptDecrypt.TRANSFORMATION_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        AlgorithmParameters params = cipher.getParameters();
        this.iv = new IvParameterSpec(params.getParameterSpec(IvParameterSpec.class).getIV());

        byte[] ciphertext = cipher.doFinal(text);

        return ciphertext;
    }

    public byte[] decrypt(SecretKey secretKey, byte[] ciphertext)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
//		byte[] salt = getSalt();
//		SecretKey secretKey = getKey(password, salt);

        Cipher cipher = Cipher.getInstance(
                EncryptDecrypt.TRANSFORMATION_AES_CBC_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, this.iv);

        byte[] plaintext = cipher.doFinal(ciphertext);

        return plaintext;
    }

    private byte[] getSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom sr = SecureRandom.getInstance(
                EncryptDecrypt.ALGORITHM_SHA1PRNG, "SUN");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        return salt;
    }
    
    public SecretKey getKey(String password) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(
                EncryptDecrypt.ALGORITHM_PBKDF2_WITH_HMAC_SHA1);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), getSalt(),
                EncryptDecrypt.ITERATION_COUNT, EncryptDecrypt.KEY_LEGTH_128);

        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        return secret;
    }

    public static String toHex(byte[] text) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length; i++) {
            sb.append(Integer.toString((text[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
}
