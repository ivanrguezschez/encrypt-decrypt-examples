package com.irs.encryptdecryptexamples;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Clase que encripta y desencripta un texto generando una clave secreta simple.
 *
 * @autor IRS
 * @version 1.0.0
 */
public class EncryptDecryptSimple {

    public static final String TRANSFORMATION_DES_ECB_PKCS5PADDING = "DES/ECB/PKCS5Padding";
            
    public EncryptDecryptSimple() {
        super();
    }

    public byte[] encrypt(SecretKey secretKey, byte[] text)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(EncryptDecryptSimple.TRANSFORMATION_DES_ECB_PKCS5PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] ciphertext = cipher.doFinal(text);

        return ciphertext;
    }

    public byte[] decrypt(SecretKey secretKey, byte[] ciphertext)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        Cipher cipher = Cipher.getInstance(EncryptDecryptSimple.TRANSFORMATION_DES_ECB_PKCS5PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] plaintext = cipher.doFinal(ciphertext);

        return plaintext;
    }
 
    public SecretKey getKey(String password) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
	SecretKey secret = kg.generateKey();
        
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
