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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Clase que encripta y desencripta un texto empleando una clave secreta y 
 * empleando Password-Based Encryption (PBE).
 *
 * @autor IRS
 * @version 1.0.0
 */
public class EncryptDecryptWithPBE {

    public static final String ALGORITHM_PBE_WITH_MD5_DES = "PBEWithMD5AndDES";
    public static final int ITERATION_COUNT = 20;
            
    public EncryptDecryptWithPBE() {
        super();
    }

    public byte[] encrypt(SecretKey secretKey, byte[] text)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            UnsupportedEncodingException, InvalidAlgorithmParameterException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(getSalt(), EncryptDecryptWithPBE.ITERATION_COUNT);
        
        Cipher cipher = Cipher.getInstance(EncryptDecryptWithPBE.ALGORITHM_PBE_WITH_MD5_DES);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParamSpec);

        byte[] ciphertext = cipher.doFinal(text);

        return ciphertext;
    }

    public byte[] decrypt(SecretKey secretKey, byte[] ciphertext)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidParameterSpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(getSalt(), EncryptDecryptWithPBE.ITERATION_COUNT);
         
        Cipher cipher = Cipher.getInstance(EncryptDecryptWithPBE.ALGORITHM_PBE_WITH_MD5_DES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);

        return plaintext;
    }
 
    public byte[] getSalt() {
        // Salt
	byte[] salt = {
		(byte) 0xc7, (byte) 0x73, (byte) 0x21, (byte) 0x8c,
		(byte) 0x7e, (byte) 0xc8, (byte) 0xee, (byte) 0x99
	};
        
        return salt;
    }
    
    public SecretKey getKey(String password) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException {
	PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(EncryptDecryptWithPBE.ALGORITHM_PBE_WITH_MD5_DES);
	SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        
        return pbeKey;
    }

    public static String toHex(byte[] text) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length; i++) {
            sb.append(Integer.toString((text[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
}
