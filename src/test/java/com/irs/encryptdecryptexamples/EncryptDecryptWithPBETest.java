package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * Test unitario para la clase EncryptDecryptWithPBE. 
 * El test consiste en encriptar y desencriptar un texto empleando una clave de 
 * encriptación Password-Based Encryption (PBE).
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecryptWithPBETest {

    // 32 bytes
    private static final String CLAVE = "com.irs.encryptdecrypt.123456789";
    private static final String TEXTO = "PASSWORD";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecryptWithPBE pbe = new EncryptDecryptWithPBE();

            SecretKey secretKey = pbe.getKey(CLAVE);

            byte[] encrypt = pbe.encrypt(secretKey, TEXTO.getBytes("UTF-8"));

            System.out.println("Texto encriptado Hx [" + EncryptDecrypt.toHex(encrypt) + "]");
            System.out.println("Texto encriptado b64 [" + DatatypeConverter.printBase64Binary(encrypt) + "]");

            byte[] decrypt = pbe.decrypt(secretKey, encrypt);

            System.out.println("Texto desencriptado [" + new String(decrypt, "UTF-8") + "]");

            assertEquals(TEXTO, new String(decrypt, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
