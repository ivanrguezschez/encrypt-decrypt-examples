package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecryptWithAES. 
 * El test consiste en encriptar y desencriptar un texto empleando una clave de 
 * encriptación Advanced Encryption Standard (AES)
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecryptWithAESTest {

    // 32 bytes
    private static final String CLAVE = "com.irs.encryptdecrypt.123456789";
    private static final String TEXTO = "PASSWORD";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecryptWithAES aes = new EncryptDecryptWithAES();

            SecretKey secretKey = aes.getKey(CLAVE);

            byte[] encrypt = aes.encrypt(secretKey, TEXTO.getBytes("UTF-8"));

            System.out.println("Texto encriptado Hx [" + EncryptDecrypt.toHex(encrypt) + "]");
            System.out.println("Texto encriptado b64 [" + DatatypeConverter.printBase64Binary(encrypt) + "]");

            byte[] decrypt = aes.decrypt(secretKey, encrypt);

            System.out.println("Texto desencriptado [" + new String(decrypt, "UTF-8") + "]");

            assertEquals(TEXTO, new String(decrypt, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
