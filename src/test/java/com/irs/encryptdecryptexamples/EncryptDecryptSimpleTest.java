package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecryptSimple. 
 * El test consiste en encriptar y desencriptar un texto empleando una clave de encriptación.
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecryptSimpleTest {

    // 32 bytes
    private static final String CLAVE = "com.irs.encryptdecrypt.123456789";
    private static final String TEXTO = "PASSWORD";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecryptSimple edSimple = new EncryptDecryptSimple();

            SecretKey secretKey = edSimple.getKey(CLAVE);

            byte[] encrypt = edSimple.encrypt(secretKey, TEXTO.getBytes("UTF-8"));

            System.out.println("Texto encriptado Hx [" + EncryptDecrypt.toHex(encrypt) + "]");
            System.out.println("Texto encriptado b64 [" + DatatypeConverter.printBase64Binary(encrypt) + "]");

            byte[] decrypt = edSimple.decrypt(secretKey, encrypt);

            System.out.println("Texto desencriptado [" + new String(decrypt, "UTF-8") + "]");

            assertEquals(TEXTO, new String(decrypt, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
