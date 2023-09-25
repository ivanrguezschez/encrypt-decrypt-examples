package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecrypt2. 
 * El test consiste en encriptar y desencriptar un texto (una password) 
 * empleando una contraseña como clave de encriptación.
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecrypt2Test {
    
    // PASSWORD es la clave empleada para cifrar y descifrar el TEXTO
    private static final String PASSWORD = "com.irs.encryptdecrypt.123456789";
    private static final String TEXTO = "PASSWORD";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecrypt2 encryptDecrypt2 = new EncryptDecrypt2();

            SecretKey secretKey = encryptDecrypt2.getKey(PASSWORD);

            byte[] encrypt = encryptDecrypt2.encrypt(secretKey, TEXTO.getBytes());

            System.out.println("Texto encriptado Hx [" + EncryptDecrypt2.toHex(encrypt) + "]");
            System.out.println("Texto encriptado b64 [" + DatatypeConverter.printBase64Binary(encrypt) + "]");

            byte[] decrypt = encryptDecrypt2.decrypt(secretKey, encrypt);

            System.out.println("Texto desencriptado [" + new String(decrypt) + "]");

            assertEquals(TEXTO, new String(decrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
