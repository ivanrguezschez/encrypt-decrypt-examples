package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecrypt. 
 * El test consiste en encriptar y desencriptar un texto (podria ser una 
 * password) empleando una contraseña como clave de encriptación.
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecryptTest {

    private static final String PASSWORD = "password";
    private static final String TEXTO = "texto a cifrar, puede ser una password";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecrypt encryptDecrypt = new EncryptDecrypt();

            String securePassword = encryptDecrypt.securePassword(PASSWORD);

            System.out.println("Password securizada: " + securePassword);

            SecretKey secretKey = encryptDecrypt.getKey(securePassword);
            //SecretKey secretKey = encryptDecrypt.getKey(PASSWORD);

            byte[] encrypt = encryptDecrypt.encrypt(secretKey, TEXTO.getBytes("UTF-8"));

            System.out.println("Texto encriptado Hx [" + EncryptDecrypt.toHex(encrypt) + "]");
            System.out.println("Texto encriptado b64 [" + DatatypeConverter.printBase64Binary(encrypt) + "]");

            byte[] decrypt = encryptDecrypt.decrypt(secretKey, encrypt);

            System.out.println("Texto desencriptado [" + new String(decrypt, "UTF-8") + "]");

            assertEquals(TEXTO, new String(decrypt, "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
