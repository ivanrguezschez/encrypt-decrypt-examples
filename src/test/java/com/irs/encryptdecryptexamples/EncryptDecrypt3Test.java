package com.irs.encryptdecryptexamples;

import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecrypt3. 
 * El test consiste en encriptar y desencriptar un texto (una password) 
 * empleando una clave de encriptación.
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecrypt3Test {
    
    // CLAVE_1 y CLAVE_2 son las claves empleadas para cifrar y descifrar el 
    // TEXTO que en este caso será una contraseña.
	
    // 16 bytes
    private static final String CLAVE_1 = "miclaveparacifra";
    
    private static final String CLAVE_2 = "miclaveparacifrarpasswords";
    
    private static final String TEXTO = "changeit";

    
    /**
     * EncryptDecrypt 1
     */
    @Test
    public void testEncryptDecrypt1() {
        try {
            EncryptDecrypt3 encryptDecrypt3 = new EncryptDecrypt3();

            SecretKey secretKey = encryptDecrypt3.getKey1(CLAVE_1);

            String textoCifradoB64 = encryptDecrypt3.encrypt1(TEXTO, secretKey);
            String textoDescifrado = encryptDecrypt3.decrypt1(textoCifradoB64, secretKey);
            
            System.out.println("AES/GCM/NoPadding -------------------------------");
            System.out.println("Texto encriptado b64 [" + textoCifradoB64 + "]");
            System.out.println("Texto desencriptado [" + textoDescifrado + "]");
            System.out.println("AES/GCM/NoPadding -------------------------------");
            
            assertEquals(TEXTO, new String(textoDescifrado));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * EncryptDecrypt 2
     */
    @Test
    public void testEncryptDecrypt2() {
        try {
            EncryptDecrypt3 encryptDecrypt3 = new EncryptDecrypt3();

            SecretKey secretKey = encryptDecrypt3.getKey2(CLAVE_2);

            String textoCifradoB64 = encryptDecrypt3.encrypt2(TEXTO, secretKey);
            String textoDescifrado = encryptDecrypt3.decrypt2(textoCifradoB64, secretKey);
            
            System.out.println("AES/CBC/PKCS5Padding ----------------------------");
            System.out.println("Texto encriptado b64 [" + textoCifradoB64 + "]");
            System.out.println("Texto desencriptado [" + textoDescifrado + "]");
            System.out.println("AES/CBC/PKCS5Padding ----------------------------");
            
            assertEquals(TEXTO, new String(textoDescifrado));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
