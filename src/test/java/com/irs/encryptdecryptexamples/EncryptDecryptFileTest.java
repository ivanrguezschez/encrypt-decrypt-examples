package com.irs.encryptdecryptexamples;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test unitario para la clase EncryptDecryptFile. 
 * El test consiste en encriptar y desencriptar un archivo empleando una 
 * contraseña como clave de encriptación.
 *
 * @author IRS
 * @version 1.0.0
 */
public class EncryptDecryptFileTest {

    private static final String PASSWORD = "password";
    private static final String ENTRADA_TO_ENCRYPT = "src/test/resources/entrada_a_encriptar.txt";
    private static final String ENTRADA_TO_DECRYPT = "src/test/resources/entrada_a_desencriptar.txt";
    
    private static final String SALIDA_DECRYPT = "src/test/resources/entrada.txt";
    private static final String SALIDA_ENCRYPT = "src/test/resources/salida.txt";

    @Test
    public void testEncryptDecrypt() {
        try {
            EncryptDecryptFile encryptDecryptFile = new EncryptDecryptFile();

            encryptDecryptFile.encryptFile(ENTRADA_TO_ENCRYPT, SALIDA_ENCRYPT, PASSWORD);
            
            encryptDecryptFile.decryptFile(ENTRADA_TO_DECRYPT, SALIDA_DECRYPT, PASSWORD);
            
            byte[] salidaEncrypt = readFile(SALIDA_ENCRYPT);
            System.out.println("Contenido del archivo de salida encriptado");
            printByteArray(salidaEncrypt);
            
            byte[] entradaEncrypt = readFile(ENTRADA_TO_DECRYPT);
            System.out.println("Contenido del archivo de entrada encriptado");
            printByteArray(entradaEncrypt);
                        
            assertEquals(salidaEncrypt.length, entradaEncrypt.length);
            for (int i = 0; i < salidaEncrypt.length; i++) {
                assertEquals(salidaEncrypt[i], entradaEncrypt[i]);
            }

            byte[] salidaDecrypt = readFile(SALIDA_DECRYPT);
            System.out.println("Contenido del archivo de salida desencriptado");
            printByteArray(salidaDecrypt);
            
            byte[] entradaDecrypt = readFile(ENTRADA_TO_ENCRYPT);
            System.out.println("Contenido del archivo de entrada desencriptado");
            printByteArray(entradaDecrypt);
                    
            assertEquals(salidaDecrypt.length, entradaDecrypt.length);
            for (int i = 0; i < salidaDecrypt.length; i++) {
                assertEquals(salidaDecrypt[i], entradaDecrypt[i]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private byte[] readFile(String fileName) throws FileNotFoundException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int byteRead = -1;
            
        try {
            FileInputStream fis = new FileInputStream(fileName);
            while ((byteRead = fis.read()) != -1) {
                baos.write(byteRead);
            }
        
            return baos.toByteArray();
        } finally {
            baos.close();
        }
    }
    
    private void printByteArray(byte[] array) {
        if (array != null) {
            for (int i = 0; i < array.length; i++) {
                System.out.print(array[i]);
            }
            System.out.println("");
        }
    }
}
