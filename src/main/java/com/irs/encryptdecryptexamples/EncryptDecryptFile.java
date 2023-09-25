package com.irs.encryptdecryptexamples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase que encripta y desencripta un archivo pasado.
 *
 * @autor IRS
 * @version 1.0.0
 */
public class EncryptDecryptFile {

    public EncryptDecryptFile() {
    }

    public void encryptFile(String entrada, String salida, String password) 
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException {
        FileInputStream in = null;
        CipherOutputStream cipherOut = null;
        
        try {
            // Creamos el stream para leer el archivo de entrada.
            in = new FileInputStream(entrada);
                        
            // Creamos una instancia de encriptación (Cipher) con algoritmo DES para encriptación simple.
            Cipher encrypt = Cipher.getInstance("DES");
            
            // Creamos una clave DES para encriptar, es provista del parametro password, para DES la clave debe ser de 8 bytes
            SecretKeySpec clave = new SecretKeySpec(password.getBytes(), "DES");
            
            // Inicializamos el Cipher para encriptar usando la clave
            encrypt.init(Cipher.ENCRYPT_MODE, clave);
            
            // Creamos un stream de salida de tipo CipherOutputStream utilizando la salida y el Cipher (encript)
            cipherOut = new CipherOutputStream(new FileOutputStream(salida), encrypt);
          
            byte[] b = new byte[1024];
            int numberOfBytedRead;
            while ((numberOfBytedRead = in.read(b)) >= 0) {
                cipherOut.write(b, 0, numberOfBytedRead);
            }
        } finally {
            if (in != null) {
                in.close();
            }
            if (cipherOut != null) {
                cipherOut.flush();
                cipherOut.close();
            }
        }
    }
    
    public void decryptFile(String entrada, String salida, String password) 
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException {
        CipherInputStream cipherIn = null;
        FileOutputStream out = null;
        
        try {
            // Creamos una instancia de encriptación (Cipher) con algoritmo DES para desencriptación simple.
            // Debe ser el mismo algoritmo que se empleo en la encriptación
            Cipher decrypt = Cipher.getInstance("DES");
            
            // Creamos una clave DES para desencriptar, es provista del parametro password, para DES la clave debe ser de 8 bytes
            SecretKeySpec clave = new SecretKeySpec(password.getBytes(), "DES");
            
            // Inicializamos el Cipher para desencriptar usando la clave
            decrypt.init(Cipher.DECRYPT_MODE, clave);
            
            // Creamos un stream de entrada de tipo CipherInputStream utilizando la entrada y el Cipher (decrypt)
            cipherIn = new CipherInputStream(new FileInputStream(entrada), decrypt);
                        
            /* 
                Los CipherInputStream y CipherOutputStream se pueden encadenar 
                pasandolos en sus constructores logrando doble o triple encriptacion.
                Notemos que tambien podriamos ubicar el cipher en la salida la 
                diferencia es que los datos en memoria estan siempre encriptados
                y solo se desencriptan al momento de escribirse al archivo.
            */
            
            // Creamos el stream de salida para escribir el archivo desencriptado
            out = new FileOutputStream(salida);
                       
            byte[] b = new byte[1024];
            int numberOfBytedRead;
            while ((numberOfBytedRead = cipherIn.read(b)) >= 0) {
                out.write(b, 0, numberOfBytedRead);
            }
        } finally {
            if (cipherIn != null) {
                cipherIn.close();
            }
            if (out != null) {
                out.flush();
                out.close();
            }
        }
    }
}
