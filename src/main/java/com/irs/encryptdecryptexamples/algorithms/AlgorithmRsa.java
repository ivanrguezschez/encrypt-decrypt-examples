package com.irs.encryptdecryptexamples.algorithms;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dh.KeyPairGeneratorSpi;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

/**
 * Ejemplo de cifrado RSA usando la libreria Bouncy Castle
 */
public class AlgorithmRsa {

    /**
     * Método que crea (genera) las claves RSA y las almacena en archivos en formato Base64 para que sea legible al abrirlo.
     */
    public void doGenerateKeys() {
        try {
            System.out.print("Introduzca el nombre de los archivos de clave a grabar \n(se almacenarán con las extensiones .priv y .pub):");
            String fileName = new Scanner(System.in).nextLine();
            if (!fileName.trim().isEmpty()) {
                String keyfilePath = AlgorithmUtils.instance().filesPath + fileName;
                KeyPairGenerator gen = KeyPairGeneratorSpi.getInstance("RSA");
                gen.initialize(1024, AlgorithmUtils.instance().generateSecureRamdom());

                Base64Encoder b64 = new Base64Encoder();

                KeyPair pair = gen.generateKeyPair();
                Key pubKey = pair.getPublic();
                Key privKey = pair.getPrivate();

                BufferedOutputStream pubOut = new BufferedOutputStream(new FileOutputStream(keyfilePath + ".pub"));
                BufferedOutputStream privOut = new BufferedOutputStream(new FileOutputStream(keyfilePath + ".priv"));
                b64.encode(pubKey.getEncoded(), 0, pubKey.getEncoded().length, pubOut);
                b64.encode(privKey.getEncoded(), 0, privKey.getEncoded().length, privOut);
                privOut.flush();
                privOut.close();
                pubOut.flush();
                pubOut.close();
            }
            System.out.println("Archivos de claves RSA almacenados");
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error generando las claves RSA: " + e);
        }
    }

    /**
     * Método que realiza el cifrado de un archivo usando la clave públic RSA.
     */
    public void doEncrypt() {
        try {
            byte[] text = AlgorithmUtils.instance().doSelectFile("Seleccione un archivo para cifrar", "txt");
            if (text != null) {
                byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave pública", "pub");
                if (key != null) {
                    Base64Encoder b64 = new Base64Encoder();
                    ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
                    BufferedOutputStream bKey = new BufferedOutputStream(keyBytes);
                    b64.decode(key, 0, key.length, bKey);
                    bKey.flush();
                    bKey.close();

                    byte[] res = encrypt(text, keyBytes.toByteArray());
                    System.out.println("Texto cifrado (en hexadecimal): " + new String(Hex.encode(res)));
                    AlgorithmUtils.instance().saveFile("encrsa", Hex.encode(res));
                }
            }
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error cifrando el archivo: " + e);
        }
    }

    /**
     * Método que realiza el descifrado de un archivo usando la clave privada RSA-
     */
    public void doDecrypt() {
        try {
            byte[] fileContent = AlgorithmUtils.instance().doSelectFile("Seleccione una archivo cifrado", "encrsa");
            if (fileContent == null) {
                return;
            }
            byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave privada", "priv");
            if (key != null) {
                Base64Encoder b64 = new Base64Encoder();
                ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();
                BufferedOutputStream bKey = new BufferedOutputStream(keyBytes);
                b64.decode(key, 0, key.length, bKey);
                bKey.flush();
                bKey.close();

                byte[] res = decrypt(Hex.decode(fileContent),keyBytes.toByteArray() );
                if (res != null) {
                    System.out.println("Texto en claro:\n" + new String(res));
                }
            }
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error descifrando el archivo: " + e);
        }
    }

    /**
     * Método que realiza el cifrado de los datos usando el algoritmo RSA.
     * @param inputData Datos a cifrar.
     * @param keyBytes Bytes de la clave.
     * @return Datos cifrados.
     */
    private byte[] encrypt(byte[] inputData, byte[] keyBytes) {
        try {
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(keyBytes);
            AsymmetricBlockCipher e = new RSAEngine();
            // http://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            return e.processBlock(inputData, 0, inputData.length);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error cifrando el archivo: " + e);
        }

        return null;
    }

    /**
     * Método que realiza el descifrado de los datos usando el algoritmo RSA.
     * @param encryptedData Datos a descifrar
     * @param keyBytes Bytes de la clave
     * @return Datos descifrados
     */
    private byte[] decrypt(byte[] encryptedData, byte[] keyBytes) {
        try {
            AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(keyBytes);
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);

            return e.processBlock(encryptedData, 0, encryptedData.length);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error descifrando el archivo: " + e);
        }

        return null;
    }
}
