package com.irs.encryptdecryptexamples;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;
import java.security.Security;
import java.util.HexFormat;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Clase de información de encriptación y desencriptación asimétrica (clave pública y clave privada).
 *
 * @autor IRS
 * @version 1.0.0
 */
public class AsymmetricMain {
    
    public static void main(String[] args) {
        try {
            System.out.println("Asymmetric encryption");
            asymmetricEncrypt();
        } catch (Exception ex) {
           ex.printStackTrace();
        }
    }
    
    private static void asymmetricEncrypt() throws Exception {
        Set<String> keypairGenerators = Security.getAlgorithms("KeyPairGenerator");
        System.out.println("Supported key generators: " + keypairGenerators.stream().sorted().collect(Collectors.joining(", ")));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(8192);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Private key\n" + encodePem(privateKey));
        System.out.println("Public key\n" + encodePem(publicKey));

        String text = "En un lugar de la Mancha de cuyo nombre no quiero acordarme";

        byte[] encrypted = encrypt(publicKey, text);
        String decrypted = new String(decrypt(privateKey, encrypted));

        System.out.println("Plain text: " + text);
        System.out.println("Public key encrypted: " + HexFormat.of().formatHex(encrypted));
        System.out.println("Private key decrypted: " + decrypted);
    }
    
    // Java (JDK) no soporta la generación del formato PEM
    // Bouncy Castle si lo soporta, hay que usar esta librería para generar el formato PEM
    private static String encodePem(PrivateKey privateKey) throws IOException {
        PemObject privateKeyPemObject = new PemObject("RSA PRIVATE KEY", privateKey.getEncoded());
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(privateKeyPemObject);
        pemWriter.close();
        return stringWriter.toString();
    }
    
    private static String encodePem(PublicKey publicKey) throws IOException {
        PemObject publicKeyPemObject = new PemObject("RSA PUBLIC KEY", publicKey.getEncoded());
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(publicKeyPemObject);
        pemWriter.close();
        return stringWriter.toString();
    }
    
    private static byte[] encrypt(PublicKey publicKey, String text) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(text.getBytes());
    }

    private static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }
}
