package com.irs.encryptdecryptexamples.algorithms;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Ejemplo de cifrado Triple DES usando la libreria Bouncy Castle
 */
public class AlgorithmTripleDes {

    BlockCipher engine = new DESedeEngine();

    /**
     * Método que crea una clave TripleDES y la almacena en un archivo en formato Hexadecimal para que sea legible al abrirlo.
     */
    public void doGenerateKey() {
        byte[] key = generateKey();
        if (key != null) {
            System.out.println("Clave generada: " + new String(Hex.encode(key)));
            AlgorithmUtils.instance().saveFile("tripledeskey", Hex.encode(key));
        }
    }

    /**
     * Método que realiza el cifrado de un archivo usando el algoritmo TripleDES y una clave alamcenada también en otro archivo.
     */
    public void doEncrypt() {
        // Archivo a cifrar
        byte[] text = AlgorithmUtils.instance().doSelectFile("Seleccione un archivo para cifrar", "txt");
        if (text != null) {
            // Clave a usar
            byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave","tripledeskey");
            if (key != null) {
                // Almacenamos en hexadecimal para que sea legible en el archivo
                byte[] res = encrypt(Hex.decode(key),text);
                System.out.println("Texto cifrado (en hexadecimal): " + new String(Hex.encode(res)));
                AlgorithmUtils.instance().saveFile("tripleencdes", Hex.encode(res));
            }
        }
    }

    /**
     * Método que realiza el descifrado de un archivo usando el algoritmo TripleDES y una clave almacenada también en otro archivo-
     */
    public void doDecrypt() {
        // Archivo a descifrar
        byte[] fileContent = AlgorithmUtils.instance().doSelectFile("Seleccione una archivo cifrado", "encdes");
        if (fileContent == null) {
            return;
        }
        // Clave a usar
        byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave","tripledeskey");
        if (key != null) {
            // Desciframos el archivo
            byte[] res = decrypt(Hex.decode(key), Hex.decode(fileContent));
            if (res != null) {
                System.out.println("Texto en claro: " + new String(res));
            }
        }
    }

    /**
     * Método que realiza el cifrado de los datos usando el algoritmo TripleDES.
     * @param key Clave
     * @param ptBytes Texto a cifrar
     * @return Texto cifrado
     */
    protected byte[] encrypt(byte[] key, byte[] ptBytes) {
        // Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

        // Inicializamos con la clave
        cipher.init(true, new KeyParameter(key));

        // Reservamos espacio para el texto cifrado
        byte[] rv = new byte[cipher.getOutputSize(ptBytes.length)];

        // Realizamos el procesamiento con TripleDES
        int tam = cipher.processBytes(ptBytes, 0, ptBytes.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error al intentar cifrar el archivo: " + e.getLocalizedMessage());
            e.printStackTrace();
            return null;
        }
        // Devolvemos los datos cifrados
        return rv;
    }

    /**
     * Método que realiza el descifrado de los datos usando el algoritmo TripleDES.
     * Este método podría obviarse y utilizarse el método encrypt para realizar el descifrado al ser
     * el algoritmo TripleDES un algoritmo simétrico, pero se mantiene por coherencia con el resto de ejemplos
     * @param key Clave
     * @param cipherText Texto a descifrar
     * @return Texto descifrado
     */
    public byte[] decrypt(byte[] key, byte[] cipherText) {
        // Creamos un cifrador de Bloque con Padding y con el modo de bloque CBC
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

        // Inicializamos con la clave
        cipher.init(false, new KeyParameter(key));

        // Reservamos espacio para el texto descifrado
        byte[] rv = new byte[cipher.getOutputSize(cipherText.length)];

        // Realizamos el procesamiento con TripleDES
        int tam = cipher.processBytes(cipherText, 0, cipherText.length, rv, 0);
        try {
            cipher.doFinal(rv, tam);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error al intentar descifrar el archivo: " + e.getLocalizedMessage());
            e.printStackTrace();
            return null;
        }
        // Devolvemos los datos descifrados
        return rv;
    }

    /**
     * Genera una Clave para el cifrado/descifrado TripleDES a partir de un número aleatorio "seguro".
     *
     * @return Clave generada con la longitud de DESedeParameters
     */
    public byte[] generateKey() {
        // Creamos un generador de aleatorios "seguro"
        SecureRandom sr = AlgorithmUtils.instance().generateSecureRamdom();

        if (!Objects.isNull(sr)) {
            // Generamos la clave TripleDES con la longitud necesaria para el algoritmo
            KeyGenerationParameters kgp = new KeyGenerationParameters(sr, (DESedeParameters.DES_EDE_KEY_LENGTH) * 8);

            DESedeKeyGenerator kg = new DESedeKeyGenerator();
            kg.init(kgp);

            return kg.generateKey();
        }

        return null;
    }
}
