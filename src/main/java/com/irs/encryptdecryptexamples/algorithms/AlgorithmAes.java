package com.irs.encryptdecryptexamples.algorithms;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Ejemplo de cifrado AES usando la libreria Bouncy Castle
 */
public class AlgorithmAes {

    // AES con un tamaño de bloque de 16 bytes
    public final int blockSize = 16;

    /**
     * Método que crea una clave AES y la almacena en un archivo en formato Hexadecimal para que sea legible al abrirlo.
     */
    public void doGenerateKey() {
        byte[] key = generateKeyAndIV();
        if (key != null) {
            System.out.println("Clave generada: " + new String(Hex.encode(Arrays.copyOfRange(key, 0, 24))));
            System.out.println("IV generado: " + new String(Hex.encode(Arrays.copyOfRange(key, 24,blockSize + 24))));
            AlgorithmUtils.instance().saveFile("aeskeyiv", Hex.encode(key));
        }
    }

    /**
     * Método que realiza el cifrado de un archivo usando el algoritmo AES y una clave alamcenada también en otro archivo.
     */
    public void doEncrypt() {
        byte[] text = AlgorithmUtils.instance().doSelectFile("Seleccione un archivo para cifrar", "txt");
        if (text != null) {
            byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave","aeskeyiv");
            if (key != null) {
                byte[] res = encrypt(text,
                        Arrays.copyOfRange(Hex.decode(key), 0, 24),
                        Arrays.copyOfRange(Hex.decode(key), 24, 24 + blockSize));
                System.out.println("Texto cifrado (en hexadecimal): " + new String(Hex.encode(res)));
                AlgorithmUtils.instance().saveFile("encaes", Hex.encode(res));
            }
        }
    }

    /**
     * Método que realiza el descifrado de un archivo usando el algoritmo AES y una clave almacenada también en otro archivo-
     */
    public void doDecrypt() {
        byte[] fileContent = AlgorithmUtils.instance().doSelectFile("Seleccione una archivo cifrado", "encaes");
        if (fileContent == null) {
            return;
        }
        byte[] key = AlgorithmUtils.instance().doSelectFile("Seleccione una clave","aeskeyiv");
        if (key != null) {
            byte[] res = decrypt(Hex.decode(fileContent),
                    Arrays.copyOfRange(Hex.decode(key), 0, 24),
                    Arrays.copyOfRange(Hex.decode(key), 24, blockSize + 24));
            if (res != null) {
                System.out.println("Texto en claro: " + new String(res));
            }
        }
    }

    /**
     * Cifra/Descifra datos con el algoritmo AES. Al ser un algoritmo de cifrado
     * simétrico se puede usar para ambos procesos
     *
     * @param cipher Cifrador/Descifrador AES
     * @param data Datos origen
     * @return Datos destino
     * @throws Exception si se produce algún error
     */
    private static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        // Creamos un array de bytes del tamaño estimado de descifrado
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];

        // Procesamos todos los bytes de los datos
        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);

        // Realizamos el procesamiento final (conceptualmente, es como el flush de los streams)
        int length2 = cipher.doFinal(outBuf, length1);
        int actualLength = length1 + length2;
        byte[] result = new byte[actualLength];

        // Copiamos el resultado y lo devolvemos
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }

    /**
     * Método que realiza el cifrado de los datos usando el algoritmo AES.
     * @param plain Datps a cifrar
     * @param key Clave (24 bytes)
     * @param iv Vector de Inicialización (Tamaño en bytes del bloque)
     * @return Datos cifrados
     */
    private static byte[] encrypt(byte[] plain, byte[] key, byte[] iv) {
        try {
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
            aes.init(true, ivAndKey);
            return cipherData(aes, plain);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error al intentar cifrar el texto: " + e);
            return null;
        }
    }

    /**
     * Método que realiza el descifrado de los datos usando el algoritmo AES.
     * Este método podría obviarse y utilizarse el método encrypt para realizar el descifrado al ser
     * el algoritmo AES un algoritmo simétrico, pero se mantiene por coherencia con el resto de ejemplos.
     * @param ciphered Datos cifrados
     * @param key Clave (24 bytes)
     * @param iv Vector de Inicialización (Tamaño en bytes del bloque)
     * @return Datos descifrados
     */
    private static byte[] decrypt(byte[] ciphered, byte[] key, byte[] iv) {
        try {
            // Creamos el cifrador
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            // Procesamos la clave y el IV
            CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
            aes.init(false, ivAndKey);
            return cipherData(aes, ciphered);
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error al intentar descifrar el texto: " + e);
            return null;
        }
    }

    /**
     * Genera una Clave e IV para el cifrado/descifrado AES a partir de un número aleatorio "seguro"
     *
     * @return 24 + blocksize bytes (Clave+IV)
     */
    public byte[] generateKeyAndIV() {
        // Creamos un generador de aleatorios "seguro"
        SecureRandom sr = AlgorithmUtils.instance().generateSecureRamdom();

        if (!Objects.isNull(sr)) {
            // Generamos del tamaño que necesitamos (24 bytes de clave + tamaño de bloque como IV)
            return sr.generateSeed(24 + blockSize + 10);
        }

        return null;
    }
}
