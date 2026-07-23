package com.irs.encryptdecryptexamples.algorithms;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Ejemplo de distintas funciones resumen (hash).
 */
public class AlgorithmHash {

    /**
     * Método que realiza la función resumen MD5 para el procesamiento.
     */
    public void doMD5() {
        doDigest(new MD5Digest());
    }

    /**
     * Método que realiza la función resumen SHA1 para el procesamiento.
     */
    public void doSHA1() {
        doDigest(new SHA1Digest());
    }

    /**
     * Método que realiza la función resuman (hash) de una archivo.
     * @param digest La función resumen a aplicar.
     * @return El resumen (hash) del contenido de un archivo.
     */
    protected byte[] doDigest(GeneralDigest digest) {
        byte[] fileContent = AlgorithmUtils.instance().doSelectFile("Seleccione un archivo", "txt");

        if (fileContent != null) {
            byte[] result = digest(digest, fileContent);
            System.out.println("El resumen es: " + new String(Hex.encode(result)));
            return result;
        }

        return null;
    }

    /**
     * Método que realiza la función resumen (hash) seleccionada
     * @param digest La función resumen a aplicar.
     * @param input El contenido del archivo sobre el que se aplicará la función resumen.
     * @return El resumen del contenido del archivo.
     */
    public byte[] digest(GeneralDigest digest, byte[] input) {
        digest.update(input, 0, input.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);

        return result;
    }
}
