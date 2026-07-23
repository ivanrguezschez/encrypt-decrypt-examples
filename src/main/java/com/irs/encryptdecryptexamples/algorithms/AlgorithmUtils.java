package com.irs.encryptdecryptexamples.algorithms;

import java.io.*;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Scanner;

public final class AlgorithmUtils {

    private static AlgorithmUtils _singleton = null;

    public String filesPath;

    /**
     * Establece la ruta de archivos a gestinar en este ejemplo
     */
    private AlgorithmUtils() {
        // Directorio actual donde se encuentra el usuario 'user.dir'
        filesPath = System.getProperty("user.dir") +  File.separator + "files" +  File.separator;
        // Si la ruta no existe se crea
        File path = new File(filesPath);
        if (!path.exists()) {
            path.mkdir();
        }
    }

    public static AlgorithmUtils instance() {
        if (_singleton == null) {
            _singleton = new AlgorithmUtils();
        }
        return _singleton;
    }

    /**
     * Generación de número aleatorio "seguro"
     */
    public SecureRandom generateSecureRamdom() {
        SecureRandom sr = null;
        try {
            sr = new SecureRandom();
            // Inicializamos con una semilla
            sr.setSeed("IRS1234.".getBytes());
        } catch (Exception e) {
            System.err.println("Ha ocurrido un error generando el número aleatorio");
            return null;
        }
        return sr;
    }

    /**
     * Elimina el contenido de la consola
     */
    public void clearConsole() {
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                Runtime.getRuntime().exec("cls");
            } else {
                Runtime.getRuntime().exec("clear");
            }
        } catch (Exception e) {
        }
    }

    /**
     * Almacena contenido en un archivo a través de la consola
     */
    public boolean saveConsoleToFile() {
        System.out.println("Introduzca el texto del archivo \n(Escriba 'fin' en una línea para finalizar)");
        String text = "", line = "";
        Scanner scan = new Scanner(System.in);

        try {
            while (!line.equals("fin")) {
                line = scan.nextLine().toLowerCase();
                if (!line.equals("fin")) {
                    text = text + line + "\n";
                }
            }
            return saveFile("txt", text.getBytes());
        } catch (Exception e) {
            scan.close();
            System.out.println("Ha ocurrido un error: " + e);
            return false;
        }

    }

    /**
     * Guarda datos en un archivo.
     * @param ext Extensión del archivo en el que almacenar los datos
     * @param data Contenido a almacenar en el archivo.
     * @return true si la operación se realiza correctamente, false en caso contrario.
     */
    public boolean saveFile(String ext, byte[] data) {
        System.out.print("Introduzca el nombre del archivo a grabar \n(se almacenará con la extensión " + ext + "):");
        String fileName = new Scanner(System.in).nextLine();

        if (fileName.trim().isEmpty()) {
            saveFile(ext, data);
        }
        String filePath = filesPath + fileName + "." + ext;
        try {
            BufferedOutputStream keystream = new BufferedOutputStream(new FileOutputStream(filePath));
            keystream.write(data, 0, data.length);
            keystream.flush();
            keystream.close();
        } catch (Exception e) {
            System.out.println("Ha ocurrido un error intentando grabar el archivo '" + filePath + "'\n");
            e.printStackTrace();
            return false;
        }
        System.out.println("Archivo almacenado en " + filePath + "\n");
        return true;
    }

    public String readTextFromConsole(String message) {
        if (message != null) {
            System.out.print(message + ":");
        }
        return new Scanner(System.in).nextLine();
    }

    /**
     * Carga un archivo
     * @param infile Archivo a cargar
     * @return el contenido del archivo
     */
    public byte[] loadFile(String infile) {
        try {
            BufferedInputStream keystream = new BufferedInputStream(new FileInputStream(infile));
            int len = keystream.available();
            byte[] keyhex = new byte[len];
            keystream.read(keyhex, 0, len);
            return keyhex;
        } catch (Exception e) {
            System.err.println("Error cargando el archivo ");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Seleciona fichero para almacenar mensaje
     * @param message Mensaje a grabar en un archivo
     * @param extension Extensión del archivo en el que grabar mensaje
     * @return
     */
    public byte[] doSelectFile(String message, String extension) {
        File dir = new File(filesPath);

        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String filename) {
                return filename.endsWith(extension);
            }
        });
        if (!Objects.isNull(files)) {
            if (files.length == 0) {
                System.out.println("No se ha encontrado ningún archivo con la extensión " + extension);
                return null;
            }
            for (File file : files) {
                System.out.println("\t- " + file.getName());
            }
        }
        String fileName = readTextFromConsole(message);
        if (new File(filesPath + fileName).exists()) {
            return loadFile(filesPath + fileName);
        }
        if (new File(filesPath + fileName + "." + extension).exists()) {
            return loadFile(filesPath + fileName + "." + extension);
        } else {
            System.out.println("No se ha encontrado el archivo");
            return null;
        }
    }
}
