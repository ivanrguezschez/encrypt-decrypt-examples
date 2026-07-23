package com.irs.encryptdecryptexamples.algorithms;

import java.util.Scanner;

public class AlgorithmMain {

    /**
     * Menu de opciones
     */
    protected final int MENU_OPTION_CREATE_FILE = 0;
    protected final int MENU_OPTION_GENERATE_DES_KEY = 1;
    protected final int MENU_OPTION_ENCRYPT_DES = 2;
    protected final int MENU_OPTION_DECRYPT_DES = 3;
    protected final int MENU_OPTION_GENERATE_TRIPLEDES_KEY = 4;
    protected final int MENU_OPTION_ENCRYPT_TRIPLEDES = 5;
    protected final int MENU_OPTION_DECRYPT_TRIPLEDES = 6;
    protected final int MENU_OPTION_GENERATE_AES_KEY = 7;
    protected final int MENU_OPTION_ENCRYPT_AES = 8;
    protected final int MENU_OPTION_DECRYPT_AES = 9;
    protected final int MENU_OPTION_CREATE_MD5 = 10;
    protected final int MENU_OPTION_CREATE_SHA1 = 11;
    protected final int MENU_OPTION_GENERATE_RSA_KEYS = 12;
    protected final int MENU_OPTION_ENCRYPT_RSA = 13;
    protected final int MENU_OPTION_DECRYPT_RSA = 14;

    public static void main(String[] args) {
        AlgorithmMain instance = new AlgorithmMain();
        instance.doMenu();
    }

    /**
     * Muestra el menú y gestiona las solicitudes de cada una de sus opciones.
     */
    private void doMenu() {
        System.out.println("\n\nPruebas de algoritmos criptográficos con Java y BouncyCastle");
        System.out.println("----------------------------------------------------------------");
        System.out.println("\t0. Crear un archivo de texto");
        System.out.println("DES");
        System.out.println("\t1. Generar clave para algoritmo de cifrado DES");
        System.out.println("\t2. Cifrar archivo con DES");
        System.out.println("\t3. Descifrar archivo con DES");
        System.out.println("TripleDES");
        System.out.println("\t4. Generar clave para algoritmo de cifrado TripleDES");
        System.out.println("\t5. Cifrar archivo con TripleDES");
        System.out.println("\t6. Descifrar archivo con TripleDES");
        System.out.println("AES");
        System.out.println("\t7. Generar clave para algoritmo de cifrado AES");
        System.out.println("\t8. Cifrar archivo con AES");
        System.out.println("\t9. Descifrar archivo con AES");
        System.out.println("FUNCIONES RESUMEN");
        System.out.println("\t10. Generar resumen MD5 de un archivo");
        System.out.println("\t11. Generar resumen SHA1 de un archivo");
        System.out.println("RSA");
        System.out.println("\t12. Generar par de claves RSA");
        System.out.println("\t13. Cifrar archivo con RSA");
        System.out.println("\t14. Descifrar archivo con RSA");
        System.out.println("\nq. Terminar ejecución");
        System.out.print("\n\nSeleccione una opción y pulse ENTER:");

        Scanner scanner = new Scanner(System.in);
        String selectedOption = scanner.nextLine();

        if (!selectedOption.matches("-?\\d+?") && !selectedOption.equals("q")) {
            System.out.println("Opción incorrecta");
        } else {
            if(selectedOption.equals("q")){
                System.exit(0);
            }
            switch (Integer.parseInt(selectedOption)) {
                case MENU_OPTION_CREATE_FILE:
                    AlgorithmUtils.instance().saveConsoleToFile();
                    break;
                case MENU_OPTION_GENERATE_DES_KEY:
                    new AlgorithmDes().doGenerateKey();
                    break;
                case MENU_OPTION_ENCRYPT_DES:
                    new AlgorithmDes().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_DES:
                    new AlgorithmDes().doDecrypt();
                    break;
                case MENU_OPTION_GENERATE_TRIPLEDES_KEY:
                    new AlgorithmTripleDes().doGenerateKey();
                    break;
                case MENU_OPTION_ENCRYPT_TRIPLEDES:
                    new AlgorithmTripleDes().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_TRIPLEDES:
                    new AlgorithmTripleDes().doDecrypt();
                    break;
                case MENU_OPTION_GENERATE_AES_KEY:
                    new AlgorithmAes().doGenerateKey();
                    break;
                case MENU_OPTION_ENCRYPT_AES:
                    new AlgorithmAes().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_AES:
                    new AlgorithmAes().doDecrypt();
                    break;
                case MENU_OPTION_CREATE_MD5:
                    new AlgorithmHash().doMD5();
                    break;
                case MENU_OPTION_CREATE_SHA1:
                    new AlgorithmHash().doSHA1();
                    break;
                case MENU_OPTION_GENERATE_RSA_KEYS:
                    new AlgorithmRsa().doGenerateKeys();
                    break;
                case MENU_OPTION_ENCRYPT_RSA:
                    new AlgorithmRsa().doEncrypt();
                    break;
                case MENU_OPTION_DECRYPT_RSA:
                    new AlgorithmRsa().doDecrypt();
                    break;
                default:
                    System.out.println("Opción incorrecta");
                    break;
            }
        }
        AlgorithmUtils.instance().clearConsole();
        doMenu();
    }
}
