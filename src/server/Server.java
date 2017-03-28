package server;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Server Socket
 * @author Manuel Martinez
 * Copyright 2017, ManuMtz
 */

public class Server {
    private static final int PORT = 9090;
    private boolean end = false;

    private BufferedReader in = null;
    private PrintStream out = null;

    private static final String SP = "$##$";
    private static final String SP_LINEA = "&00&";

    private static final String LS = "\n";
    private static final String FS = File.separator;

    private static SecretKey secretKey;
    private static KeyPair keyPair;
    private static PublicKey clientKey;

    private static final String BOOKS = "books";
    private static final String REBUTDIR = "rebut";

    private File mCristoBook = new File(BOOKS + FS + "mcristo.txt");
    private File rebut = new File(REBUTDIR + FS + "dracula.txt");

    private static final String TANCARCONNEXIO = "TANCARCONNEXIO";
    private static final String CHAT = "CHAT";
    private static final String RETORNCTRL = "RETORNCTRL";
    private static final String CLAUPUBLICA = "CLAUPUBLICA";
    private static final String MISSATGEENCRIPTAT = "MISSATGEENCRIPTAT";
    private static final String MISSATGEENCRIPTATFILE = "MISSATGEENCRIPTATFILE";
    private static final String CLAUENCRIPTADA = "CLAUENCRIPTADA";
    private static final String CLAUENCRIPTADAFI = "CLAUENCRIPTADAFI";

    private static final byte[] IV_PARAM = {0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F};

    private boolean farewellMessage = false;

    private void listen() {
        ServerSocket serverSocket;
        Socket clientSocket;

        try {
            //Es crea un ServerSocket que atendrà el port nº PORT a l'espera de
            //clients que demanin comunicar-se.
            serverSocket = new ServerSocket(PORT);

            while (!end) {
                //El mètode accept resta a l'espera d'una petició i en el moment de
                //produir-se crea una instància específica de sòcol per suportar
                //la comunicació amb el client acceptat.
                clientSocket = serverSocket.accept();

                //Processem la petició del client.
                proccesClientRequest(clientSocket);

                //Tanquem el sòcol temporal per atendre el client.
                closeClient(clientSocket);
            }

            //Tanquem el sòcol principal
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void proccesClientRequest(Socket clientSocket) {
        String clientMessage = "";

        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintStream(clientSocket.getOutputStream());

            do {
                farewellMessage = processData(clientMessage);

                if (farewellMessage) {
                    break;
                }

                menu();

                clientMessage = in.readLine();

            } while ((clientMessage) != null && !farewellMessage);

        } catch (IOException ex) {
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void menu() {
        String opcio;
        Scanner sc = new Scanner(System.in);

        System.out.println("---------------- Server ----------------");
        System.out.println();
        System.out.println("0. Desconnectar-se del CLIENT");
        System.out.println("1. Enviar un missatge al CLIENT");
        System.out.println("2. Retornar el control de les comunicacions al CLIENT");
        System.out.println("11. Generar clau simètrica i público-privades");
        System.out.println("12. Enviar clau pública al CLIENT");
        System.out.println("13. Encriptar missatge amb RSA amb clau embolcallada i enviar al CLIENT");
        System.out.println("14. Encriptar missatge (mès linias) amb RSA amb clau embolcallada i enviar al CLIENT");
        System.out.println("15. Encriptar llibre amb RSA amb clau embolcallada i enviar al CLIENT");
        System.out.println();
        System.out.print("opció?: ");
        opcio = sc.nextLine();

        switch (opcio) {
            case "0":
                out.println(TANCARCONNEXIO + SP + "El server tanca la comunicació");
                out.flush();
                farewellMessage = true;
                break;
            case "1":
                System.out.print("Nou missatge: ");
                String missatge = sc.nextLine();
                out.println(CHAT + SP + missatge);
                out.flush();
                break;
            case "2":
                out.println(RETORNCTRL + SP + "El SERVER retorna el control de les comunicacions al CLIENT");
                out.flush();
                break;
            case "11":
                secretKey = generadorDeClausSimetriques(128);
                keyPair = generadorDeClausAsimetriques(1024);
                menu();
                break;
            case "12":
                if (keyPair != null) {
                    BASE64Encoder encoder = new BASE64Encoder();
                    String clavePublica = encoder.encode(keyPair.getPublic().getEncoded()).replaceAll(LS, SP_LINEA);
                    out.println(CLAUPUBLICA + SP + clavePublica);
                    out.flush();
                    System.out.println(clavePublica);
                    System.out.println("Clau enviada");
                } else {
                    System.out.println("Has de generar la clau pùblica del menu 11");
                    menu();
                }
                break;
            case "13":
                if (clientKey != null && secretKey != null) {
                    System.out.print("Nou missatge a encriptar: ");
                    String missatgeAEncriptar = sc.nextLine();

                    String missatgeEncriptat = encriptarRSA(missatgeAEncriptar);

                    StringTokenizer msgTokenizer = new StringTokenizer(missatgeEncriptat, LS);

                    out.println(MISSATGEENCRIPTAT);
                    out.flush();

                    while (msgTokenizer.hasMoreTokens()) {
                        out.println(msgTokenizer.nextToken());
                        out.flush();
                    }

                    out.println(CLAUENCRIPTADAFI);
                    out.flush();

                    System.out.println("Missatge y clau enviada");
                } else {
                    System.out.println("El CLIENT ha de enviar la seva clau pùblica abans de tot");
                    System.out.println("A mès no t'oblides de crear la clau simetrica");
                    menu();
                }
                break;
            case "14":
                if (clientKey != null && secretKey != null) {

                    StringBuilder lineasAEncriptar = new StringBuilder();

                    System.out.print("Cuantes linies: ");
                    String nLineas = sc.nextLine();
                    int intLineas = 0;

                    try {
                        intLineas = Integer.parseInt(nLineas);

                        if (intLineas < 1) {
                            System.out.println("1 linia per defecte");
                            intLineas = 1;
                        }
                    } catch (NumberFormatException nfe) {
                        System.out.println("Nùmero de linies no vàlid");
                        menu();
                    }

                    for (int i = 0; i < intLineas; i++) {
                        System.out.print("linia " + (i + 1) + ": ");
                        String text = sc.nextLine();
                        lineasAEncriptar.append(text);
                        lineasAEncriptar.append(LS);
                    }

                    lineasAEncriptar.deleteCharAt(lineasAEncriptar.length() - 1);

                    String missatgeEncriptat = encriptarRSA(lineasAEncriptar.toString());

                    StringTokenizer msgTokenizer = new StringTokenizer(missatgeEncriptat, LS);

                    out.println(MISSATGEENCRIPTAT);
                    out.flush();

                    while (msgTokenizer.hasMoreTokens()) {
                        out.println(msgTokenizer.nextToken());
                        out.flush();
                    }

                    out.println(CLAUENCRIPTADAFI);
                    out.flush();

                    System.out.println("Missatge y clau enviada");
                } else {
                    System.out.println("El CLIENT ha de enviar la seva clau pùblica abans de tot");
                    System.out.println("A mès no t'oblides de crear la clau simetrica");
                    menu();
                }
                break;
            case "15":
                if (clientKey != null && secretKey != null) {

                    StringBuilder lineasAEncriptar = new StringBuilder();

                    try (BufferedReader br = new BufferedReader(new FileReader(mCristoBook))) {

                        String sCurrentLine;

                        while ((sCurrentLine = br.readLine()) != null) {
                            lineasAEncriptar.append(sCurrentLine);
                            lineasAEncriptar.append(LS);
                        }

                        lineasAEncriptar.deleteCharAt(lineasAEncriptar.length() - 1);

                    } catch (IOException e) {
                        System.out.println("books/mcristo.txt ha de existir (pot ser que no sigui aquest error)");
                        menu();
                    }

                    String missatgeEncriptat = encriptarRSA(lineasAEncriptar.toString());

                    StringTokenizer msgTokenizer = new StringTokenizer(missatgeEncriptat, LS);

                    out.println(MISSATGEENCRIPTATFILE);
                    out.flush();

                    while (msgTokenizer.hasMoreTokens()) {
                        out.println(msgTokenizer.nextToken());
                        out.flush();
                    }

                    out.println(CLAUENCRIPTADAFI);
                    out.flush();

                    System.out.println("Llibre y clau enviada");

                } else {
                    System.out.println("El SERVER ha de enviar la seva clau pùblica abans de tot");
                    System.out.println("A mès no t'oblides de crear la clau simetrica");
                    menu();
                }
                break;
            default:
                menu();
        }
    }

    private boolean processData(String clientMessage) {

        if (!clientMessage.isEmpty()) {

            StringTokenizer st = new StringTokenizer(clientMessage, SP);
            String tipusMissatge = st.nextToken();

            if (tipusMissatge.equals(CHAT)) {
                System.out.println("Missatge CHAT del CLIENT: " + st.nextToken());
            } else if (tipusMissatge.equals(CLAUPUBLICA)) {

                BASE64Decoder decoder = new BASE64Decoder();
                try {
                    String clauPub = st.nextToken().replaceAll(SP_LINEA, LS);
                    byte[] clavePublica = decoder.decodeBuffer(clauPub);
                    clientKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(clavePublica));
                    System.out.println("Clau pùblica rebuda");
                } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

            } else if (tipusMissatge.equals(RETORNCTRL)) {
                System.out.println("Control retomado");
            } else if (tipusMissatge.equals(MISSATGEENCRIPTAT)) {
                StringBuilder missatge = new StringBuilder();
                String trosMissatgeTmp;
                try {
                    while (((trosMissatgeTmp = in.readLine()) != null)
                            && !trosMissatgeTmp.contains(CLAUENCRIPTADAFI)) {
                        missatge.append(trosMissatgeTmp).append(LS);
                    }
                    missatge.deleteCharAt(missatge.length() - 1);

                    String msgTotal = missatge.toString();

                    StringTokenizer msgTotalTokenizer = new StringTokenizer(msgTotal, SP);

                    String missatgeEncriptat = "";
                    String simetricKeyEncriptada = "";

                    while (msgTotalTokenizer.hasMoreTokens()) {

                        if (msgTotalTokenizer.nextToken().equals(MISSATGEENCRIPTAT)) {
                            missatgeEncriptat = msgTotalTokenizer.nextToken();
                        }

                        if (msgTotalTokenizer.nextToken().equals(CLAUENCRIPTADA)) {
                            simetricKeyEncriptada = msgTotalTokenizer.nextToken();
                        }
                    }

                    BASE64Decoder decoder = new BASE64Decoder();

                    byte[] missatgeEncriptatByte = decoder.decodeBuffer(missatgeEncriptat);
                    byte[] simetricKeyEncriptadaByte = decoder.decodeBuffer(simetricKeyEncriptada);

                    System.out.println("Missatge del CLIENT:");
                    System.out.println(desencriptarRSA(missatgeEncriptatByte, simetricKeyEncriptadaByte));

                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (tipusMissatge.equals(MISSATGEENCRIPTATFILE)) {
                StringBuilder missatge = new StringBuilder();
                String trosMissatgeTmp;

                File rebDir = new File(REBUTDIR);

                if (!rebDir.exists()) {
                    rebDir.mkdirs();
                }

                try (BufferedWriter bw = new BufferedWriter(new FileWriter(rebut, false))) {
                    while (((trosMissatgeTmp = in.readLine()) != null)
                            && !trosMissatgeTmp.contains(CLAUENCRIPTADAFI)) {
                        missatge.append(trosMissatgeTmp).append(LS);
                    }
                    missatge.deleteCharAt(missatge.length() - 1);

                    String msgTotal = missatge.toString();

                    StringTokenizer msgTotalTokenizer = new StringTokenizer(msgTotal, SP);

                    String missatgeEncriptat = "";
                    String simetricKeyEncriptada = "";

                    while (msgTotalTokenizer.hasMoreTokens()) {

                        if (msgTotalTokenizer.nextToken().equals(MISSATGEENCRIPTAT)) {
                            missatgeEncriptat = msgTotalTokenizer.nextToken();
                        }

                        if (msgTotalTokenizer.nextToken().equals(CLAUENCRIPTADA)) {
                            simetricKeyEncriptada = msgTotalTokenizer.nextToken();
                        }
                    }

                    BASE64Decoder decoder = new BASE64Decoder();

                    byte[] missatgeEncriptatByte = decoder.decodeBuffer(missatgeEncriptat);
                    byte[] simetricKeyEncriptadaByte = decoder.decodeBuffer(simetricKeyEncriptada);

                    bw.write(desencriptarRSA(missatgeEncriptatByte, simetricKeyEncriptadaByte));
                    bw.flush();

                    System.out.println("Fitxer rebut");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }

        return clientMessage.contains(TANCARCONNEXIO);
    }

    private void closeClient(Socket clientSocket) {
        //Si falla el tancament no podem fer gaire cosa, només enregistrar el problema.
        try {
            //Tancament de tots els recursos.
            if (clientSocket != null && !clientSocket.isClosed()) {
                if (!clientSocket.isInputShutdown()) {
                    clientSocket.shutdownInput();
                }
                if (!clientSocket.isOutputShutdown()) {
                    clientSocket.shutdownOutput();
                }
                clientSocket.close();
            }
        } catch (IOException ex) {
            //Enregistrem l’error amb un objecte Logger.
            Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, ex);
        }
    }

    private SecretKey generadorDeClausSimetriques(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    private KeyPair generadorDeClausAsimetriques(int size) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(size);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    private String encriptarRSA(String text) {

        StringBuilder dadesEncriptades = new StringBuilder();

        dadesEncriptades.append(MISSATGEENCRIPTAT).append(SP);

        try {
            //Encriptem les dades amb AES en mode CBC.
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            byte[] textEnByte = cipher.doFinal(text.getBytes());

            dadesEncriptades.append(new BASE64Encoder().encode(textEnByte)).append(SP);

            //Encriptem la clau d'encriptació que s'ha fet servir amb RSA + la clau pública.
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, clientKey);
            byte[] clauAESEncriptadaEnByte = cipher.wrap(secretKey);

            dadesEncriptades.append(CLAUENCRIPTADA).append(SP).append(new BASE64Encoder().encode(clauAESEncriptadaEnByte));

        } catch (Exception ex) {
            System.err.println("ERROR al encriptar en RSA" + ex);
        }

        return dadesEncriptades.toString();
    }

    private String desencriptarRSA(byte[] missatgeEncriptatByte, byte[] simetricKeyEncriptadaByte) {
        String dadesDesencriptadesEnString = "";
        try {
            //Desencriptem la clau d'encriptació que s'ha fet servir amb RSA + la clau privada.
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
            SecretKey clauAESDesencriptada = (SecretKey) cipher.unwrap(simetricKeyEncriptadaByte, "AES", Cipher.SECRET_KEY);
            //Una clau simètrica és una "SECRET_KEY".

            //Desencriptem les dades amb AES en mode CBC.
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.DECRYPT_MODE, clauAESDesencriptada, iv);
            byte[] dadesDesencriptadesEnByte = cipher.doFinal(missatgeEncriptatByte);

            dadesDesencriptadesEnString = new String(dadesDesencriptadesEnByte);

        } catch (Exception ex) {
            System.err.println("ERROR: No es pot desencriptar " + ex);
        }
        return dadesDesencriptadesEnString;
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.listen();
    }

}
