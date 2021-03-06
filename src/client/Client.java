package client;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Client Socket
 *
 * @author Manuel Martinez
 *         Copyright 2017, ManuMtz
 */

public class Client {

    private BufferedReader in;
    private PrintStream out;

    private static final String SP = "$##$";

    private static final String NULL = "null";

    private static final String LS = System.lineSeparator();
    private static final int LS_SIZE = LS.length();

    private static final String FS = File.separator;

    private static SecretKey secretKey;
    private static KeyPair keyPair;
    private static PublicKey clientKey;

    private static final String BOOKS = "books";
    private static final String REBUTDIR = "rebut";

    private File draculaBook = new File(BOOKS + FS + "dracula.txt");
    private File rebut = new File(REBUTDIR + FS + "mcristo.txt");

    private static final String TANCARCONNEXIO = "TANCARCONNEXIO";

    private static final String CHAT = "CHAT";

    private static final String RETORNCTRL = "RETORNCTRL";

    private static final String CLAUPUBLICA = "CLAUPUBLICA";
    private static final String CLAUPUBLICAFI = "CLAUPUBLICAFI";

    private static final String MISSATGEENCRIPTAT = "MISSATGEENCRIPTAT";
    private static final String MISSATGEENCRIPTATFILE = "MISSATGEENCRIPTATFILE";
    private static final String CLAUENCRIPTADA = "CLAUENCRIPTADA";
    private static final String CLAUENCRIPTADAFI = "CLAUENCRIPTADAFI";

    private static final String CHATLINIAS = "CHATLINIAS";
    private static final String CHATFILE = "CHATFILE";
    private static final String CHATLINIASFI = "CHATLINIASFI";

    private static final byte[] IV_PARAM = {0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F};

    private boolean noTancar = true;

    private void connect(String address, int port) {
        String serverData;
        boolean continueConnected = true;
        Socket socket;

        try {
            socket = new Socket(InetAddress.getByName(address), port);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintStream(socket.getOutputStream());

            //El client atén el port fins que decideix finalitzar.
            while (continueConnected) {
                serverData = in.readLine();

                //Processament de les dades rebudes i obtenció d’una nova petició.
                continueConnected = getRequest(serverData);
            }

            close(socket);
        } catch (UnknownHostException ex) {
            System.err.println("Error de connexió. No existeix el host - " + ex.getMessage());
        } catch (IOException ex) {
            System.err.println("Error de connexió indefinit - " + ex.getMessage());
        }
    }

    private boolean getRequest(String serverData) {

        noTancar = processData(serverData);

        if (!noTancar) {
            return false;
        }

        menu();

        return noTancar;
    }

    private void menu() {
        String opcio;
        Scanner sc = new Scanner(System.in);

        System.out.println("---------------- CLIENT ----------------");
        System.out.println();
        System.out.println("0. Desconnectar-se del SERVER");
        System.out.println("1. Enviar un missatge al SERVER");
        System.out.println("2. Retornar el control de les comunicacions al SERVER");
        System.out.println("11. Generar clau simètrica i público-privades");
        System.out.println("12. Enviar clau pública al SERVER");
        System.out.println("13. Encriptar missatge amb RSA amb clau embolcallada i enviar al SERVER");
        System.out.println();
        System.out.println("EXTRAS");
        System.out.println();
        System.out.println("14. Encriptar missatge (mès linias) amb RSA amb clau embolcallada i enviar al SERVER");
        System.out.println("15. Encriptar llibre amb RSA amb clau embolcallada i enviar al SERVER");
        System.out.println("16. Enviar un missatge (mès linias) al SERVER");
        System.out.println("17. Enviar un llibre al SERVER");
        System.out.println();
        System.out.print("opció?: ");
        opcio = sc.nextLine();

        switch (opcio) {
            case "0":
                out.println(TANCARCONNEXIO + SP + "El client tanca la comunicació");
                out.flush();
                noTancar = false;
                break;
            case "1":
                System.out.print("Nou missatge: ");
                String missatge = sc.nextLine();
                out.println(CHAT + SP + missatge);
                out.flush();
                break;
            case "2":
                out.println(RETORNCTRL + SP + "El CLIENT retorna el control de les comunicacions al SERVER");
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
                    String clavePublica = encoder.encode(keyPair.getPublic().getEncoded());

                    StringTokenizer cPublicaTokenizer = new StringTokenizer(clavePublica, LS);

                    out.println(CLAUPUBLICA);
                    out.flush();

                    while (cPublicaTokenizer.hasMoreElements()) {
                        String tmpLine = cPublicaTokenizer.nextToken(LS);
                        out.println(tmpLine);
                        out.flush();
                    }

                    out.println(CLAUPUBLICAFI);
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
                        out.println(msgTokenizer.nextToken(LS));
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

                    int intLineas;
                    System.out.print("Cuantes linies: ");
                    String nLineas = sc.nextLine();

                    try {
                        intLineas = Integer.parseInt(nLineas);
                        if (intLineas < 1) {
                            throw new NumberFormatException("Nùmero de linies no vàlid");
                        } else {

                            for (int i = 0; i < intLineas; i++) {
                                System.out.print("linia " + (i + 1) + ": ");
                                String text = sc.nextLine();
                                lineasAEncriptar.append(text);
                                lineasAEncriptar.append(LS);
                            }

                            for (int i = 0; i < LS_SIZE; i++) {
                                lineasAEncriptar.deleteCharAt(lineasAEncriptar.length() - 1);
                            }

                            String missatgeEncriptat = encriptarRSA(lineasAEncriptar.toString());
                            StringTokenizer msgTokenizer = new StringTokenizer(missatgeEncriptat, LS);

                            out.println(MISSATGEENCRIPTAT);
                            out.flush();

                            while (msgTokenizer.hasMoreTokens()) {
                                out.println(msgTokenizer.nextToken(LS));
                                out.flush();
                            }

                            out.println(CLAUENCRIPTADAFI);
                            out.flush();

                            System.out.println("Missatge y clau enviada");
                        }

                    } catch (NumberFormatException nfe) {
                        System.out.println("Nùmero de linies no vàlid");
                        menu();
                    }

                } else {
                    System.out.println("El SERVER ha de enviar la seva clau pùblica abans de tot");
                    System.out.println("A mès no t'oblides de crear la clau simetrica");
                    menu();
                }
                break;
            case "15":
                if (clientKey != null && secretKey != null) {

                    StringBuilder lineasAEncriptar = new StringBuilder();

                    try (BufferedReader br = new BufferedReader(new FileReader(draculaBook))) {

                        String sCurrentLine;

                        while ((sCurrentLine = br.readLine()) != null) {
                            lineasAEncriptar.append(sCurrentLine);
                            lineasAEncriptar.append(LS);
                        }

                        try {
                            for (int i = 0; i < LS_SIZE; i++) {
                                lineasAEncriptar.deleteCharAt(lineasAEncriptar.length() - 1);
                            }
                        } catch (StringIndexOutOfBoundsException sOB) {
                            lineasAEncriptar.append(NULL);
                        }

                        String missatgeEncriptat = encriptarRSA(lineasAEncriptar.toString());

                        StringTokenizer msgTokenizer = new StringTokenizer(missatgeEncriptat, LS);

                        out.println(MISSATGEENCRIPTATFILE);
                        out.flush();

                        while (msgTokenizer.hasMoreTokens()) {
                            out.println(msgTokenizer.nextToken(LS));
                            out.flush();
                        }

                        out.println(CLAUENCRIPTADAFI);
                        out.flush();

                        System.out.println("Llibre y clau enviada");

                    } catch (IOException e) {
                        System.out.println("books/dracula.txt ha de existir (pot ser que no sigui aquest error)");
                        menu();
                    }

                } else {
                    System.out.println("El SERVER ha de enviar la seva clau pùblica abans de tot");
                    System.out.println("A mès no t'oblides de crear la clau simetrica");
                    menu();
                }
                break;
            case "16":
                StringBuilder lineasDelMissatge = new StringBuilder();

                System.out.print("Cuantes linies: ");
                String nLineas = sc.nextLine();

                try {
                    int intLineas = Integer.parseInt(nLineas);
                    if (intLineas < 1) {
                        throw new NumberFormatException("Nùmero de linies no vàlid");
                    } else {

                        for (int i = 0; i < intLineas; i++) {
                            System.out.print("linia " + (i + 1) + ": ");
                            String text = sc.nextLine();
                            lineasDelMissatge.append(text);
                            lineasDelMissatge.append(LS);
                        }

                        for (int i = 0; i < LS_SIZE; i++) {
                            lineasDelMissatge.deleteCharAt(lineasDelMissatge.length() - 1);
                        }

                        StringTokenizer msgTokenizer = new StringTokenizer(lineasDelMissatge.toString(), LS);

                        out.println(CHATLINIAS);
                        out.flush();

                        while (msgTokenizer.hasMoreTokens()) {
                            out.println(msgTokenizer.nextToken(LS));
                            out.flush();
                        }

                        out.println(CHATLINIASFI);
                        out.flush();

                        System.out.println("Missatge enviat");
                    }

                } catch (NumberFormatException nfe) {
                    System.out.println("Nùmero de linies no vàlid");
                    menu();
                }
                break;
            case "17":
                StringBuilder lineasDelLlibre = new StringBuilder();

                try (BufferedReader br = new BufferedReader(new FileReader(draculaBook))) {

                    String sCurrentLine;

                    while ((sCurrentLine = br.readLine()) != null) {
                        lineasDelLlibre.append(sCurrentLine);
                        lineasDelLlibre.append(LS);
                    }

                    try {
                        for (int i = 0; i < LS_SIZE; i++) {
                            lineasDelLlibre.deleteCharAt(lineasDelLlibre.length() - 1);
                        }
                    } catch (StringIndexOutOfBoundsException sOB) {
                        lineasDelLlibre.append(NULL);
                    }

                    StringTokenizer msgTokenizer = new StringTokenizer(lineasDelLlibre.toString(), LS);

                    out.println(CHATFILE);
                    out.flush();

                    while (msgTokenizer.hasMoreTokens()) {
                        out.println(msgTokenizer.nextToken(LS));
                        out.flush();
                    }

                    out.println(CHATLINIASFI);
                    out.flush();

                    System.out.println("Llibre enviat");

                } catch (IOException e) {
                    System.out.println("books/dracula.txt ha de existir (pot ser que no sigui aquest error)");
                    menu();
                }
                break;
            default:
                menu();
        }
    }

    private boolean processData(String serverData) {

        if (!serverData.isEmpty()) {

            StringTokenizer st = new StringTokenizer(serverData, SP);
            String tipusMissatge = st.nextToken(SP);

            if (tipusMissatge.equals(CHAT)) {
                System.out.println("Missatge CHAT del SERVER:");

                try {
                    String msg = st.nextToken(SP);
                    System.out.println(msg);
                } catch (NoSuchElementException ns) {
                    System.out.println(NULL);
                }

            } else if (tipusMissatge.equals(CLAUPUBLICA)) {

                BASE64Decoder decoder = new BASE64Decoder();
                try {

                    StringBuilder clauPublica = new StringBuilder();

                    String trosMissatgeTmp;

                    while (((trosMissatgeTmp = in.readLine()) != null)
                            && !trosMissatgeTmp.contains(CLAUPUBLICAFI)) {
                        clauPublica.append(trosMissatgeTmp).append(LS);
                    }

                    for (int i = 0; i < LS_SIZE; i++) {
                        clauPublica.deleteCharAt(clauPublica.length() - 1);
                    }

                    byte[] clavePublica = decoder.decodeBuffer(clauPublica.toString());

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

                    for (int i = 0; i < LS_SIZE; i++) {
                        missatge.deleteCharAt(missatge.length() - 1);
                    }

                    String msgTotal = missatge.toString();

                    StringTokenizer msgTotalTokenizer = new StringTokenizer(msgTotal, SP);

                    String missatgeEncriptat = "";
                    String simetricKeyEncriptada = "";

                    while (msgTotalTokenizer.hasMoreTokens()) {

                        if (msgTotalTokenizer.nextToken(SP).equals(MISSATGEENCRIPTAT)) {
                            missatgeEncriptat = msgTotalTokenizer.nextToken(SP);
                        }

                        if (msgTotalTokenizer.nextToken(SP).equals(CLAUENCRIPTADA)) {
                            simetricKeyEncriptada = msgTotalTokenizer.nextToken(SP);
                        }
                    }

                    BASE64Decoder decoder = new BASE64Decoder();

                    byte[] missatgeEncriptatByte = decoder.decodeBuffer(missatgeEncriptat);
                    byte[] simetricKeyEncriptadaByte = decoder.decodeBuffer(simetricKeyEncriptada);

                    System.out.println("Missatge del SERVER:");
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

                    for (int i = 0; i < LS_SIZE; i++) {
                        missatge.deleteCharAt(missatge.length() - 1);
                    }

                    String msgTotal = missatge.toString();

                    StringTokenizer msgTotalTokenizer = new StringTokenizer(msgTotal, SP);

                    String missatgeEncriptat = "";
                    String simetricKeyEncriptada = "";

                    while (msgTotalTokenizer.hasMoreTokens()) {

                        if (msgTotalTokenizer.nextToken(SP).equals(MISSATGEENCRIPTAT)) {
                            missatgeEncriptat = msgTotalTokenizer.nextToken(SP);
                        }

                        if (msgTotalTokenizer.nextToken(SP).equals(CLAUENCRIPTADA)) {
                            simetricKeyEncriptada = msgTotalTokenizer.nextToken(SP);
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
            } else if (tipusMissatge.equals(CHATLINIAS)) {
                StringBuilder missatge = new StringBuilder();
                String trosMissatgeTmp;

                try {
                    while (((trosMissatgeTmp = in.readLine()) != null)
                            && !trosMissatgeTmp.contains(CHATLINIASFI)) {
                        missatge.append(trosMissatgeTmp).append(LS);
                    }

                    System.out.println("Missatge CHAT (mès linias) del SERVER:");

                    String msgTotal;

                    if (!missatge.toString().isEmpty()) {

                        for (int i = 0; i < LS_SIZE; i++) {
                            missatge.deleteCharAt(missatge.length() - 1);
                        }

                        msgTotal = missatge.toString();
                    } else {
                        msgTotal = NULL;
                    }

                    System.out.println(msgTotal);

                } catch (IOException e) {
                    e.printStackTrace();
                }

            } else if (tipusMissatge.equals(CHATFILE)) {
                StringBuilder missatge = new StringBuilder();
                String trosMissatgeTmp;

                File rebDir = new File(REBUTDIR);

                if (!rebDir.exists()) {
                    rebDir.mkdirs();
                }

                try (BufferedWriter bw = new BufferedWriter(new FileWriter(rebut, false))) {
                    while (((trosMissatgeTmp = in.readLine()) != null)
                            && !trosMissatgeTmp.contains(CHATLINIASFI)) {
                        missatge.append(trosMissatgeTmp).append(LS);
                    }

                    for (int i = 0; i < LS_SIZE; i++) {
                        missatge.deleteCharAt(missatge.length() - 1);
                    }

                    bw.write(missatge.toString());
                    bw.flush();

                    System.out.println("Fitxer rebut");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }

        return !serverData.contains(TANCARCONNEXIO);
    }

    private void close(Socket socket) {
        //Si falla el tancament no podem fer gaire cosa, només enregistrar el problema.
        try {
            //Tancament de tots els recursos.
            if (socket != null && !socket.isClosed()) {
                if (!socket.isInputShutdown()) {
                    socket.shutdownInput();
                }
                if (!socket.isOutputShutdown()) {
                    socket.shutdownOutput();
                }
                socket.close();
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
        Client cliente = new Client();
        cliente.connect("127.0.0.1", 9090);
    }

}
