package client;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.net.hostdb.HostEntry;
import merrimackutil.net.hostdb.HostsDatabase;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;
import merrimackutil.util.Tuple;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
import org.bouncycastle.crypto.generators.SCrypt;

public class KDCClient {
    private static HostsDatabase hosts;
    private static String user;
    private static String service;
    private static SecretKey sessionKey;
    private static final NonceCache nonceCache = new NonceCache(32, 300);

    public static void main(String[] args) {
        LongOption userOption = new LongOption("user", true, 'u');
        LongOption serviceOption = new LongOption("service", true, 's');
        LongOption hostsOption = new LongOption("hosts", true, 'h');
        LongOption helpOption = new LongOption("help", false, '?');

        OptionParser parser = new OptionParser(args);
        LongOption[] options = {userOption, serviceOption, hostsOption, helpOption};
        parser.setLongAndShortOpts(options);

        Tuple<Character, String> result;
        String hostsFile = "hosts.json";

        while ((result = parser.getLongOpt(false)) != null) {
            switch (result.getFirst()) {
                case 'u': user = result.getSecond(); break;
                case 's': service = result.getSecond(); break;
                case 'h': hostsFile = result.getSecond(); break;
                case '?': printUsage(); System.exit(0);
                default: 
                    System.err.println("Unknown option: " + result.getFirst());
                    printUsage(); 
                    System.exit(1);
            }
        }

        if (user == null || service == null) {
            System.err.println("Error: --user and --service are required.");
            printUsage();
            System.exit(1);
        }

        try {
            hosts = new HostsDatabase(new File(hostsFile));
            JSONObject root = JsonIO.readObject(new File(hostsFile));
            JSONArray hostsArray = root.getArray("hosts");
            HostEntry kdcEntry = null;

            for (int i = 0; i < hostsArray.size(); i++) {
                JSONObject hostObj = hostsArray.getObject(i);
                if (!"kdcd".equals(hostObj.getString("host-name"))) continue;

                if (!hostObj.containsKey("port")) {
                    throw new RuntimeException("KDC entry missing 'port'!");
                }
                Integer port = hostObj.getInt("port");
                if (port == null) throw new RuntimeException("KDC port invalid!");

                JSONObject kdcJson = new JSONObject();
                kdcJson.put("host", hostObj.getString("address"));
                kdcJson.put("port", port);
                kdcEntry = new HostEntry(kdcJson);
                break;
            }

            if (kdcEntry == null) {
                throw new RuntimeException("KDC entry (kdcd) not found!");
            }

            char[] password = promptPassword();
            Tuple<Boolean, SecretKey> authResult = chapAuthenticate(kdcEntry, user, password);
            Arrays.fill(password, '\0');

            if (!authResult.getFirst()) {
                System.err.println("Authentication failed!");
                System.exit(1);
            }

            Ticket serviceTicket = requestServiceTicket(
                kdcEntry, 
                user, 
                service, 
                authResult.getSecond()
            );
            communicateWithService(serviceTicket);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static byte[] computeChapResponse(SecretKey key, byte[] nonce) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.doFinal(nonce);
    }

    private static Tuple<Boolean, SecretKey> chapAuthenticate(HostEntry kdcEntry, String user, char[] password) 
        throws Exception {
        try (Socket kdcSocket = new Socket(kdcEntry.getAddress(), kdcEntry.getPort());
             PrintWriter out = new PrintWriter(kdcSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(kdcSocket.getInputStream()))) {

            JSONObject claim = new JSONObject();
            claim.put("type", "chap_claim");
            claim.put("username", user);
            out.println(claim.toJSON());

            JSONObject challenge = JsonIO.readObject(in.readLine());
            if (!"chap_challenge".equals(challenge.getString("type"))) {
                return new Tuple<>(false, null);
            }

            byte[] nonce = hexToBytes(challenge.getString("nonce"));
            SecretKey userKey = deriveKey(new String(password), user, 256);
            byte[] response = computeChapResponse(userKey, nonce);

            JSONObject resp = new JSONObject();
            resp.put("type", "chap_response");
            resp.put("hash", bytesToHex(response));
            out.println(resp.toJSON());

            JSONObject result = JsonIO.readObject(in.readLine());
            return new Tuple<>(
                "chap_success".equals(result.getString("status")),
                userKey
            );
        }
    }

    private static Ticket requestServiceTicket(HostEntry kdcEntry, String user, String service, SecretKey userKey) throws Exception {
        try (Socket kdcSocket = new Socket(kdcEntry.getAddress(), kdcEntry.getPort());
             PrintWriter out = new PrintWriter(kdcSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(kdcSocket.getInputStream()))) {

            JSONObject request = new JSONObject();
            request.put("type", "ticket_request");
            request.put("service", service);
            request.put("user", user);
            out.println(request.toJSON());

            JSONObject response = JsonIO.readObject(in.readLine());
            if (!"ticket_response".equals(response.getString("type"))) {
                throw new SecurityException("Invalid ticket response");
            }

            byte[] encryptedKey = hexToBytes(response.getString("session_key"));
            byte[] iv = hexToBytes(response.getString("iv"));
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, userKey, new GCMParameterSpec(128, iv));
            byte[] decryptedKey = cipher.doFinal(encryptedKey);
            
            return new Ticket(
                hexToBytes(response.getString("ticket")),
                new SecretKeySpec(decryptedKey, "AES")
            );
        }
    }

    private static void communicateWithService(Ticket ticket) throws Exception {
        if (hosts.hostKnown(service)) {
            String serviceAddress = hosts.getAddress(service);
            int servicePort = hosts.getPort(service);

            JSONObject serviceJson = new JSONObject();
            serviceJson.put("host-name", service);
            serviceJson.put("address", serviceAddress);
            serviceJson.put("port", servicePort);

            HostEntry serviceEntry = new HostEntry(serviceJson);

            try (Socket serviceSocket = new Socket(serviceEntry.getAddress(), serviceEntry.getPort());
                 PrintWriter out = new PrintWriter(serviceSocket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(serviceSocket.getInputStream()))) {

                performServiceHandshake(ticket, out, in);

                @SuppressWarnings("resource")
                Scanner userInput = new Scanner(System.in);
                while (true) {
                    System.out.print("Message to send: ");
                    String message = userInput.nextLine();

                    JSONObject encryptedMsg = encryptMessage(message);
                    out.println(encryptedMsg.toJSON());
                    out.flush();

                    JSONObject response = JsonIO.readObject(in.readLine());
                    String decrypted = decryptMessage(response);
                    System.out.println("Response: " + decrypted);
                }
            }
        } else {
            System.out.println("Service '" + service + "' not found in the database.");
        }
    }

    private static void performServiceHandshake(Ticket ticket, PrintWriter out, BufferedReader in) throws Exception {
        JSONObject hello = new JSONObject();
        hello.put("type", "client_hello");
        hello.put("nonce", bytesToHex(generateNonce()));
        hello.put("ticket", bytesToHex(ticket.getEncryptedData()));
        out.println(hello.toJSON());
        out.flush();

        JSONObject serviceResp = JsonIO.readObject(in.readLine());
        if (!"handshake_response".equals(serviceResp.getString("type"))) {
            throw new SecurityException("Invalid handshake response");
        }
        
        verifyServiceResponse(serviceResp, ticket.getSessionKey());
    }

    private static void verifyServiceResponse(JSONObject response, SecretKey sessionKey) throws Exception {
        byte[] receivedNonce = hexToBytes(response.getString("encrypted_nonce"));
        byte[] iv = hexToBytes(response.getString("iv"));
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        byte[] decryptedNonce = cipher.doFinal(receivedNonce);
        
        if (nonceCache.containsNonce(decryptedNonce)) {
            throw new SecurityException("Invalid nonce in handshake");
        }
        nonceCache.addNonce(decryptedNonce);
    }

    private static JSONObject encryptMessage(String message) throws Exception {
        JSONObject msg = new JSONObject();
        byte[] nonce = generateNonce();
        byte[] iv = generateIV();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        msg.put("type", "service_message");
        msg.put("nonce", bytesToHex(nonce));
        msg.put("iv", bytesToHex(iv));
        msg.put("ciphertext", bytesToHex(ciphertext));
        
        return msg;
    }

    private static String decryptMessage(JSONObject response) throws Exception {
        byte[] iv = hexToBytes(response.getString("iv"));
        byte[] ciphertext = hexToBytes(response.getString("ciphertext"));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    private static SecretKey deriveKey(String secret, String salt, int keySize) throws Exception {
        byte[] keyBytes = SCrypt.generate(
            secret.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            16384, 8, 1, keySize/8
        );
        return new SecretKeySpec(keyBytes, "AES");
    }

    @SuppressWarnings("resource")
    private static char[] promptPassword() {
        Console console = System.console();
        if (console == null) {
            System.out.print("Password: ");
            return new Scanner(System.in).nextLine().toCharArray();
        }
        return console.readPassword("Password: ");
    }

    private static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        return iv;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            bytes[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
        }
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static void printUsage() {
        System.out.println("usage:");
        System.out.println("client --hosts <hostfile> --user <user> --service <service>");
        System.out.println("client --user <user> --service <service>");
        System.out.println("options:");
        System.out.println("-h, --hosts Set the hosts file.");
        System.out.println("-u, --user The user name.");
        System.out.println("-s, --service The name of the service.");
        System.out.println("--help Display this help message.");
    }

    private static class Ticket {
        private final byte[] encryptedData;
        private final SecretKey sessionKey;
        
        public Ticket(byte[] encryptedData, SecretKey sessionKey) {
            this.encryptedData = encryptedData;
            this.sessionKey = sessionKey;
        }
        
        public byte[] getEncryptedData() {
            return encryptedData; 
        }
        public SecretKey getSessionKey() {
            return sessionKey; 
        }
    }
}