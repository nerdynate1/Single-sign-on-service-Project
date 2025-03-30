package client;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.net.hostdb.HostsDatabase;
import merrimackutil.json.JsonIO;
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
            System.out.println("[DEBUG] Loading hosts database...");
            hosts = new HostsDatabase(new File(hostsFile));

            System.out.println("[DEBUG] Getting KDC details...");
            if (!hosts.hostKnown("kdcd")) {
                throw new RuntimeException("KDC host 'kdcd' not found!");
            }
            String kdcAddress = hosts.getAddress("kdcd");
            int kdcPort = hosts.getPort("kdcd");

            System.out.println("[DEBUG] Getting service details...");
            if (!hosts.hostKnown(service)) {
                throw new RuntimeException("Service '" + service + "' not found!");
            }
            String serviceAddress = hosts.getAddress(service);
            int servicePort = hosts.getPort(service);

            char[] password = promptPassword();
            
            Tuple<Boolean, Ticket> authResult = performKDCSession(
                kdcAddress, 
                kdcPort, 
                user, 
                password, 
                service
            );
            Arrays.fill(password, '\0');

            if (!authResult.getFirst()) {
                System.err.println("Authentication failed!");
                System.exit(1);
            }

            System.out.println("[DEBUG] Starting service communication...");
            communicateWithService(authResult.getSecond(), serviceAddress, servicePort);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static Tuple<Boolean, Ticket> performKDCSession(
        String kdcAddress, int kdcPort, String user, char[] password, String service
    ) throws Exception {
        try (Socket kdcSocket = new Socket(kdcAddress, kdcPort);
             PrintWriter out = new PrintWriter(kdcSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(kdcSocket.getInputStream()))) {

             JSONObject claim = new JSONObject();
             claim.put("type", "chap_claim");
             claim.put("username", user);
             out.println(claim.toJSON());
             System.out.println("[DEBUG] Sent CHAP claim: " + claim.toJSON());

             JSONObject challenge = JsonIO.readObject(in.readLine());
             System.out.println("[DEBUG] Received challenge: " + challenge.toJSON());
                if (!"chap_challenge".equals(challenge.getString("type"))) {
                 System.err.println("[ERROR] Invalid challenge type");
                 return new Tuple<>(false, null);
                }
            

             byte[] nonce = hexToBytes(challenge.getString("nonce"));
             System.out.println("[DEBUG] Challenge nonce: " + bytesToHex(nonce));

             SecretKey userKey = deriveKey(new String(password), user, 256);
             System.out.println("[DEBUG] Derived user key: " + bytesToHex(userKey.getEncoded()));

             byte[] responseHash = computeChapResponse(userKey, nonce);
             System.out.println("[DEBUG] Computed response hash: " + bytesToHex(responseHash));

             JSONObject resp = new JSONObject();
             resp.put("type", "chap_response");
             resp.put("hash", bytesToHex(responseHash));
             out.println(resp.toJSON());
             System.out.println("[DEBUG] Sent CHAP response: " + resp.toJSON());

            JSONObject result = JsonIO.readObject(in.readLine());
            System.out.println("[DEBUG] Received auth result: " + result.toJSON());
            if (!"chap_success".equals(result.getString("type"))) {
                System.err.println("[ERROR] Authentication failed");
                return new Tuple<>(false, null);
            }

            JSONObject ticketRequest = new JSONObject();
            ticketRequest.put("type", "ticket_request");
            ticketRequest.put("service", service);
            ticketRequest.put("user", user);
            out.println(ticketRequest.toJSON());
            System.out.println("[DEBUG] Sent ticket request: " + ticketRequest.toJSON());

            JSONObject ticketResponse = JsonIO.readObject(in.readLine());
            System.out.println("[DEBUG] Received ticket response: " + ticketResponse.toJSON());
            if (!"ticket_response".equals(ticketResponse.getString("type"))) {
                throw new SecurityException("Invalid ticket response");
            }

            byte[] encryptedKey = hexToBytes(ticketResponse.getString("session_key"));
            byte[] iv = hexToBytes(ticketResponse.getString("client_iv"));
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, userKey, new GCMParameterSpec(128, iv));
            byte[] decryptedKey = cipher.doFinal(encryptedKey);
            sessionKey = new SecretKeySpec(decryptedKey, "AES");

            System.out.println("[DEBUG] Decrypted session key: " + bytesToHex(sessionKey.getEncoded()));

            return new Tuple<>(
                true,
                new Ticket(
                    hexToBytes(ticketResponse.getString("ticket")),
                    sessionKey
                )
            );
        }
    }

    private static void communicateWithService(Ticket ticket, String serviceAddress, int servicePort) {
        try (Socket serviceSocket = new Socket(serviceAddress, servicePort);
             PrintWriter out = new PrintWriter(serviceSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(serviceSocket.getInputStream()))) {

            JSONObject hello = new JSONObject();
            hello.put("type", "client_hello");
            byte[] clientNonce = generateNonce();
            hello.put("nonce", bytesToHex(clientNonce));
            hello.put("ticket", bytesToHex(ticket.getEncryptedData()));
            out.println(hello.toJSON());
            System.out.println("[DEBUG] Sent client hello: " + hello.toJSON());

            JSONObject handshakeResponse = JsonIO.readObject(in.readLine());
            System.out.println("[DEBUG] Received handshake response: " + handshakeResponse.toJSON());
            if (!"handshake_response".equals(handshakeResponse.getString("type"))) {
                throw new SecurityException("Invalid handshake response");
            }

            byte[] encryptedNonce = hexToBytes(handshakeResponse.getString("encrypted_nonce"));
            byte[] iv = hexToBytes(handshakeResponse.getString("iv"));
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
            byte[] decryptedNonce = cipher.doFinal(encryptedNonce);
            
            if (nonceCache.containsNonce(decryptedNonce)) {
                throw new SecurityException("Replay attack detected!");
            }
            nonceCache.addNonce(decryptedNonce);

            try (Scanner scanner = new Scanner(System.in)) {
                while (true) {
                    System.out.print("Enter message (or 'exit' to quit): ");
                    String message = scanner.nextLine();
                    
                    if ("exit".equalsIgnoreCase(message)) break;

                    JSONObject encryptedMsg = encryptMessage(message);
                    out.println(encryptedMsg.toJSON());
                    System.out.println("[DEBUG] Sent encrypted message: " + encryptedMsg.toJSON());
                    
                    JSONObject response = JsonIO.readObject(in.readLine());
                    System.out.println("[DEBUG] Received response: " + response.toJSON());
                    System.out.println("Received: " + decryptMessage(response));
                }
            }
        } catch (Exception e) {
            System.err.println("Service communication error:");
            e.printStackTrace();
        }
    }

    private static byte[] computeChapResponse(SecretKey key, byte[] nonce) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.doFinal(nonce);
    }

    private static SecretKey deriveKey(String secret, String salt, int keySize) throws Exception {
        byte[] keyBytes = SCrypt.generate(
            secret.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            16384,  
            8,      
            1,      
            keySize/8
        );
        return new SecretKeySpec(keyBytes, "AES");
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

    private static byte[] generateNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static JSONObject encryptMessage(String message) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(message.getBytes());

        JSONObject msg = new JSONObject();
        msg.put("type", "service_message");
        msg.put("iv", bytesToHex(iv));
        msg.put("ciphertext", bytesToHex(ciphertext));
        return msg;
    }

    private static String decryptMessage(JSONObject response) throws Exception {
        byte[] iv = hexToBytes(response.getString("iv"));
        byte[] ciphertext = hexToBytes(response.getString("ciphertext"));
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(ciphertext));
    }

    private static char[] promptPassword() {
        Console console = System.console();
        if (console == null) {
            System.out.print("Password: ");
            return new Scanner(System.in).nextLine().toCharArray();
        }
        return console.readPassword("Password: ");
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
        
        public byte[] getEncryptedData() { return encryptedData; }
        public SecretKey getSessionKey() { return sessionKey; }
    }
}