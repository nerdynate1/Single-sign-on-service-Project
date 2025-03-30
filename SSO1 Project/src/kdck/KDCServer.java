package kdck;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;
import merrimackutil.util.Tuple;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;

public class KDCServer {
    private static HashMap<String, String> secrets;
    private static int port;
    private static long validityPeriod;
    private static NonceCache nonceCache;

    public static void main(String[] args) {
        LongOption configOption = new LongOption("config", true, 'c');
        LongOption helpOption = new LongOption("help", false, '?');

        OptionParser parser = new OptionParser(args);
        LongOption[] options = {configOption, helpOption};
        parser.setLongAndShortOpts(options);

        Tuple<Character, String> result;
        String configFile = "config.json";

        while ((result = parser.getLongOpt(false)) != null) {
            switch (result.getFirst()) {
                case 'c': configFile = result.getSecond(); break;
                case '?': printUsage(); System.exit(0);
                default: 
                    System.err.println("Unknown option: " + result.getFirst());
                    printUsage();
                    System.exit(1);
            }
        }

        try {
            JSONObject config = JsonIO.readObject(new File(configFile));
            port = config.getInt("port");
            validityPeriod = Long.parseLong(config.getString("validity-period"));
            secrets = loadSecrets(config.getString("secrets-file"));
            nonceCache = new NonceCache(32, 300);

            ExecutorService pool = Executors.newFixedThreadPool(10);
            try (ServerSocket server = new ServerSocket(port)) {
                System.out.println("KDC Server running on port " + port);
                while (true) {
                    Socket client = server.accept();
                    pool.submit(new ClientHandler(client, secrets, validityPeriod, nonceCache));
                }
            }
        } catch (Exception e) {
            System.err.println("Server startup failed:");
            e.printStackTrace();
        }
    }

    private static HashMap<String, String> loadSecrets(String secretsFile) throws Exception {
        HashMap<String, String> secrets = new HashMap<>();
        JSONObject secretsJson = JsonIO.readObject(new File(secretsFile));
        JSONArray secretsArray = secretsJson.getArray("secrets");

        for (int i = 0; i < secretsArray.size(); i++) {
            JSONObject secretEntry = secretsArray.getObject(i);
            secrets.put(secretEntry.getString("user"), secretEntry.getString("secret"));
        }

        return secrets;
    }

    private static void printUsage() {
        System.out.println("usage:");
        System.out.println("kdcd --config <configfile>");
        System.out.println("kdcd --help");
        System.out.println("options:");
        System.out.println("-c, --config Set the config file.");
        System.out.println("--help Display this help message.");
    }

    private static class ClientHandler implements Runnable {
        private final Socket client;
        private final HashMap<String, String> secrets;
        private final long validityPeriod;
        private final NonceCache nonceCache;
    
        public ClientHandler(Socket client, HashMap<String, String> secrets, long validityPeriod, NonceCache nonceCache) {
            this.client = client;
            this.secrets = secrets;
            this.validityPeriod = validityPeriod;
            this.nonceCache = nonceCache;
        }
    
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                 PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {
                JSONObject claim = JsonIO.readObject(in.readLine());
                if (!"chap_claim".equals(claim.getString("type"))) {
                    sendError(out, "Invalid message type");
                    return;
                }
    
                String user = claim.getString("username");
                String secret = secrets.get(user);
                if (secret == null) {
                    sendError(out, "User not found");
                    return;
                }
    
                byte[] nonce = generateNonce();
                this.nonceCache.addNonce(nonce); 
                JSONObject challenge = new JSONObject();
                challenge.put("type", "chap_challenge");
                challenge.put("nonce", bytesToHex(nonce));
                out.println(challenge.toJSON());
    
                JSONObject response = JsonIO.readObject(in.readLine());
                if (!"chap_response".equals(response.getString("type"))) {
                    sendError(out, "Invalid response type");
                    return;
                }
    
                SecretKey userKey = deriveKey(secret, user, 256);
                byte[] expectedHash = computeChapResponse(userKey, nonce);
                byte[] actualHash = hexToBytes(response.getString("hash"));
                
                if (!Arrays.equals(expectedHash, actualHash)) {
                    sendError(out, "Authentication failed");
                    return;
                }
    
                JSONObject success = new JSONObject();
                success.put("type", "chap_success");
                out.println(success.toJSON());
    
                JSONObject ticketRequest = JsonIO.readObject(in.readLine());
                if (!"ticket_request".equals(ticketRequest.getString("type"))) {
                    sendError(out, "Invalid ticket request");
                    return;
                }
    
                String service = ticketRequest.getString("service");
                String serviceSecret = secrets.get(service);
                if (serviceSecret == null) {
                    sendError(out, "Unknown service");
                    return;
                }
    

                SecretKey sessionKey = generateSessionKey();
                
                JSONObject encryptedTicket = buildTicket(user, service, sessionKey, serviceSecret);
                
                byte[] clientIV = generateIV();
                byte[] encryptedSessionKey = encrypt(
                    sessionKey.getEncoded(), 
                    userKey, 
                    clientIV
                );
    
                JSONObject ticketResponse = new JSONObject();
                ticketResponse.put("type", "ticket_response");
                ticketResponse.put("session_key", bytesToHex(encryptedSessionKey));
                ticketResponse.put("client_iv", bytesToHex(clientIV));
                ticketResponse.put("ticket", encryptedTicket.toJSON());
                out.println(ticketResponse.toJSON());
    
            } catch (Exception e) {
                System.err.println("Client handling error:");
                e.printStackTrace();
            } finally {
                try { client.close(); } catch (IOException e) { /* Ignored */ }
            }
        }
    
        private JSONObject buildTicket(String user, String service, SecretKey sessionKey, String serviceSecret) 
            throws Exception {
            JSONObject ticket = new JSONObject();
            ticket.put("user", user);
            ticket.put("service", service);
            ticket.put("created", System.currentTimeMillis());
            ticket.put("validity", validityPeriod);
            ticket.put("session_key", bytesToHex(sessionKey.getEncoded()));
    
            SecretKey serviceKey = deriveKey(serviceSecret, service, 256);
            byte[] serviceIV = generateIV();
            byte[] encryptedData = encrypt(
                ticket.toJSON().getBytes(StandardCharsets.UTF_8),
                serviceKey,
                serviceIV
            );
    
            JSONObject encryptedTicket = new JSONObject();
            encryptedTicket.put("iv", bytesToHex(serviceIV));
            encryptedTicket.put("data", bytesToHex(encryptedData));
            return encryptedTicket;
        }
    
        private SecretKey generateSessionKey() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        }
    
        private byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return cipher.doFinal(data);
        }
    
        private byte[] generateNonce() {
            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[32];
            random.nextBytes(nonce);
            return nonce;
        }
    
        private byte[] generateIV() {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            return iv;
        }
    
        private void sendError(PrintWriter out, String message) {
            JSONObject error = new JSONObject();
            error.put("type", "error");
            error.put("message", message);
            out.println(error.toJSON());
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
            16384, 8, 1, keySize/8
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
}