package kdcd;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.net.hostdb.HostEntry;
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
                    pool.submit(new ClientHandler(client));
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
    private static boolean chapAuthenticate(Socket client, String user) throws Exception {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {
        byte[] nonce = generateNonce();
        JSONObject challenge = new JSONObject();
        challenge.put("type", "chap_challenge");
        challenge.put("nonce", bytesToHex(nonce));
        out.println(challenge.toJSON());
    
        JSONObject response = JsonIO.readObject(in.readLine());
        if (!"chap_response".equals(response.getString("type"))) {
                return false;
        }
    
            String secret = secrets.get(user);
            if (secret == null) return false;
    
            SecretKey userKey = deriveKey(secret, user, 256);
            byte[] expectedResponse = computeChapResponse(userKey, nonce);
            byte[] actualResponse = hexToBytes(response.getString("hash"));
    
            return Arrays.equals(expectedResponse, actualResponse);
        }
    }

    private static class ClientHandler implements Runnable {
        private final Socket client;

        public ClientHandler(Socket client) {
            this.client = client;
        }
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                 PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {
        
                JSONObject claim = JsonIO.readObject(in.readLine());
                String user = claim.getString("username");
                if (chapAuthenticate(client, user)) {
                    System.out.println("User " + user + " authenticated successfully.");
                } else {
                    System.err.println("Authentication failed for user: " + user);
                }
            } catch (Exception e) {
                System.err.println("Client handling error:");
                e.printStackTrace();
            } finally {
                try { client.close(); } catch (IOException e) { /* Ignore */ }
            }
        }


        private static SecretKey generateSessionKey() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        }

        private static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return cipher.doFinal(data);
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

    private static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        return nonce;
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
    private static JSONObject generateTicket(String user, String service, SecretKey sessionKey, SecretKey, serviceKey)throws Exception{
        JSONObject ticketData = new JSONObject();
        ticketData.put("client", user);
        ticketData.put("service", service);
        ticketData.put("created", System.currentTimeMillis());
        ticketData.put("valid", validityPeriod);

        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, serviceKey, new GCMParameterSpec(128, iv));
    }
}
