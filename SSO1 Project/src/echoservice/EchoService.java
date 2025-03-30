package echoservice;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;
import org.bouncycastle.crypto.generators.SCrypt;

public class EchoService {
    private static NonceCache nonceCache;
    private static SecretKey serviceKey;

    public static void main(String[] args) {
        try {
            JSONObject config = JsonIO.readObject(new File("config1.json"));
            String serviceName = config.getString("service-name");
            String serviceSecret = config.getString("service-secret");
            int port = config.getInt("port");

            nonceCache = new NonceCache(32, 300_000);

            serviceKey = deriveKey(serviceSecret, serviceName, 256);

            ExecutorService pool = Executors.newFixedThreadPool(10);
            try (ServerSocket server = new ServerSocket(port)) {
                System.out.println("[+] Echo Service '" + serviceName + "' running on port " + port);
                while (true) {
                    Socket client = server.accept();
                    pool.execute(() -> handleClient(client));
                }
            }
        } catch (Exception e) {
            System.err.println("Echo Service failed to start:");
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket client) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
             PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {

            JSONObject request = JsonIO.readObject(in.readLine());

            String nonce = request.getString("nonce");
            if (nonceCache.containsNonce(nonce.getBytes())) {
                System.out.println("[!] Replay attack detected from " + client.getInetAddress());
                return;
            }
            nonceCache.addNonce(nonce.getBytes());

            String encryptedPayload = request.getString("payload");
            String decryptedMessage = decrypt(encryptedPayload, serviceKey);

            String responseMessage = decryptedMessage.toUpperCase();

            String encryptedResponse = encrypt(responseMessage, serviceKey);

            JSONObject response = new JSONObject();
            response.put("payload", encryptedResponse);
            out.println(response.toJSON());

        } catch (Exception e) {
            System.err.println("Error handling client:");
            e.printStackTrace();
        } finally {
            try { client.close(); } catch (IOException e) { /* Ignored */ }
        }
    }

    private static SecretKey deriveKey(String secret, String salt, int keySize) throws Exception {
        byte[] keyBytes = SCrypt.generate(
            secret.getBytes("UTF-8"),
            salt.getBytes("UTF-8"),
            16384, 8, 1, keySize / 8
        );
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
    }

    private static String decrypt(String encryptedData, SecretKey key) throws Exception {
        String[] parts = encryptedData.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(ciphertext), "UTF-8");
    }
}