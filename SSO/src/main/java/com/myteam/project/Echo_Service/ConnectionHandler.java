package com.myteam.project.Echo_Service;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
//import java.util.Scanner;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JsonIO;
import merrimackutil.util.NonceCache;

public class ConnectionHandler implements Runnable
{
    private Socket sock;
    private String serviceSecret;
    private String serviceName;
    private NonceCache nonceCache;

    /**
     * Creates a new conneciton handler 
     * @param sock the socket associated with the connection.
     */
    public ConnectionHandler(Socket sock, String serviceName, String serviceSecret, NonceCache nonceCache)
    {
        this.sock = sock;
        this.serviceSecret = serviceSecret;
        this.serviceName = serviceName;
        this.nonceCache = nonceCache;
    }

    /**
     * How to handle the connection
     */
    public void run(){
        try
        {
            // Setup the streams for use.
            //Scanner recv = new Scanner(sock.getInputStream());
            //PrintWriter send = new PrintWriter(sock.getOutputStream(), true);
            InputStream inputStream = sock.getInputStream();
            OutputStream outputStream = sock.getOutputStream();

            BufferedReader reader = new BufferedReader( new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            StringBuilder requestBuilder = new StringBuilder();
            String line;
            while((line=reader.readLine())!= null){
                requestBuilder.append(line);
            }

            String requestBody = requestBuilder.toString();
            JSONObject handshakeRequest = JsonIO.readObject (requestBody);
            
            if(!isValidTicket(handshakeRequest)){
                sendErrorResponse(outputStream, "Invalid ticket.");
                sock.close();
                return;
            }
        

            String receivedNonce = handshakeRequest.getString("nonce");
            byte[] nonceBytes = receivedNonce.getBytes();
            if (nonceCache.containsNonce(nonceBytes)){
                System.out.println("Replay detected. Closing Connection.");
                sock.close();
                return;
            }
            nonceCache.addNonce(nonceBytes);

            JSONObject encrptedPayload = handshakeRequest.getObject("payload");
            String cipherText = encrptedPayload.getString("cipherText");
            String key = encrptedPayload.getString("key");
            String iv = encrptedPayload.getString("iv");

            GCMDecrypt decryptor = new GCMDecrypt();
            String decryptedMessage = decryptor.decrypt(cipherText, key, iv);

            String upperCaseM = decryptedMessage.toUpperCase();

            GCMEncrypt encryptor = new GCMEncrypt();
            EncryptResult ecryptedReply = encryptor.encrypt(upperCaseM);

            JSONObject reply = new JSONObject();
            reply.put ("payload", ecryptedReply);

            PrintWriter writer = new PrintWriter(outputStream, true);
            writer.println((reply.toString()));

            // Close the connection.
            sock.close();
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
        }    catch (Exception ex)
        {
            ex.printStackTrace();
        }    
    }

    private boolean isValidTicket (JSONObject handshakeRequest){
        String ticketServiceName = handshakeRequest.getString("serviceName");


        Object ticketTimeStampObj = handshakeRequest.get("timestamp");
        long ticketTimeStamp = 0;

        if(ticketTimeStampObj instanceof Long){
            ticketTimeStamp = (Long) ticketTimeStampObj;
        } else if (ticketTimeStampObj instanceof Integer){
            ticketTimeStamp = ((Integer) ticketTimeStampObj).longValue();
        }

        
        long currentTimeStamp = System.currentTimeMillis();

        if(!ticketServiceName.equals(serviceName)){
            return false;
        }

//5 minute 
        if (currentTimeStamp - ticketTimeStamp > 5 * 60 * 1000){
            return false;
        }
        return true;
    }

    private void sendErrorResponse(OutputStream outputStream, String errorMessage) throws IOException{
        JSONObject errorResponse = new JSONObject();
        errorResponse.put("error", errorMessage);
        PrintWriter writer = new PrintWriter(outputStream, true);
        writer.println(errorResponse.toString());

    }
}