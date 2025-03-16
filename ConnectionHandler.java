import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import merrimackutil.json.types.JSONObject;
import merrimackutil.json.JsonIO;
import merrimackutil.nonce.NonceCache;

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
    public ConnectionHandler(Socket sock)
    {
        this.sock = sock;
        this.serviceSecret = serviceSecret;
        this.serviceName = serviceName;
        this.nonceCache = nonceCache;
    }

    /**
     * How to handle the connection
     */
    public void run() 
    {
        try
        {
            // Setup the streams for use.
            //Scanner recv = new Scanner(sock.getInputStream());
            //PrintWriter send = new PrintWriter(sock.getOutputStream(), true);
            InputStream inputStream = sock.getInputStream();
            OutputStream outputStream = sock.getOutputStream();

            JSONObject handshakeRequest = JsonIO.readObject (inputStream);

            String receivedNonce = handshakeRequest.getString("nonce");
            if (nonceCache.exists(recievedNonce)){
                System.out.println("Replay detected. Closing Connection.");
                sock.close();
                return;
            }
            nonceCache.add(recievedNonce);

            JSONObject encrptedPayload = handshakeRequest.getObject("payload");
            String decryptedMessage = GCMDecrypt.decrypt(encrptedPayload, serviceSecret);

            String upperCaseM = decryptedMessage.toUpperCase();

            JSONObject ecryptedReply = GCMEncrypt.encrypt(upperCaseM, serviceSecret);

            JSONObject reply = new JSONObject();
            reply.put ("payload", ecryptedReply);

            // Close the connection.
            sock.close();
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
        }    
    }
}