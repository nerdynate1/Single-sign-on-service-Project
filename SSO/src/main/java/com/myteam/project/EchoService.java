package com.myteam.project;
import java.net.Socket;
import java.net.ServerSocket;
//import java.util.Scanner;
//import java.io.PrintWriter;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;



public class EchoService {

  public static void main(String[] args)
  {
    // A pool with 10 threads.
    ExecutorService pool = Executors.newFixedThreadPool(10);
    NonceCache nonceCache = new NonceCache(32, 300);


    try
    {
      //Read Config file
      File configFile = new File ("config.json");
      JSONObject config = JsonIO.readObject(configFile);

      String serviceName = config.getString ("service-name");
      String serviceSecret = config.getString("service-secret");
      int port = config.getInt("port");

      try (ServerSocket server = new ServerSocket(port)) {
        System.out.println("EchoService [" + serviceName + "] listening on port" + port);

        // Loop forever handing connections.
        while (true)
        {
          // Wait for a connection.
          Socket sock = server.accept();

          System.out.println("Connection received from" + sock.getInetAddress());

          pool.execute(new ConnectionHandler(sock, serviceName, serviceSecret, nonceCache));
        }
      }
    }
    catch(IOException ioe)
    {
      ioe.printStackTrace();
    }
  }

}



