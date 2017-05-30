package be.service;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ServerSocketFactory;

import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;

public class Service {
	
	public static void main(String[] args) 
			throws IOException, ClassNotFoundException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException
	{
		// For sake of simplification, we have one server with multiple SPs.
		//	In real life scenario, every SP would have its own server
		System.out.println("Starting service provider server..");
		ServerSocketFactory fac = ServerSocketFactory.getDefault();
		ServerSocket serverSocket = fac.createServerSocket(GlobalConsts.SP_PORT);
		
		System.out.println("SP server online. Listening for incoming connections at port " + GlobalConsts.SP_PORT);
		while(true) {
			Socket clientSocket = serverSocket.accept();
			SocketTransmitter connection = new SocketTransmitter(clientSocket);
			
			System.out.println("Client connection established. Waiting for SP request.");
			
			// First get the correct service provider
			Integer spChoice = connection.ReceiveObject();
			
			ServiceProvider app = ServiceProviderFactory.makeSP(connection, spChoice);
			app.run();
		}
	}
	
}
