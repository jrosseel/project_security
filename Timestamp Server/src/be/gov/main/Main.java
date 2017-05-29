package be.gov.main;

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

import be.security.shared.data.SignedData;
import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;

public class Main {

	public static void main(String[] args) 
			throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException 
	{
		System.out.println("Starting government server..");
		ServerSocketFactory fac = ServerSocketFactory.getDefault();
		ServerSocket serverSocket = fac.createServerSocket(GlobalConsts.GOVERNMENT_PORT);
		
		System.out.println("Government server online. Listening for incoming connections at port " + GlobalConsts.GOVERNMENT_PORT);
		while(true) {
			Socket clientSocket = serverSocket.accept();
			SocketTransmitter transmitter = new SocketTransmitter(clientSocket);
			
			SignedData<Long> currentTime = Revalidation.revalidate();
			System.out.println("Client connection established. Sending updated government time to client. Timestamp: " + currentTime.data);
			
			// Send back the current time
			transmitter.Send(currentTime);
		}
	}
	
}
