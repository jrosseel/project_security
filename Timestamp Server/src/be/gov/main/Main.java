package be.gov.main;

import java.io.IOException;
import java.io.PrintWriter;
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

import be.security.shared.encryption.ByteSerializer;

public class Main {

	public static void main(String[] args) 
			throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException 
	{
		ServerSocketFactory fac = ServerSocketFactory.getDefault();
		ServerSocket serverSocket = fac.createServerSocket(8080);
		while(true) {
			Socket clientSocket = serverSocket.accept();
			
			byte[] response = ByteSerializer.EncodeObject(Revalidation.revalidate());
			clientSocket.getOutputStream().write(response);
		}
	}
	
}
