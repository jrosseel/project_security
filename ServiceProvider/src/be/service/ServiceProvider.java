package be.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import be.security.shared.data.CardAuthenticationMedium;
import be.security.shared.data.Certificate;
import be.security.shared.data.KeyNegotiation;
import be.security.shared.data.KeyNegotiationChallenge;
import be.security.shared.data.KeyNegotiationResponse;
import be.security.shared.data.QueryMedium;
import be.security.shared.data.SignedData;
import be.security.shared.encryption.ByteSerializer;
import be.security.shared.encryption.Cryptography;
import be.security.shared.keystore.KeyReader;
import be.service.certify.X509CertificateSimplifier;
import be.service.config.Config;
import be.service.config.ServerException;
import be.service.logic.CardAuthenticator;
import be.service.logic.QueryResultReader;
import be.service.logic.Queryer;
import global.connection.sockets.SocketTransmitter;

public class ServiceProvider {
	
	private SocketTransmitter _connection;
	private int 			  _spId;
	private String 			  _name;
	private byte 			  _domainId;
	private KeyReader 		  _keyReader;
	
	private SecretKey _symmetricKey;
	private Certificate _myCert;
	
	public ServiceProvider(SocketTransmitter connection, int spId, String name, byte domainId) {
		_connection = connection;
		_spId = spId;
		_name = name;
		_domainId = domainId;
		_keyReader = new KeyReader(name, Config.KEYSTORE_PASSWD);
	}

	public void run()
					throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeySpecException 
	{	
		// First authenticate yourself to the caller
		SignedData<Certificate> signedCert = _getIdentification();
		_myCert = signedCert.data;
		
		System.out.println("Authenticating to client. Sending identification certificate.");
		_connection.Send(signedCert);
		
		System.out.println("Waiting for client response.");
		
		KeyNegotiation keyNeg = _connection.ReceiveObject();
		System.out.println("Received client key negotiation request.");
		
		try {
			KeyNegotiationResponse keyNegResp = _handleKeynegotiation(keyNeg);
			System.out.println("Sending key negotiation response.");
			_connection.Send(keyNegResp);
			
			System.out.println("Sending card authentication request.");
			CardAuthenticator authenticator = new CardAuthenticator(_symmetricKey);
			_connection.Send(authenticator.getAuthenticationRequest());
			
			System.out.println("Card authentication request sent. Waiting for response.");
			CardAuthenticationMedium cardAuthResponse = _connection.ReceiveObject();
			System.out.println("Received card authentication response.");
			
			//if(! authenticator.verifyChallenge(cardAuthResponse.data))
			//	throw new ServerException("Card authentication failed. Invalid challenge response.");
			
			System.out.println("Card authenticated. Asking query.");

			QueryMedium queryAsk = new QueryMedium();
			queryAsk.data = new Queryer(_spId).makeQuery();
			_connection.Send(queryAsk);
			
			System.out.println("Query answer received. Printing data");
			QueryMedium queryResp = _connection.ReceiveObject();
			
			QueryResultReader qParser = new QueryResultReader(queryResp.data);
			_printAttributeData(qParser.read());
			
			System.out.println("Service provider job is done. Waiting for the next request.");
		} 
		catch (ServerException e) 
		{	
			System.out.println("Server exception occured. Aborting connection. ");
			e.printStackTrace();	
		}
		finally {
			_connection.close();
		}
		
	}
	
	private KeyNegotiationResponse _handleKeynegotiation(KeyNegotiation keyNeg) 
					throws ServerException, InvalidKeyException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, IOException, InvalidAlgorithmParameterException 
	{
		System.out.println("Handling key negotiation. Decrypting symmetric key");
		PrivateKey key = _keyReader.readPrivate(Config.SP_KEY_NAME,
    											Config.SP_KEY_PASSWD);
		byte[] encodedSymmetricKey 
					= Cryptography.decryptAsymmetric(keyNeg.encryptedSymmetricKey, key);
						// Symm key stored as getEncoded
		_symmetricKey = new SecretKeySpec(encodedSymmetricKey, "AES");
		
		System.out.println("Decrypting challenge.");
		byte[] encodedChallenge = Cryptography.decryptSymmetric(keyNeg.encryptedKeyNegotiationChallenge, _symmetricKey);
		KeyNegotiationChallenge neg = KeyNegotiationChallenge.decode(encodedChallenge);

		System.out.println("Checking subject.");
		if(!neg.subject.equals(_myCert.subject))
			throw new ServerException("Invalid subject. Aborting connection.");
		
		System.out.println("Challenge accepted. Number: " + neg.challenge);
		int resp = neg.challenge + 1;
		byte[] encryptedResponse = Cryptography.encryptSymmetric(ByteSerializer.EncodeInt(resp),
																 _symmetricKey);
		
		System.out.println("Challenge answered. Sending response.");
		KeyNegotiationResponse response = new KeyNegotiationResponse();
		response.challengeResponse = encryptedResponse;
		
		return response;
	}

	private SignedData<Certificate> _getIdentification() throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
		return new X509CertificateSimplifier(_name, "123456", _domainId)
						.getSignedCertificate();
	}

	private void _printAttributeData(String[] read) {
		for(int i = 0; i < read.length; i++) {
			System.out.println((i + 1) + ": " + read[i]);
		}
	}

}
