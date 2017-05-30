package be.service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

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
import be.security.shared.data.SignedData;
import be.security.shared.encryption.ByteSerializer;
import be.security.shared.encryption.Cryptography;
import be.security.shared.keystore.KeyReader;
import be.security.shared.settings.GlobalConsts;
import be.service.certify.X509CertificateSimplifier;
import be.service.config.Config;
import be.service.config.ServerException;
import be.service.logic.CardAuthenticator;
import global.connection.sockets.SocketTransmitter;

public class ServiceProvider {
	
	private SocketTransmitter _connection;
	private String 			  _name;
	private int 			  _domainId;
	private KeyReader 		  _keyReader;
	
	private SecretKey _symmetricKey;
	private Certificate _myCert;
	
	public ServiceProvider(SocketTransmitter connection, String name, int domainId) {
		_connection = connection;
		_name = name;
		_domainId = domainId;
		_keyReader = new KeyReader(name, Config.KEYSTORE_PASSWD);
	}

	public void run()
					throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException, ClassNotFoundException 
	{	
		// First authenticate yourself to the caller
		SignedData<Certificate> signedCert = _getIdentification();
		_myCert = signedCert.data;
		_connection.Send(signedCert);
		
		KeyNegotiation keyNeg = _connection.ReceiveObject();

		try {
			KeyNegotiationResponse keyNegResp = _handleKeynegotiation(keyNeg);
			_connection.Send(keyNegResp);
			
			CardAuthenticator authenticator = new CardAuthenticator(_symmetricKey);
			_connection.Send(authenticator.getAuthenticationRequest());
			CardAuthenticationMedium cardAuthResponse = _connection.ReceiveObject();
			
			authenticator.verifyChallenge(cardAuthResponse.data);
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
					throws ServerException, InvalidKeyException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, IOException 
	{
		byte[] encodedSymmetricKey 
					= Cryptography.decryptAsymmetric(keyNeg.encryptedKeyNegotiationChallenge, 
													 _keyReader.readPrivate(Config.SP_KEY_NAME,
				 						  			         				Config.SP_KEY_PASSWD));
						// Symm key stored as getEncoded
		_symmetricKey = new SecretKeySpec(encodedSymmetricKey, GlobalConsts.SYMM_CRYPTO_ALGORITHM);
		
		byte[] encodedChallenge = Cryptography.decryptSymmetric(keyNeg.encryptedKeyNegotiationChallenge, _symmetricKey);
		KeyNegotiationChallenge neg = KeyNegotiationChallenge.decode(encodedChallenge);
		
		if(!neg.subject.equals(_myCert.subject))
			throw new ServerException("Invalid subject. Aborting connection.");
		
		int resp = neg.challenge + 1;
		byte[] encryptedResponse = Cryptography.encryptSymmetric(ByteSerializer.EncodeInt(resp),
																 _symmetricKey);
		
		KeyNegotiationResponse response = new KeyNegotiationResponse();
		response.challengeResponse = encryptedResponse;
		
		return response;
	}

	private SignedData<Certificate> _getIdentification() throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
		return new X509CertificateSimplifier(_name, "123456", _domainId)
						.getSignedCertificate();
	}

	
}
