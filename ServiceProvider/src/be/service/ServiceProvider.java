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

import be.security.shared.data.Certificate;
import be.security.shared.data.KeyNegotiation;
import be.security.shared.data.KeyNegotiationChallenge;
import be.security.shared.data.SignedData;
import be.security.shared.encryption.Cryptography;
import be.security.shared.keystore.KeyReader;
import be.service.certify.X509CertificateSimplifier;
import be.service.config.Config;
import global.connection.sockets.SocketTransmitter;

public class ServiceProvider {
	
	private SocketTransmitter _connection;
	private String 			  _name;
	private int 			  _domainId;
	private KeyReader 		  _keyReader;
	
	private byte[] _symmetricKey;
	
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
		SignedData<Certificate> myCert = _getIdentification();
		_connection.Send(myCert);
		
		KeyNegotiation keyNeg = _connection.ReceiveObject();

		_symmetricKey = Cryptography.decryptAsync(keyNeg.encryptedKeyNegotiationChallenge, 
							 				 	  _keyReader.readPrivate(Config.SP_KEY_NAME,
							 						  			         Config.SP_KEY_PASSWD));
		//KeyNegotiationChallenge chall =
		// TODO: Further steps
	}
	
	private SignedData<Certificate> _getIdentification() throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
		return new X509CertificateSimplifier(_name, "123456", _domainId)
						.getSignedCertificate();
	}

}
