package be.security.shared.signing;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.data.SignedData;
import be.security.shared.encryption.ByteSerializer;
import be.security.shared.encryption.Cryptography;
import be.security.shared.encryption.Hasher;
import be.security.shared.keystore.KeyReader;

public class DataSigner 
{
	private KeyReader _penKeyStore;
	
	private String _penKey, 
				   _penPasswd,
				   _issuer;

	public DataSigner(String penKeyStore, String penKeyStorePasswd, String penKey, String penKeyPasswd, String issuer) 
	{
		_penKeyStore = new KeyReader(penKeyStore, penKeyStorePasswd);
		
		_penKey = penKey;
		_penPasswd = penKeyPasswd;
		_issuer = issuer;
	}
	
	public <T extends Serializable> SignedData<T> sign(T data) 
			throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException 
	{
		PrivateKey pen = _getPen();
		
		// Encode the object
		byte[] hash = Hasher.hashObject(data);
		
		byte[] signature = Cryptography.encrypt(hash, pen);
		
		return new SignedData<T>(data, _issuer, signature);
	}
	
	
	private PrivateKey _getPen() 
		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		return _penKeyStore.readPrivate(_penKey, _penPasswd);
	}
}