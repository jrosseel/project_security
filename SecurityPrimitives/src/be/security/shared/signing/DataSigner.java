package be.security.shared.signing;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.data.SignedData;
import be.security.shared.encryption.Hasher;
import be.security.shared.keystore.KeyReader;
import be.security.shared.settings.GlobalConsts;

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
			throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException 
	{
		// Encode the object
		byte[] hash = Hasher.hashObject(data);

		return sign(data, hash);
	}
	
	public <T extends Serializable> SignedData<T> sign(T data, byte[] hash) 
			throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException 
	{
		byte[] signature = signHash(hash);
		    
		return new SignedData<T>(data, _issuer, signature);
	}
	

	public byte[] signHash(byte[] hash) 
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException
	{ 
		PrivateKey pen = _getPen();
		
		Signature signer;
	    signer = Signature.getInstance(GlobalConsts.SIGNATURE_ALGORITHM);
	    signer.initSign(pen);
	    signer.update(hash);
	    byte[] signature = signer.sign();
		
	    return signature;
	}
	
	
	private PrivateKey _getPen() 
		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		return _penKeyStore.readPrivate(_penKey, _penPasswd);
	}
}
