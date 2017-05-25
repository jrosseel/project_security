package be.security.shared.keystore;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import be.security.shared.settings.GlobalConsts;


public class KeyReader 
{
	private String keyStoreLoc;
	private String storePassword;
	
	public KeyReader
		(String keyStoreName, String storePassword)
	{
		this.keyStoreLoc = 
				GlobalConsts.KEY_STORE_FOLDER + keyStoreName + ".jks";
		this.storePassword = storePassword;
	}
	
	public PrivateKey readPrivate(String keyName, String password) 
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException 
	{
		KeyStore ks = _LoadKeyStore(keyStoreLoc, storePassword);
		
		PrivateKey sk = (PrivateKey) ks.getKey(keyName, password.toCharArray());

		return sk;
	}
	
	public PublicKey readPublic(String keyName) 
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyStore ks = _LoadKeyStore(keyStoreLoc, storePassword);
		
		Certificate cert = (Certificate) ks.getCertificate(keyName);
		PublicKey pk = (PublicKey)cert.getPublicKey();

		return pk;
	}
	
	/** Loads a KeyStore, given the location and password.
	 */
	private static KeyStore _LoadKeyStore(String keyStoreLoc, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		
		KeyStore ks = KeyStore.getInstance(GlobalConsts.KEY_STORE_TYPE);
		
		FileInputStream fis = new FileInputStream(keyStoreLoc);
		ks.load(fis, password.toCharArray());
		fis.close();
		
		return ks;
		
	}
}
