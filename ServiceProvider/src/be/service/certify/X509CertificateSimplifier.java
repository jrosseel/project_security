package be.service.certify;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.data.Certificate;
import be.security.shared.data.SignedData;
import be.security.shared.keystore.KeyReader;
import be.security.shared.signing.DataSigner;

public class X509CertificateSimplifier 
{
	private KeyReader _keyStore;
	private int _domain;
	
	// Every SP has its own keystore
	//	 The SP public and private key are stored in the key-pair called "me"
	private final static String _KEY_NAME   = "me";
	
	public X509CertificateSimplifier(String keyStoreName, String storePassword, int domain) 
	{
		_keyStore = new KeyReader(keyStoreName, storePassword);
		_domain = domain;
	}
	
	/**
	 * Returns the certificate of the current service provider.
	 */
	public SignedData<Certificate> getSignedCertificate()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException 
	{
		Certificate cert = _getCertificate();
		
		// This is somewhat a hack! Normally, the service provider should not have access to the private key of CA. No one should except for CA!
		// 	 Only for purposes of simplification, we included this hack.
		DataSigner signer = new DataSigner("ca", "123456", 
										   "global_masterkey", "123456", 
										   "CN=Global Masterkey CA,OU=Master Key Holding Vault,O=Master Key Holding Ltd.,L=Luxembourg,ST=Brussels,C=BE,E=contact@jenterosseel.com");
		
		return signer.sign(cert);
	}
	
	private Certificate _getCertificate() 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		X509Certificate x509 = (X509Certificate) _keyStore.readCertificate(_KEY_NAME);
		
		Certificate cert = new Certificate();
		cert.domain = _domain;
		cert.subject = x509.getSubjectX500Principal().getName();
		cert.publicKey = x509.getPublicKey().getEncoded();
		
		return cert;
	}
}
