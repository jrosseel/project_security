package signing;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import data.SignedCertificate;
import encryption.Cryptography;
import keystore.KeyReader;
import settings.Config;

public class CertificateSigner 
{
	private KeyReader _caKeyStore;
	
	private String _caKey, 
				   _caKeyPasswd;

	public CertificateSigner(String caKeyStoreName, String caKeyStorePasswd, String caKey, String caKeyPasswd) 
	{
		_caKeyStore = new KeyReader(caKeyStoreName, caKeyStorePasswd);
		
		_caKey = caKey;
		_caKeyPasswd = caKeyPasswd;
	}
	
	public SignedCertificate sign(Certificate cert) 
			throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException 
	{
		PrivateKey pen = _getPen();
		byte[] signature = Cryptography.encrypt(cert, pen);
		
		String issuer = _getIssuer();
		
		return new SignedCertificate(cert, issuer, signature);
	}
	
	
	private PrivateKey _getPen() 
		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		return _caKeyStore.readPrivate(_caKey, _caKeyPasswd);
	}
	
	private String _getIssuer()
	{
		// TODO: Read from certificate, instead of hardcode
		return Config.CA_SUBJECT;
	}
}
