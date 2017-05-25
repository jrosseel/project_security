package signing;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import data.SignedCertificate;
import encryption.ByteSerializer;
import keystore.KeyReader;

public class SignatureVerifier 
{
	private PublicKey _caPublicKey;
	
	public SignatureVerifier(String caKeyStoreName, String caKeyStorePasswd, String caKey) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyReader _caKeyStore = new KeyReader(caKeyStoreName, caKeyStorePasswd);
		_caPublicKey = _caKeyStore.readPublic(caKey);	
	}
	
	/**
	 * Verifies if the signed certificate is valid. 
	 */
	public boolean verify(SignedCertificate certificate)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException 
	{
		return verify(
				ByteSerializer.EncodeObject(certificate.certificate), 
				certificate.signature);
	}
	
	/**
	 * Verifies if the certificate is valid, meaning it is signed by CA.
	 * 
	 * @param data: The certificate
	 * @param signedData: The signed certificate
	 * 
	 * @return Whether the signedData represents the same object signed by CA
	 */
	public boolean verify(byte[] data, byte[] signedData) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		Signature sig = Signature.getInstance("RSA");
		
		// Set the public key used for verification
		sig.initVerify(_caPublicKey);
		// Set the certificate
		sig.update(data);
		
		// Verify the signed data matches the signature
		return sig.verify(signedData);
	}
}
