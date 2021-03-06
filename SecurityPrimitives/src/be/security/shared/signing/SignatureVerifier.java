package be.security.shared.signing;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import be.security.shared.data.SignedData;
import be.security.shared.encryption.Hasher;
import be.security.shared.keystore.KeyReader;

public class SignatureVerifier 
{
	private PublicKey _caPublicKey;
	
	public SignatureVerifier(String caKeyStoreName, String caKeyStorePasswd, String caKey) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		KeyReader _caKeyStore = new KeyReader(caKeyStoreName, caKeyStorePasswd);
		
		_caPublicKey = _caKeyStore.readPublic(caKey);	
	}
	
	public SignatureVerifier(PublicKey pk) 
	{
		_caPublicKey = pk;	
	}
	
	/**
	 * Verifies if the signed data is valid. 
	 * @param <T>
	 */
	public <T extends Serializable> boolean verify(SignedData<T> signedData)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException 
	{
		byte[] hash = Hasher.hashObject(signedData.data);
		return verify(
				hash, 
				signedData.signature);
	}
	
	/**
	 * Verifies if the certificate is valid, meaning it is signed by CA.
	 * 
	 * @param data: The certificate
	 * @param signedData: The signed certificate
	 * 
	 * @return Whether the signedData represents the same object signed by CA
	 * @throws IOException 
	 */
	public boolean verify(byte[] hash, byte[] signature) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
		Signature sig = Signature.getInstance("SHA1withRSA");
		
		// Set the public key used for verification
		sig.initVerify(_caPublicKey);
		// Set the certificate
		sig.update(hash);
		
		// Verify the signed data matches the signature
		return sig.verify(signature);
	}
}
