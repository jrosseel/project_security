package data;

import java.security.cert.Certificate;

public class SignedCertificate 
{

	public SignedCertificate(Certificate certificate, String issuer, byte[] signature) {
		this.certificate = certificate;
		this.issuer = issuer;
		this.signature = signature;
	}
	
	public final Certificate certificate;

	// Data used for signing
	public final String issuer;
	public final byte[] signature;
	
}