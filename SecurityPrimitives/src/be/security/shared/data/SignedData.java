package be.security.shared.data;

import java.io.Serializable;

/**
 * Class containing data and its signature.
 *
 * @param <T>: Type of data which is signed. Needs to be serializable
 */
public class SignedData<T extends Serializable>
	implements Serializable
{
	public SignedData(T data, String issuer, byte[] signature) {
		this.data = data;
		this.issuer = issuer;
		this.signature = signature;
	}
	
	public final T data;

	// Data used for signing
	public final String issuer;
	public final byte[] signature;
	
	
	
	private static final long serialVersionUID = -3175236278801919374L;
}