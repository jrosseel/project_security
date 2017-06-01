package be.service.logic;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import be.security.shared.data.CardAuthenticationMedium;
import be.security.shared.encryption.ByteSerializer;
import be.security.shared.encryption.Cryptography;
import be.security.shared.encryption.Hasher;
import be.security.shared.signing.SignatureVerifier;
import be.service.config.ServerException;

public class CardAuthenticator {

	private final SecretKey _symmetricKey;
	private final int _challenge;
	
	public CardAuthenticator(SecretKey symmetricKey) 
	{
		_symmetricKey = symmetricKey;
		
		SecureRandom random = new SecureRandom();
		_challenge = random.nextInt();
	}

	public Serializable getAuthenticationRequest()
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		byte[] challengeData = ByteSerializer.EncodeInt(_challenge);
		byte[] challengeEncrypted = Cryptography.encryptSymmetric(challengeData, _symmetricKey);
		
		CardAuthenticationMedium transferMedium = new CardAuthenticationMedium();
		transferMedium.data = challengeEncrypted;
		
		return transferMedium;
	}
	
	public boolean verifyChallenge(byte[] reply)
			throws ServerException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, SignatureException, IOException, InvalidKeySpecException
	{
		// Get full message - [PK[b + exp], Signature]
		byte[] replyMessage = Cryptography.decryptSymmetric(reply, _symmetricKey);
		
		// Get certificate
		BigInteger publicKey = _getKFromMessageReply(replyMessage);
		BigInteger exp = _getExpFromMessageReply(replyMessage);
		// Create key
		RSAPublicKeySpec spec = new RSAPublicKeySpec(publicKey, exp);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PublicKey pub = factory.generatePublic(spec);
		
		// Get signature
		byte[] signature = _getsignatureFromMessageReply(replyMessage);
		
		// Verify challenge
		byte[] hashedChallenge = Hasher.hashBytes(ByteSerializer.EncodeInt(_challenge)); 
		SignatureVerifier verifier = new SignatureVerifier(pub);
		
		return verifier.verify(hashedChallenge, signature);
	}

	/**
	 * Return first field of the replyMessage  	Cert[k - 64 bytes, exp - 3 bytes]
	 */
	private BigInteger _getKFromMessageReply(byte[] msg)
	{
		byte[] k = Arrays.copyOfRange(msg, 0, 64);
		return new BigInteger(k);
	}
	
	private BigInteger _getExpFromMessageReply(byte[] msg) 
	{
		byte[] exp = Arrays.copyOfRange(msg, 64, 67);
		return new BigInteger(exp);
	}
	
	/**
	 * Return second field of the replyMessage   Signature - 64 bytes
	 */
	private byte[] _getsignatureFromMessageReply(byte[] msg)
	{
		return Arrays.copyOfRange(msg, 67, msg.length);
	}
}