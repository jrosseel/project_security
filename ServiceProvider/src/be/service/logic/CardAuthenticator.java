package be.service.logic;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import be.security.shared.data.CardAuthenticationMedium;
import be.security.shared.encryption.ByteSerializer;
import be.security.shared.encryption.Cryptography;
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
	
	public void verifyChallenge(byte[] reply)
			throws ServerException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		byte[] replyMessage = Cryptography.decryptSymmetric(reply, _symmetricKey);
		// TODO. properly decode
		
	}
}