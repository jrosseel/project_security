package be.gov.main;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import be.security.shared.keystore.KeyReader;

/*
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.data.SignedData;
import be.security.shared.keystore.KeyReader;
import be.security.shared.signing.SignatureVerifier;
*/
public class Test {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException
	{
		KeyReader k = new KeyReader("misc", "123456");
		//RSAPublicKey key = (RSAPublicKey) k.readPublic("card identifier");
		RSAPrivateKey sk = (RSAPrivateKey)k.readPrivate("card identifier", "");
		printBytes(sk.getModulus().toByteArray());
		System.out.println("\n");
		printBytes(sk.getPrivateExponent().toByteArray());
		System.out.println(sk.getModulus().toByteArray().length);
		System.out.println(sk.getPrivateExponent().toByteArray().length);
		
		byte[] test = new byte[]{(byte)0x00, (byte)0x75, (byte)0x2c, (byte)0x8a, (byte)0xb0, (byte)0xc9, (byte)0x9a, (byte)0x7c, (byte)0x6b, (byte)0x3c, (byte)0xc4, (byte)0x49, (byte)0x4c, (byte)0x25, (byte)0x50, (byte)0xf1, (byte)0x32, (byte)0xbc, (byte)0x1f, (byte)0x44, (byte)0x4a, (byte)0x82, (byte)0xe9, (byte)0xf3, (byte)0xb6, (byte)0x37, (byte)0xab, (byte)0x4e, (byte)0x06, (byte)0x47, (byte)0xc2, (byte)0x8f, (byte)0x49, (byte)0xa4, (byte)0x1f, (byte)0xc6, (byte)0x40, (byte)0x82, (byte)0x3d, (byte)0x19, (byte)0x9d, (byte)0x41, (byte)0x7d, (byte)0xe2, (byte)0x07, (byte)0xe8, (byte)0xa2, (byte)0xb7, (byte)0x5b, (byte)0xfb, (byte)0xcb, (byte)0x7f, (byte)0xca, (byte)0x81, (byte)0x8c, (byte)0xed, (byte)0xd3, (byte)0x52, (byte)0x4b, (byte)0x6b, (byte)0x0d, (byte)0x4b, (byte)0xe3, (byte)0x81};
		BigInteger modulusInBig = new BigInteger(test);
		System.out.println(sk.getPrivateExponent());
		System.out.println(modulusInBig);
		
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	

}
