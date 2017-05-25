package be.shared.data;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.cert.Certificate;


public class KeystoreEx {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// keystore Werner
		KeyStore keyStore1 = KeyStore.getInstance("JKS");
		String fileName = "keystore1.jks";
		FileInputStream fis = new FileInputStream(fileName);
		keyStore1.load(fis, "password".toCharArray());
		fis.close();
		
		// get certificate freya in keystore werner
		Certificate cert = (Certificate) keyStore1.getCertificate("freya");
		
		// get public key freya
		PublicKey pk_freya = (PublicKey)cert.getPublicKey();
		
		// encrypt message with public key freya
		Cipher rsaenc = Cipher.getInstance("RSA");
		rsaenc.init(Cipher.ENCRYPT_MODE, pk_freya);
		byte[] encrypted = rsaenc.doFinal("This is a text".getBytes("UTF-8"));
		
		// keystore freya
		KeyStore keyStore2 = KeyStore.getInstance("JKS");
		String fileName2 = "keystore2.jks";
		FileInputStream fis2 = new FileInputStream(fileName2);
		keyStore2.load(fis2, "password".toCharArray());
		fis2.close();
		
		// get private key freya
		PrivateKey sk_freya = (PrivateKey) keyStore2.getKey("freya", "password".toCharArray());
        Cipher rsadec = Cipher.getInstance("RSA");      
        rsadec.init(Cipher.DECRYPT_MODE, sk_freya);
        byte[] decrypted = rsadec.doFinal(encrypted);
		
        System.out.println(new String(decrypted));
		
	}

}
