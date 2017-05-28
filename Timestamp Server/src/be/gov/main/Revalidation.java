package be.gov.main;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.gov.config.Config;
import be.security.shared.data.SignedData;
import be.security.shared.signing.DataSigner;

public class Revalidation
{
	public static SignedData<Long> revalidate(long date) 
						throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		
		DataSigner signer = new DataSigner(Config.KEY_STORE_NAME, 
										   Config.KEYSTORE_LOC, 
										   Config.SERVER_KEY_NAME, 
										   Config.SERVER_KEY_PASSWD, 
										   Config.SERVER_ISSUER);
		
		return signer.sign(date);
	}
}
