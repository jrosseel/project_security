package be.msec.smartcard;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.smartcard.access.DataRestrictions;
import be.msec.smartcard.query.QueryResolver;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet {
	
	private CardData card;
    private final byte[] sigma;
    private final byte[] mod_pub_gov = new byte[]{(byte)0xc0, (byte)0xe0, (byte)0xeb, (byte)0x88, (byte)0xba, (byte)0xe3, (byte)0x82, (byte)0x6e, (byte)0x47, (byte)0x23, (byte)0xf3, (byte)0x11, (byte)0x3b, (byte)0xff, (byte)0x3c, (byte)0x2a, (byte)0xaa, (byte)0x19, (byte)0x92, (byte)0xe1, (byte)0xb0, (byte)0xb9, (byte)0xcb, (byte)0x87, (byte)0xbe, (byte)0xf7, (byte)0xd5, (byte)0x9a, (byte)0x10, (byte)0xad, (byte)0x72, (byte)0x64, (byte)0x44, (byte)0xeb, (byte)0x43, (byte)0x01, (byte)0x61, (byte)0x4c, (byte)0xa7, (byte)0xcd, (byte)0x71, (byte)0xe6, (byte)0xd6, (byte)0xd5, (byte)0x19, (byte)0x01, (byte)0x55, (byte)0xd8, (byte)0x83, (byte)0xf6, (byte)0x05, (byte)0x8a, (byte)0x4e, (byte)0x2a, (byte)0x58, (byte)0x2e, (byte)0xe6, (byte)0x69, (byte)0xd3, (byte)0xb9, (byte)0x72, (byte)0x84, (byte)0xbd, (byte)0x33};		
    private final byte[] exp_pub_gov = new byte[]{(byte)0x01, (byte)0x00, (byte)0x01};
    private final byte[] mod_pub_ca = new byte[]{(byte)0xaa, (byte)0x0d, (byte)0x5f, (byte)0x3e, (byte)0xde, (byte)0x27, (byte)0xa2, (byte)0x06, (byte)0x7a, (byte)0x47, (byte)0x3e, (byte)0x62, (byte)0xe3, (byte)0x52, (byte)0x02, (byte)0xe2, (byte)0xcf, (byte)0x36, (byte)0x6a, (byte)0x9e, (byte)0xa4, (byte)0x80, (byte)0x79, (byte)0x2d, (byte)0x97, (byte)0x82, (byte)0x3c, (byte)0xf5, (byte)0x16, (byte)0xbc, (byte)0x59, (byte)0xcf, (byte)0x6a, (byte)0x0c, (byte)0x49, (byte)0xf4, (byte)0x59, (byte)0xab, (byte)0xb7, (byte)0x98, (byte)0x6e, (byte)0xd6, (byte)0x85, (byte)0xbe, (byte)0x35, (byte)0x7d, (byte)0xcf, (byte)0xf0, (byte)0x52, (byte)0x8a, (byte)0x8d, (byte)0xf1, (byte)0x6d, (byte)0xc9, (byte)0xd3, (byte)0xa9, (byte)0x4f, (byte)0x9a, (byte)0x2e, (byte)0x4b, (byte)0xfd, (byte)0xd2, (byte)0x87, (byte)0x2b};
    private final byte[] exp_pub_ca = new byte[]{(byte)0x01, (byte)0x00, (byte)0x01};    
    private final byte[] mod_priv_co = new byte[]{(byte)0xbe, (byte)0x6d, (byte)0x72, (byte)0x7f, (byte)0xae, (byte)0xd1, (byte)0x1d, (byte)0x34, (byte)0xe2, (byte)0xaf, (byte)0x74, (byte)0xe2, (byte)0x3e, (byte)0xf5, (byte)0x51, (byte)0x9f, (byte)0xb4, (byte)0xf0, (byte)0x2b, (byte)0xb0, (byte)0xfb, (byte)0xab, (byte)0xbb, (byte)0x61, (byte)0x3f, (byte)0xab, (byte)0xd2, (byte)0x12, (byte)0xdb, (byte)0xa7, (byte)0x95, (byte)0xd8, (byte)0x2b, (byte)0xc9, (byte)0x26, (byte)0x2f, (byte)0x3c, (byte)0xff, (byte)0x99, (byte)0x4a, (byte)0x09, (byte)0x10, (byte)0x64, (byte)0x14, (byte)0x95, (byte)0x3e, (byte)0x03, (byte)0xd5, (byte)0x86, (byte)0xa3, (byte)0x30, (byte)0x39, (byte)0xa8, (byte)0x39, (byte)0xd3, (byte)0xe8, (byte)0xbe, (byte)0xe3, (byte)0x8d, (byte)0x39, (byte)0x11, (byte)0x1e, (byte)0x53, (byte)0x6f};       
    private final byte[] exp_pub_co = new byte[]{(byte)0x01, (byte)0x00, (byte)0x01};
    private final byte[] exp_priv_co = new byte[]{(byte)0x12, (byte)0x14, (byte)0x82, (byte)0x2c, (byte)0x20, (byte)0x85, (byte)0x03, (byte)0xdc, (byte)0x16, (byte)0x63, (byte)0x62, (byte)0x4d, (byte)0x9f, (byte)0x49, (byte)0x75, (byte)0x18, (byte)0x1c, (byte)0xc7, (byte)0x6a, (byte)0x78, (byte)0x28, (byte)0x20, (byte)0x37, (byte)0xa2, (byte)0x48, (byte)0xea, (byte)0xec, (byte)0x32, (byte)0x61, (byte)0x5e, (byte)0xff, (byte)0xff, (byte)0xca, (byte)0xb5, (byte)0x72, (byte)0x7d, (byte)0xf3, (byte)0x78, (byte)0x46, (byte)0x53, (byte)0xe4, (byte)0x46, (byte)0x47, (byte)0x5d, (byte)0xd9, (byte)0xe6, (byte)0xda, (byte)0xcf, (byte)0x2a, (byte)0xa2, (byte)0x0b, (byte)0x26, (byte)0x71, (byte)0xba, (byte)0x02, (byte)0xc0, (byte)0x09, (byte)0x3d, (byte)0x3a, (byte)0xeb, (byte)0xe6, (byte)0xed, (byte)0x89, (byte)0x81};
    private byte[] diff;
    private OwnerPIN pin;
	private AESKey ks;
	private byte[] rand_ks;
	private byte[] challenge; 
	private Cipher RSAencrypt = Cipher.getInstance(Cipher.ALG_RSA_PKCS1 , false);
	private Cipher AESencrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
	//input above instance variables into info below
	private byte[] info;
	private short incomingData;
	private short auth = 0;
	private byte[] domain = null;
	//	private short newPin;
	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 */
		pin = new OwnerPIN(InstructionCodes.PIN_TRY_LIMIT,InstructionCodes.PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, InstructionCodes.PIN_SIZE); 
		
		sigma = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5C, 0x00 }; // 1 day = 86400000 milliseconds 
		diff = new byte[]{0x00, 0x00, 0x00, 0x01};		
		card = new CardData();
		
		// public key G
		RSAPublicKey pub_gov = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		pub_gov.setExponent(exp_pub_gov, (short)0, (short)exp_pub_gov.length);
		pub_gov.setModulus(mod_pub_gov, (short)0, (short)mod_pub_gov.length);	
		card.setPublicKeyGovernment(pub_gov);
		
		// public key CA
		RSAPublicKey pub_ca = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		pub_ca.setExponent(exp_pub_ca, (short)0, (short)exp_pub_ca.length);
		pub_ca.setModulus(mod_pub_ca, (short)0, (short)mod_pub_ca.length);
		card.setPublicKeyCA(pub_ca);
		
		// private key Common
		RSAPrivateKey priv_co = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
		priv_co.setExponent(exp_priv_co, (short)0, (short)exp_priv_co.length);
		priv_co.setModulus(mod_priv_co, (short)0, (short)mod_priv_co.length);
		card.setPrivateKeyCommon(priv_co);
		
		// AES key user
		AESKey ku;
		ku = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		rand_ks = new byte[16];
		RandomData rnd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        rnd.generateData(rand_ks, (short)0, (short)rand_ks.length);
		
		ku.setKey(rand_ks, (short)0);
		card.setKu(ku);
				
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException 
	{
			new IdentityCard();				
	}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() 
	{
		if (pin.getTriesRemaining()==0)
			return false;
		
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException 
	{
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
				
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != InstructionCodes.IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		try {
			_executeInstruction(apdu, buffer);
		} catch (KeyStoreException e) {
			// 
		} catch (NoSuchAlgorithmException e) {
		} catch (CertificateException e) {
		} catch (IOException e) {
		} catch (InvalidKeyException e) {
		} catch (SignatureException e) {
		} catch (CryptoException e) {
		} catch (InvalidKeySpecException e) {
		} catch (Exception e) {
		}
	}

	/**
	 * Authenticates the owner of the card using a PIN code.
	 */
	private void _validatePIN(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==InstructionCodes.PIN_SIZE)
		{
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,InstructionCodes.PIN_SIZE)==false)
				ISOException.throwIt(SignalCodes.SW_VERIFICATION_FAILED);
		}
		else 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/**
	 * Executes the current instruction
	 * @throws Exception 
	 */
	private void _executeInstruction(APDU apdu, byte[] buffer) throws Exception 
	{
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS])
		{				
			case InstructionCodes.VALIDATE_PIN_INS:
				_validatePIN(apdu);
				break;
			case InstructionCodes.GET_NAME_INS:
				_getCardData(apdu, card.getName());
				break;
			case InstructionCodes.GET_ADDRESS_INS:
				_getCardData(apdu, card.getAddress());
				break;
			case InstructionCodes.GET_COUNTRY_INS:
				_getCardData(apdu, card.getCountry());
				break;
			case InstructionCodes.GET_BIRTH_DATE_INS:
				_getCardData(apdu, card.getBirthDate());
				break;
			case InstructionCodes.GET_AGE_INS:
				_getCardData(apdu, card.getAge());
				break;
			case InstructionCodes.GET_GENDER_INS:
				_getCardData(apdu, card.getGender());
				break;
			case InstructionCodes.GET_SSN_INS:
				_getCardData(apdu, card.getSsn());
				break;
			case InstructionCodes.GET_PHOTO_INS:
				_getCardData(apdu, card.getPhoto());
				break;
			case InstructionCodes.DO_HELLO_INS:
				_doHelloTime(apdu);
				break;
			case InstructionCodes.DO_NEW_TIME_INS:
				_doNewTime(apdu);
				break;
			case InstructionCodes.DO_AUTH_SP_STEP:
				_doAuthSPStep(apdu);
				break;
			case InstructionCodes.DO_AUTH_SP:
				_doAuthSP(apdu);
				break;
			case InstructionCodes.DO_AUTH_CARD:
				_doAuthCard(apdu);
				break;
			case InstructionCodes.GET_AUTH_SER_EKEY:
				_doServAuthEkey(apdu);
				break;
			case InstructionCodes.GET_AUTH_SER_EMSG:
				_doServAuthEmsg(apdu);
				break;
			case InstructionCodes.DO_CHECK_SERVER_RESP:
				_doCheckServerResp(apdu);
				break;
			case InstructionCodes.DO_ATTRIBUTE_QUERY:
				_doAttributeQuery(apdu);
				break;
				
			//If no matching instructions are found it is indicated in the status word of the response.
			//This can be done by using this method. As an argument a short is given that indicates
			//  the type of warning. There are several predefined warnings in the 'ISO7816' class.
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	// Methods
	private void _doHelloTime(APDU apdu)
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else {
			byte[] buffer_in = apdu.getBuffer();
			
			/*
			 * buffer_in contains
			 * - CLA 		= 1 byte
			 * - INS-code	= 1 byte
			 * - P1			= 1 byte
			 * - P2			= 1 byte
			 * - LC = # bytes in data field = 1 byte
			 * - data		= various number of bytes
			 * - Le = max # bytes in data field = 1 byte
			 * 
			 *  => OFFSET_DATA = CLA + INS + P1 + P2 + LC
			 */
			
			short offset = (short) (ISO7816.OFFSET_CDATA); 
			
			byte result=0;
			
			for(short i=0; i<8;i++)
			{
				if(!(card.getLastValidationTime()[i] == (buffer_in[offset+i] - sigma[i])))
				{
					if(card.getLastValidationTime()[i]<(buffer_in[offset+i]-sigma[i]))
					{
						result=1;
					}
					break;
				}
			}
			
			byte[] buffer_out = new byte[]{result};
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}		
	
	private void _doNewTime(APDU apdu) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, CryptoException, InvalidKeySpecException
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] buffer_in = apdu.getBuffer();			
			
			short length_time = (short) 8;
			short length_signature = (short) 64;
			short offset_signature = (short) (ISO7816.OFFSET_CDATA); 
			short offset_time = (short) (offset_signature+length_signature);
			byte result=2;
			
			byte[] time = new byte[length_time];
			byte[] signature = new byte[length_signature];
						
			// fill bytearray signature
			for(short i=0; i<length_signature;i++)
			{
				signature[i] = buffer_in[offset_signature+i];
			}
			
			// fill bytearray time
			for(short i=0; i<length_time;i++)
			{
				time[i] = buffer_in[offset_time+i];
			}
			
			// hash time
			MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			md.reset();
			byte[] hash = new byte[20];
			md.doFinal(time, (short) 0, (short) time.length, hash, (short) 0);
			
			Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			sig.init(card.getPublicKeyGovernment(), Signature.MODE_VERIFY);
		
			if(sig.verify(hash, (short)0, (short)hash.length, signature, (short)0, (short)signature.length))
			{
				result = 1;
				card.setLastValidationTime(time);
			}
			else
			{
				result = 0;
				ISOException.throwIt(SignalCodes.SW_UPDATE_TIME_FAILED);
			}

			byte[] buffer_out = new byte[]{result};
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}	
	
	private int authStep = 0;
	private byte[] authBuffer = new byte[512];
	private byte[] storage = new byte[512];
	private void _doAuthSPStep(APDU apdu)
	{
		if ( ! pin.isValidated()) 
			ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		
		if (authStep == 0) {
            Util.arrayFillNonAtomic(authBuffer, (short) 0, (short) authBuffer.length, (byte) 0);
        }
        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        short START = 0;
        Util.arrayCopy(buffer, START, storage, START, (short)8);
        short readCount = apdu.setIncomingAndReceive();
        short i = (short) (255*authStep);
        while ( bytesLeft > 0){
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, authBuffer, i, readCount);
            bytesLeft -= readCount;
            i+=readCount;
            readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }      
        authStep += 1;
	}	
	
	private byte[] subject = null; 
	
	private RSAPublicKey pub_sp = null;
	private byte[]time = null;
	private void _doAuthSP(APDU apdu) throws CertificateException
	{
		if ( ! pin.isValidated()) 
			ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		authStep = 0;
		byte result = 3;
		// Dirty fix to get length of signature 
		ByteBuffer b_sig_len = ByteBuffer.wrap(new byte[]{authBuffer[0], authBuffer[1]});
		short sig_len = b_sig_len.getShort();
				
		// Same for length certificate
		ByteBuffer b_cert_len = ByteBuffer.wrap(new byte[]{authBuffer[2], authBuffer[3]});
		short cert_len = b_cert_len.getShort();

		// offsets
		short off_sig = 4; // signature start at fifth pos of authBuffer
		short off_cert = (short)(off_sig + sig_len);	
			
		// fill arrays with signature and certificate
		byte[] signature = new byte[sig_len];
		byte[] cert = new byte[cert_len];
		for(short i=0; i<sig_len; i++)
		{
			signature[i] = authBuffer[off_sig+i];
		}
		
		for(short i=0; i<cert_len; i++)
		{
			cert[i] = authBuffer[off_cert+i];
		}
				
		MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		md.reset();
		byte[] hash = new byte[20];
		md.doFinal(cert, (short) 0, (short) cert.length, hash, (short) 0);
		
		Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		sig.init(card.getPublicKeyCA(), Signature.MODE_VERIFY);
		if(sig.verify(hash, (short)0, (short)hash.length, signature, (short)0, (short)signature.length))
		{			
			splitCertificate(cert);
			// Check if endtime < lastval
			result = 1;
			for(short i=0; i<8;i++)
			{
				if(!(time[i]==card.getLastValidationTime()[i]))
				{
					if(time[i] < card.getLastValidationTime()[i])
					{
						ISOException.throwIt(SignalCodes.SW_VERIFICATION_CERT_FAILED);
					}
					break;
				}
			}		
			
			// challenge
			

		}
		else
		{
			ISOException.throwIt(SignalCodes.SW_VERIFICATION_CERT_FAILED);
		}		
		
		byte[] buffer_out = new byte[]{result};
		
		apdu.setOutgoing();
		
		apdu.setOutgoingLength((short)buffer_out.length);
		apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
	}		
	
	private byte[] e_key;
	private byte[] e_msg;
	
	private void _doServAuthEkey(APDU apdu)
	{
		byte[] secure_rand = new byte[16];
		RandomData rnd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        rnd.generateData(secure_rand, (short)0, (short)secure_rand.length);
		
		// symmetric key
		ks = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		ks.setKey(secure_rand, (short)0);
		
		// asymmetric encryption of key
		RSAencrypt.init(pub_sp, Cipher.MODE_ENCRYPT);
		e_key = new byte[64]; 
		RSAencrypt.doFinal(secure_rand, (short)0, (short)secure_rand.length, e_key, (short)0);
		
		byte[] buffer_out = e_key;
		
		apdu.setOutgoing();
		
		apdu.setOutgoingLength((short)buffer_out.length);
		apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
	}
	
	private void _doServAuthEmsg(APDU apdu)
	{
		challenge = new byte[]{0x00, 0x00, 0x00, 0x02};
		//challenge = new byte[4];
		//RandomData rnd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		//rnd.generateData(challenge, (short)0, (short)challenge.length);
		
		// encrypt challenge and subject. Length = 4 (2 shorts defining the length of challenge and subject) + challenge + subject
		short needed = 0;
		short encrypt_length = (short)(4+challenge.length+subject.length);
		// array has to be a multiple of 16
		byte[]extra = null;
		if(encrypt_length%16!=0)
		{
			needed = (short)(16-(encrypt_length%16));
			encrypt_length = (short)(encrypt_length+needed);
			extra = new byte[needed];
		}
		byte[] to_encrypt =  ByteBuffer.allocate(encrypt_length).putShort((short) challenge.length)
																					.putShort((short) subject.length)
																					.put(challenge)
																					.put(subject)
																					.put(extra).array();
		e_msg = new byte[encrypt_length];
		// encrypt the bytebuffer above
		AESencrypt.init(ks, Cipher.MODE_ENCRYPT);
		byte[] temp = new byte[16];
		
		short max = (short)(encrypt_length/16); 
		short current = 0;
		for(short i=0; i<max; i++)
		{
			// encrypt block per block
			AESencrypt.doFinal(to_encrypt, (short)(0+(current*16)), (short)16, temp, (short)0);
			Util.arrayCopy(temp, (short) 0, e_msg, (short)(0+(current*16)), (short) 16);
			current++;
		}
		
		byte[] buffer_out = e_msg;
		
		apdu.setOutgoing();
		
		apdu.setOutgoingLength((short)buffer_out.length);
		apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
	}
	
	
	private void splitCertificate(byte[]cert)
	{
		short offset = 8;
		// length of subject, subject itself
		ByteBuffer b_subj_len = ByteBuffer.wrap(new byte[]{cert[0], cert[1]});
		short subj_len = b_subj_len.getShort();
		subject = new byte[subj_len];
		for(short i=0; i<subj_len; i++)
		{
			subject[i] = cert[offset+i];
		}
		
		// length of domain, domain itself
		ByteBuffer b_dom_len = ByteBuffer.wrap(new byte[]{cert[2], cert[3]});
		short dom_len = b_dom_len.getShort();
		domain = new byte[dom_len];
		for(short i=0; i<dom_len; i++)
		{
			domain[i] = cert[offset+subj_len+i];
		}
		
		// length of publicKey, publicKey itself
		ByteBuffer b_pub_len = ByteBuffer.wrap(new byte[]{cert[4], cert[5]});
		short pub_len = b_pub_len.getShort();
		byte[] key_helper = new byte[pub_len];
		for(short i=0; i<pub_len; i++)
		{
			if(i==0)
			{
				// check if first byte = 0x00. If so, don't put in array
				if(cert[offset+subj_len+dom_len+i] != 0x00)
				{
					key_helper[i] = cert[offset+subj_len+dom_len+i];
				}
			}
			key_helper[i] = cert[offset+subj_len+dom_len+i];
		}
		
		// length of date, date itself
		ByteBuffer b_time_len = ByteBuffer.wrap(new byte[]{cert[6], cert[7]});
		short time_len = b_time_len.getShort();
		time = new byte[time_len];
		for(short i=0; i<time_len; i++)
		{
			time[i] = cert[offset+subj_len+dom_len+pub_len+i];
		}
		
		// generate public key
		// get modulus
		short mod_len = 64;
		short exp_len = 3;
		// also -2 => don't know where these bytes stand for?
		short off_mod = (short)(key_helper.length-mod_len-exp_len-2);
		byte[] mod = new byte[64];
		for(short i=0; i<64; i++)
		{
			mod[i] = key_helper[off_mod+i];
		}
		
		// get public exponent
		short off_exp = (short)(key_helper.length-exp_len);
		byte[] exp = new byte[3];
		for(short i=0; i<3; i++)
		{
			exp[i] = key_helper[off_exp+i];
		}
		
		pub_sp = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
		pub_sp.setExponent(exp, (short)0, (short)exp.length);
		pub_sp.setModulus(mod, (short)0, (short)mod.length);
		
	}
	
	private void _doCheckServerResp(APDU apdu)
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] buffer_in = apdu.getBuffer();
			short offset = 5;
			byte length_response = (short)16;
			
			byte[]response = new byte[length_response];
			for(short i=0; i<length_response; i++)
			{
				response[i] = buffer_in[offset+i];
			}
			
			byte[] decrypted = new byte[16];
			AESencrypt.init(ks, Cipher.MODE_DECRYPT);
			AESencrypt.doFinal(response, (short)0, (short)response.length, decrypted, (short)0);
			
			byte[] challenge_check = {decrypted[12], decrypted[13], decrypted[14], decrypted[15]};
			challenge[3] = (byte) (challenge[3] + diff[3]);
			byte result = 2;
			
			for(short i=0; i<4;i++)
			{
				if(challenge[i]!=challenge_check[i])
				{
					ISOException.throwIt(SignalCodes.SW_CHALLENGE_FAILED);
					break;
				}
			}
			auth = 1;
			
			byte[] buffer_out = new byte[]{result};
			
			apdu.setOutgoing();
			
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}
	
	private void _doAuthCard(APDU apdu)
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
			// buffer contains Emsg
			byte[] buffer_in = apdu.getBuffer();			
			short offset = 5;
			byte length_response = (short)16;
			
			// First check if authentication = true
			if(auth!=1)
			{
				ISOException.throwIt(SignalCodes.SW_AUTHENTICATION_CARD_FAILED);
			}
			
			byte[]response = new byte[length_response];
			for(short i=0; i<length_response; i++)
			{
				response[i] = buffer_in[offset+i];
			}
			
			byte[] decrypted = new byte[16];
			AESencrypt.init(ks, Cipher.MODE_DECRYPT);
			AESencrypt.doFinal(response, (short)0, (short)response.length, decrypted, (short)0);
			
			byte[] to_hash = new byte[20]; // 20 = length decrypted + Auth.length
			
			for(short i=0; i<16; i++)
			{
				to_hash[i] = decrypted[i];
			}
			to_hash[16] = (byte)'A';
			to_hash[17] = (byte)'u';
			to_hash[18] = (byte)'t';
			to_hash[19] = (byte)'h';
			
			
			// Sign decrypted met private key Common
			// => First hash decrypt	
			MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			md.reset();
			byte[] hash = new byte[20];
			md.doFinal(to_hash, (short) 0, (short) to_hash.length, hash, (short) 0);
						
			Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			sig.init(card.getPrivateKeyCommon(), Signature.MODE_SIGN);
			byte[] signature = new byte[64];
			sig.sign(hash, (short)0, (short)hash.length, signature, (short)0);

			// for the sake of simplicty, we send the public key (= 64 bytes modulus and 3 bytes public exponent) to the middleware
			// instead of the whole certificate (sending more than 256 bytes at a time was a problem we couldn't solve on time)
			short encrypt_length = (short)(signature.length+mod_priv_co.length+exp_pub_co.length); 
			short needed = 0;
			
			byte[]extra = null;
			if(encrypt_length%16!=0)
			{
				needed = (short)(16-(encrypt_length%16));
				encrypt_length = (short)(encrypt_length+needed);
				extra = new byte[needed];
			}
			byte[] to_encrypt =  ByteBuffer.allocate(encrypt_length).put(mod_priv_co).put(exp_pub_co).put(signature).put(extra).array();
																						
			e_msg = new byte[encrypt_length];
			// encrypt the bytebuffer above
			AESencrypt.init(ks, Cipher.MODE_ENCRYPT);
			byte[] temp = new byte[16];
			
			short max = (short)(encrypt_length/16); 
			short current = 0;
			for(short i=0; i<max; i++)
			{
				// encrypt block per block
				AESencrypt.doFinal(to_encrypt, (short)(0+(current*16)), (short)16, temp, (short)0);
				Util.arrayCopy(temp, (short) 0, e_msg, (short)(0+(current*16)), (short) 16);
				current++;
			}
			
			byte[] buffer_out = e_msg;
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}
	
	private void _doAttributeQuery(APDU apdu) throws Exception
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
			// buffer contains Emsg
			byte[] buffer_in = apdu.getBuffer();			
			short offset = (short) 5; 
			short length = ByteBuffer.wrap(new byte[]{0x00, buffer_in[4]}).getShort();
			byte[] requested = new byte[length];
			byte result = 1;
			for(short i=0; i<length; i++)
			{
				requested[i] = buffer_in[offset+i];
			}
			
			// First check if authentication = true
			if(auth!=1)
			{
				ISOException.throwIt(SignalCodes.SW_AUTHENTICATION_CARD_FAILED);
			}
			
			byte domain_code = domain[1];
			if(!DataRestrictions.IsAllowedAccess(requested, domain_code))
				ISOException.throwIt(SignalCodes.SW_QUERY_RIGHTS_FAILED);
			
			// Construct nym
			MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			md.reset();
			byte[] hash = new byte[20];
			byte[] to_hash = ByteBuffer.allocate(rand_ks.length+card.getCertificateCommon().length).put(rand_ks).put(card.getCertificateCommon()).array();
			md.doFinal(to_hash, (short)0, (short) to_hash.length, hash, (short) 0);
			card.setNym(hash);
			
			// query results;
			QueryResolver res = new QueryResolver(card);
			byte[] results = res.resolveQuery(requested);		
					
			// Final data = nym + results: sym encrypt
			short encrypt_length = (short)(results.length+card.getNym().length+3); 
			short needed = 0;		
			byte[]extra = null;
			if(encrypt_length%16!=0)
			{
				needed = (short)(16-(encrypt_length%16));
				encrypt_length = (short)(encrypt_length+needed);
				extra = new byte[needed];
			}
			
			// Allways return nym + some extra field
			// One field= [QueryCode, length_datafield, datafield] => QueryCode = 1 byte, length_datafield = 2 bytes (short) => so always need 3 bytes + length of datafield
			byte[] final_data = ByteBuffer.allocate(card.getNym().length+results.length+3+needed).put((byte)0x00).putShort((short) card.getNym().length).put(card.getNym()).put(results).put(extra).array();		
			
			
			
			byte[] e_attributes = new byte[encrypt_length];
			// encrypt the bytebuffer above
			AESencrypt.init(ks, Cipher.MODE_ENCRYPT);
			byte[] temp = new byte[16];
			
			short max = (short)(encrypt_length/16); 
			short current = 0;
			for(short i=0; i<max; i++)
			{
				// encrypt block per block
				AESencrypt.doFinal(final_data, (short)(0+(current*16)), (short)16, temp, (short)0);
				Util.arrayCopy(temp, (short) 0, e_attributes, (short)(0+(current*16)), (short) 16);
				current++;
			}
			
			byte[] buffer_out = e_attributes;
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
		}
	}

	private void _getCardData(APDU apdu, byte[] item)
	{
		if(!pin.isValidated())ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
	        apdu.setOutgoing();
	        apdu.setOutgoingLength((short)item.length);
	        apdu.sendBytesLong(item,(short)0,(short)item.length);
		}
    }
	
	
}
