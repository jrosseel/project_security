package be.msec.smartcard;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;

import java.security.PublicKey;

public class IdentityCard extends Applet {
	
	private CardData card;
    private final byte[] sigma;
    private final byte[] mod_pub_gov = new byte[]{(byte)0xc7, (byte)0x0e, (byte)0x54, (byte)0x1a, (byte)0x2e, (byte)0x2e, (byte)0x12, (byte)0xa9, (byte)0xbb, (byte)0x04, (byte)0x2b, (byte)0x36, (byte)0x05, (byte)0x5b, (byte)0xbf, (byte)0x2b, (byte)0xc9, (byte)0x5d, (byte)0xf0, (byte)0x78, (byte)0x2c, (byte)0xef, (byte)0x9a, (byte)0x55, (byte)0x48, (byte)0x3f, (byte)0x3c, (byte)0x09, (byte)0x06, (byte)0x3f, (byte)0xed, (byte)0xed, (byte)0x23, (byte)0x68, (byte)0xcc, (byte)0x92, (byte)0xdc, (byte)0x8f, (byte)0x14, (byte)0xbb, (byte)0x13, (byte)0x32, (byte)0xf4, (byte)0x4e, (byte)0x7f, (byte)0x8b, (byte)0x3b, (byte)0x09, (byte)0x7f, (byte)0x35, (byte)0xca, (byte)0x2c, (byte)0x5c, (byte)0x1a, (byte)0x49, (byte)0x40, (byte)0xef, (byte)0xa4, (byte)0xaa, (byte)0xe6, (byte)0x78, (byte)0x52, (byte)0xb8, (byte)0xc3};
    private final byte[] exp_pub_gov = new byte[]{(byte)0x01, (byte)0x00, (byte)0x01};
    private final byte[] mod_pub_ca = new byte[]{(byte)0x00, (byte)0xb5, (byte)0x70, (byte)0x78, (byte)0xa8, (byte)0xf3, (byte)0x02, (byte)0xae, (byte)0x31, (byte)0xec, (byte)0xe9, (byte)0x63, (byte)0x07, (byte)0x9c, (byte)0x0b, (byte)0x60, (byte)0x8e, (byte)0x88, (byte)0xc2, (byte)0x1c, (byte)0x5f, (byte)0x01, (byte)0x78, (byte)0x5d, (byte)0xb4, (byte)0xae, (byte)0x0e, (byte)0xad, (byte)0xa0, (byte)0xe7, (byte)0x1e, (byte)0xe4, (byte)0x9c, (byte)0xa4, (byte)0x34, (byte)0x66, (byte)0xf1, (byte)0xf1, (byte)0xec, (byte)0x02, (byte)0x9a, (byte)0x5b, (byte)0x23, (byte)0x6f, (byte)0x56, (byte)0x8b, (byte)0xd9, (byte)0x1a, (byte)0x23, (byte)0x65, (byte)0x2f, (byte)0x32, (byte)0xbe, (byte)0xfe, (byte)0xd5, (byte)0x43, (byte)0x61, (byte)0x7c, (byte)0x10, (byte)0xc4, (byte)0x46, (byte)0xa8, (byte)0x20, (byte)0x71, (byte)0x4e, (byte)0xac, (byte)0x37, (byte)0x3b, (byte)0xdd, (byte)0xb7, (byte)0x96, (byte)0xa4, (byte)0x46, (byte)0x1c, (byte)0x74, (byte)0x4d, (byte)0x33, (byte)0xdc, (byte)0x45, (byte)0xbf, (byte)0xfa, (byte)0x6e, (byte)0xe8, (byte)0x65, (byte)0xc1, (byte)0x68, (byte)0x8f, (byte)0xd3, (byte)0x07, (byte)0x0c, (byte)0x67, (byte)0x56, (byte)0x27, (byte)0x3d, (byte)0x73, (byte)0x21, (byte)0xe2, (byte)0x6b, (byte)0x72, (byte)0x6d, (byte)0x09, (byte)0x25, (byte)0x20, (byte)0x69, (byte)0xc3, (byte)0xdb, (byte)0xbb, (byte)0x9c, (byte)0x6b, (byte)0xe1, (byte)0x6b, (byte)0xbb, (byte)0x19, (byte)0xd1, (byte)0x7d, (byte)0xaa, (byte)0xbe, (byte)0x97, (byte)0xb9, (byte)0x10, (byte)0xb1, (byte)0x5a, (byte)0xc4, (byte)0xf5, (byte)0x5f, (byte)0x17, (byte)0x75, (byte)0x42, (byte)0x89, (byte)0x57, (byte)0x77, (byte)0xf6, (byte)0x62, (byte)0x01, (byte)0x8d, (byte)0xbf, (byte)0x1e, (byte)0xce, (byte)0xe5, (byte)0x80, (byte)0x9c, (byte)0xd9, (byte)0x77, (byte)0x84, (byte)0xee, (byte)0xc8, (byte)0x85, (byte)0x32, (byte)0xf9, (byte)0x5d, (byte)0x64, (byte)0x7d, (byte)0x77, (byte)0x84, (byte)0x42, (byte)0xab, (byte)0x30, (byte)0x23, (byte)0x90, (byte)0x53, (byte)0x2a, (byte)0x36, (byte)0x62, (byte)0x6a, (byte)0xbe, (byte)0x1b, (byte)0xe4, (byte)0x1d, (byte)0xf8, (byte)0xcc, (byte)0x93, (byte)0x45, (byte)0x1a, (byte)0xc0, (byte)0xfb, (byte)0x61, (byte)0x96, (byte)0x05, (byte)0xb2, (byte)0xb4, (byte)0x26, (byte)0x80, (byte)0xb4, (byte)0x2e, (byte)0x81, (byte)0xb1, (byte)0xd2, (byte)0xd1, (byte)0x22, (byte)0xef, (byte)0x8c, (byte)0xf9, (byte)0x3d, (byte)0x67, (byte)0xd9, (byte)0x19, (byte)0xf5, (byte)0xc5, (byte)0xe7, (byte)0x0a, (byte)0xab, (byte)0xff, (byte)0xec, (byte)0x86, (byte)0xba, (byte)0x04, (byte)0x21, (byte)0x5c, (byte)0x4d, (byte)0x08, (byte)0xe1, (byte)0x25, (byte)0x93, (byte)0x56, (byte)0xc1, (byte)0x10, (byte)0xa6, (byte)0x6b, (byte)0x87, (byte)0xce, (byte)0x57, (byte)0xe6, (byte)0xde, (byte)0xf9, (byte)0xd0, (byte)0xc3, (byte)0x99, (byte)0xa0, (byte)0x3f, (byte)0xa4, (byte)0x5f, (byte)0x2d, (byte)0x21, (byte)0x7b, (byte)0xbd, (byte)0xa6, (byte)0x25, (byte)0x9f, (byte)0x53, (byte)0xc6, (byte)0x7f, (byte)0x6e, (byte)0x60, (byte)0xf6, (byte)0xbb, (byte)0xf5, (byte)0x76, (byte)0x69, (byte)0x21, (byte)0x69, (byte)0x19, (byte)0x2d, (byte)0xf6, (byte)0x1c, (byte)0x11, (byte)0xa2, (byte)0x43, (byte)0xf6, (byte)0x84, (byte)0x6f, (byte)0x3b, (byte)0x1b, (byte)0xc5, (byte)0xd7, (byte)0xef, (byte)0xc0, (byte)0xb3, (byte)0xcb, (byte)0xe2, (byte)0xd7, (byte)0x0f, (byte)0x7c, (byte)0xc3, (byte)0xac, (byte)0x1f, (byte)0xca, (byte)0xb0, (byte)0xad, (byte)0x44, (byte)0x8a, (byte)0x97, (byte)0x05, (byte)0xd9, (byte)0xb2, (byte)0xba, (byte)0x36, (byte)0xca, (byte)0x9d, (byte)0x62, (byte)0xdd, (byte)0x36, (byte)0xb5, (byte)0x28, (byte)0xb8, (byte)0x09, (byte)0xf3, (byte)0xd9, (byte)0xd4, (byte)0xa8, (byte)0x09, (byte)0x2b, (byte)0x66, (byte)0xda, (byte)0xdd, (byte)0x89, (byte)0x5a, (byte)0x84, (byte)0xd8, (byte)0xf1, (byte)0xc3, (byte)0x9b, (byte)0x20, (byte)0xe3, (byte)0x91, (byte)0xf6, (byte)0x3a, (byte)0x2f, (byte)0x02, (byte)0xee, (byte)0xe8, (byte)0xd7, (byte)0x1c, (byte)0x53, (byte)0x6f, (byte)0x12, (byte)0xb0, (byte)0x54, (byte)0x2a, (byte)0x06, (byte)0x80, (byte)0x8c, (byte)0x49, (byte)0xcd, (byte)0xcd, (byte)0x87, (byte)0x29, (byte)0x39, (byte)0xec, (byte)0x89, (byte)0x16, (byte)0xc1, (byte)0x72, (byte)0x73, (byte)0xa5, (byte)0x40, (byte)0x6c, (byte)0xec, (byte)0x24, (byte)0x12, (byte)0xe2, (byte)0xae, (byte)0xde, (byte)0x02, (byte)0x32, (byte)0xa9, (byte)0xcb, (byte)0xa4, (byte)0x95, (byte)0x09, (byte)0x30, (byte)0x5f, (byte)0x67, (byte)0x47, (byte)0x35, (byte)0x5f, (byte)0x12, (byte)0x0f, (byte)0x7e, (byte)0x04, (byte)0xd4, (byte)0x2b, (byte)0xf0, (byte)0x15, (byte)0x81, (byte)0x20, (byte)0xa6, (byte)0x6e, (byte)0x58, (byte)0x82, (byte)0x05, (byte)0x14, (byte)0xed, (byte)0x36, (byte)0x8b, (byte)0xd6, (byte)0xd1, (byte)0x23, (byte)0xdb, (byte)0xcf, (byte)0xfe, (byte)0xe4, (byte)0x51, (byte)0x30, (byte)0x23, (byte)0x1f, (byte)0x8e, (byte)0xcb, (byte)0xa2, (byte)0x2d, (byte)0xc6, (byte)0x65, (byte)0xac, (byte)0x42, (byte)0x18, (byte)0x55, (byte)0x94, (byte)0x7b, (byte)0xae, (byte)0x7d, (byte)0x72, (byte)0x18, (byte)0x56, (byte)0x05, (byte)0x58, (byte)0x78, (byte)0x14, (byte)0xc7, (byte)0xe3, (byte)0x0a, (byte)0x2c, (byte)0x99, (byte)0xa9, (byte)0x64, (byte)0x48, (byte)0x12, (byte)0xd4, (byte)0x97, (byte)0x1e, (byte)0x14, (byte)0x8f, (byte)0x48, (byte)0x79, (byte)0xc2, (byte)0x3b, (byte)0x3a, (byte)0xd6, (byte)0x20, (byte)0x15, (byte)0x7c, (byte)0x76, (byte)0x34, (byte)0x6e, (byte)0x53, (byte)0x4c, (byte)0x67, (byte)0xe3, (byte)0x96, (byte)0x47, (byte)0xc2, (byte)0xf7, (byte)0xc2, (byte)0xe7, (byte)0xa1, (byte)0x0a, (byte)0xed, (byte)0x22, (byte)0x5f, (byte)0x94, (byte)0xd7, (byte)0xce, (byte)0xca, (byte)0xf6, (byte)0x01, (byte)0x8f, (byte)0x93, (byte)0xfa, (byte)0xc2, (byte)0x55, (byte)0xb7, (byte)0xe7, (byte)0x41, (byte)0xd6, (byte)0x5e, (byte)0x51, (byte)0x09, (byte)0x21, (byte)0xa6, (byte)0x4d, (byte)0x37, (byte)0xb2, (byte)0x27, (byte)0xe7, (byte)0x8f, (byte)0x9a, (byte)0xf4, (byte)0x98, (byte)0xf8, (byte)0xc7, (byte)0x9c, (byte)0xc8, (byte)0x95, (byte)0x2a, (byte)0x54, (byte)0x3a, (byte)0xfa, (byte)0xa6, (byte)0x6c, (byte)0x92, (byte)0x6e, (byte)0xd2, (byte)0x6e, (byte)0xff, (byte)0x29, (byte)0x9b, (byte)0xd2, (byte)0xa3, (byte)0xd4, (byte)0x5a, (byte)0x97, (byte)0x05, (byte)0x29, (byte)0xf8, (byte)0x93};
    private final byte[] exp_pub_ca = new byte[]{(byte)0x01, (byte)0x00, (byte)0x01};
    private OwnerPIN pin;
	
	//input above instance variables into info below
	private byte[] info;
	private short incomingData;
	//	private short newPin;
	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 */
		pin = new OwnerPIN(InstructionCodes.PIN_TRY_LIMIT,InstructionCodes.PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, InstructionCodes.PIN_SIZE); 
		
		sigma = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5C, 0x00 }; // 1 day = 86400000 milliseconds 
				
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
		
		// AES key user
		AESKey ku;
		ku = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		// key = nLkAZn239Fja230P
		ku.setKey(new byte[]{(byte)0x6e, (byte)0x4c, (byte)0x6b, (byte)0x41, (byte)0x5a, (byte)0x6e, (byte)0x32, (byte)0x33, (byte)0x39, (byte)0x46, (byte)0x6a, (byte)0x61, (byte)0x32, (byte)0x33, (byte)0x30, (byte)0x50}, (short)0);
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
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 * @throws CryptoException 
	 */
	private void _executeInstruction(APDU apdu, byte[] buffer) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, CryptoException, InvalidKeySpecException 
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
			case InstructionCodes.DO_AUTH_SP:
				_doAuthSP(apdu);
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
			
			short length_hello = 5;
			short offset = (short) (ISO7816.OFFSET_CDATA+length_hello); 
			
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
			}

			byte[] buffer_out = new byte[]{result};
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}	
	
	private void _doAuthSP(APDU apdu)
	{
		if ( ! pin.isValidated()) ISOException.throwIt(SignalCodes.SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] buffer_in = apdu.getBuffer();			
			
			// possibly do multiple loops to get all data from certificate
			
			// store signature somewhere
			
			// hash the certificate
			MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			md.reset();
			byte[] hash = new byte[20];
			//md.doFinal(time, (short) 0, (short) time.length, hash, (short) 0);
			
			// verify signature. Use public key ca
			
			Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			sig.init(card.getPublicKeyCA(), Signature.MODE_VERIFY);
			byte result = 2;
			//if(sig.verify(hash, (short)0, (short)hash.length, signature, (short)0, (short)signature.length))
			//{
				result = 1;
				// check if end time certificate < lastValidationTime
				
				// if so, abort
				
				// else: Ks = new symmetric key with secure random
				RandomData rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM); 
				byte[] secure_rand = new byte[20];
				rnd.generateData(secure_rand, (short) 0, (short)secure_rand.length);
				AESKey ks;
				ks = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
				ks.setKey(secure_rand, (short)0);
				
				// get public key of SP out of certificate
				// use this key to asymmetric encrypt (Ekey) symmetric key ks
				
				// generate challenge = secure random number
				byte[] challenge = new byte[20];
				rnd.generateData(challenge, (short)0, (short)challenge.length);
				
				// symmetric encryption Emsg = [c, SubjectOfSP] with Ks
				
				// Send Emsg and Ekey to Middleware and later on to the SP
				
				
			//}
			//else
			//{
			//	result = 0;
			//}

			byte[] buffer_out = new byte[]{result};
			
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
