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
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;

import java.security.PublicKey;

public class IdentityCard extends Applet {
	
	private CardData card;
    private final byte[] sigma;
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
		else{
			byte[] buffer_in = apdu.getBuffer();
			
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
			short offset_time = (short) (ISO7816.OFFSET_CDATA); 
			short offset_signature = (short) (offset_time+length_time);
			byte result=2;
			
			byte[] time = new byte[length_time];
			byte[] signature = new byte[length_signature];
			
			// fill bytearray time
			for(short i=0; i<length_time;i++)
			{
				time[i] = buffer_in[offset_time+i];
			}
			// fill bytearray signature
			for(short i=0; i<length_time;i++)
			{
				signature[i] = buffer_in[offset_signature+i];
			}
			// hash time
			MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			md.reset();
			byte[] hash = new byte[64];
			md.doFinal(time, (short) 0, (short) time.length, hash, (short) 0);
			Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
									
			// gives an error => see how to create public key from byte array
			/*sig.init((Key)getPublicKeyGov(), Signature.MODE_VERIFY);
			if(sig.verify(hash, (short)0, (short)hash.length, signature, (short)0, (short)signature.length))
			{
				result = 1;
				// Only to test. If it works => update validation time
			}
			{
				result = 0;
			}*/

			byte[] buffer_out = new byte[]{result};
			
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)buffer_out.length);
			apdu.sendBytesLong(buffer_out,(short)0,(short)buffer_out.length);
			
		}
	}
	
	public PublicKey getPublicKeyGov() throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(card.getPublicKeyGovernment());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey gov = keyFactory.generatePublic(pubKeySpec);
		return gov;
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
