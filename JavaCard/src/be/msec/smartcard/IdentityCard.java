package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.RSAPrivateKey;

public class IdentityCard extends Applet {
	
	private CardData card;
    private final byte[] sigma;
	private byte[] serial = new byte[]{(byte)0x4A, (byte)0x61, (byte)0x6e};
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
		
		sigma = new byte[]{56, 54, 52, 48, 48, 48, 48, 48}; // 1 day = 86400000 milliseconds 
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
		if (buffer[ISO7816.OFFSET_CLA] != InstructionCodes.IDENTITY_CARD_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(buffer[ISO7816.OFFSET_CLA] == InstructionCodes.VALIDATE_PIN_INS)
			_validatePIN(apdu);
	
		else if(buffer[ISO7816.OFFSET_LC] == InstructionCodes.DO_HELLO_TIME)
			_doHelloTime(apdu);
		else
		{
			_ensurePinValidity();
			_executeInstruction(apdu, buffer);
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
				ISOException.throwIt(InstructionCodes.SW_VERIFICATION_FAILED);
		}
		else 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	/**
	 * Ensures the execution can only continue if the PIN is valid.
	 */
	private void _ensurePinValidity() 
	{
		// If the pin is not validated, a response APDU with the
		//	'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())
			ISOException.throwIt(InstructionCodes.SW_PIN_VERIFICATION_REQUIRED);
	}

	/**
	 * Executes the current instruction
	 */
	private void _executeInstruction(APDU apdu, byte[] buffer) 
	{
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS])
		{
				
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
				
			//If no matching instructions are found it is indicated in the status word of the response.
			//This can be done by using this method. As an argument a short is given that indicates
			//  the type of warning. There are several predefined warnings in the 'ISO7816' class.
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	// Methods
	
	
	private void _doHelloTime(APDU apdu)
	{

		byte[] buffer = apdu.getBuffer();

		// Lc byte denotes the number of bytes in the data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		byte byteRead = (byte)(apdu.setIncomingAndReceive());
		
		// it is an error if the number of data bytes read does not match the number in Lc byte
		if ( ( numBytes != 1 ) || (byteRead != 1) )
		 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		// Hello
		byte[] hello = new byte[]{72, 101, 108, 108, 111};
		// Justify offset to get the current time
		for(short i = 0; i < hello.length; i++){
			if(buffer[ISO7816.OFFSET_CDATA + i] != hello[i]) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		short time_length = (short) card.getLastValidationTime().length;
		byte new_timestamp = 0;
		for(short i=0; i<time_length; i++)
		{
			if(card.getLastValidationTime()[i]<(buffer[i]-sigma[i]))
			{
				// new timestamp needed
				new_timestamp = 1;
			}
		}
		
		// Send response to middleware
		short Le = apdu.setOutgoing();	
		apdu.setOutgoingLength(Le);
		buffer[0] = new_timestamp;
		apdu.sendBytes((short) 0, Le);

    }
		
	private void _getCardData(APDU apdu, byte[] item)
	{
		//This sequence of three methods sends the data contained in
		//'serial' with offset '0' and length 'serial.length'
		//to the host application.
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)item.length);
        apdu.sendBytesLong(item,(short)0,(short)item.length);
    }
}
