package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.RSAPrivateKey;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte VALIDATE_SERIAL_INS = 0x25;
	private static final byte REQ_VALIDATION_INS= 0x23;
	
	private static final byte GET_NAME_INS = 0x24;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte DO_HELLO_TIME = 0x28;
	private static final byte GET_ADDRESS_INS = 0x29;
	private static final byte GET_COUNTRY_INS = 0x30;
	private static final byte GET_BIRTH_DATE_INS = 0x31;
	private static final byte GET_AGE_INS = 0x32;
	private static final byte GET_GENDER_INS = 0x33;
	private static final byte GET_PHOTO_INS = 0x34;
	private static final byte GET_SSN_INS = 0x35;
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	// Timestap on card
	private final static byte GET_TIMESTAP_DATA=(byte)0x09;
		
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	// certificates: EDIT!
    private byte[] certificateCA = new byte[]{48, -126, 2, -128, 48, -126, 2, 42, -96, 3, 2, 1, 2, 2, 9, 0, -74, -62, -61, -98, 13, -50, 20, -91, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 48, -127, -103, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 24, 48, 22, 6, 3, 85, 4, 8, 12, 15, 79, 111, 115, 116, 45, 86, 108, 97, 97, 110, 100, 101, 114, 101, 110, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 90, 117, 108, 116, 101, 49, 22, 48, 20, 6, 3, 85, 4, 10, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 22, 48, 20, 6, 3, 85, 4, 3, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 48, 48, 46, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 1, 22, 33, 109, 105, 99, 104, 105, 101, 108, 46, 100, 104, 111, 110, 116, 64, 115, 116, 117, 100, 101, 110, 116, 46, 107, 117, 108, 101, 117, 118, 101, 110, 46, 98, 101, 48, 30, 23, 13, 49, 55, 48, 51, 49, 53, 49, 53, 53, 52, 50, 55, 90, 23, 13, 50, 50, 48, 51, 49, 53, 49, 53, 53, 52, 50, 55, 90, 48, -127, -103, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 24, 48, 22, 6, 3, 85, 4, 8, 12, 15, 79, 111, 115, 116, 45, 86, 108, 97, 97, 110, 100, 101, 114, 101, 110, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 90, 117, 108, 116, 101, 49, 22, 48, 20, 6, 3, 85, 4, 10, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 22, 48, 20, 6, 3, 85, 4, 3, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 48, 48, 46, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 1, 22, 33, 109, 105, 99, 104, 105, 101, 108, 46, 100, 104, 111, 110, 116, 64, 115, 116, 117, 100, 101, 110, 116, 46, 107, 117, 108, 101, 117, 118, 101, 110, 46, 98, 101, 48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2, 65, 0, -77, -52, -115, -111, 104, -62, -67, 70, 112, -63, 23, 105, -82, 86, -12, 54, 120, 104, 80, -100, -67, 78, 5, 58, -58, -86, 105, -13, 84, -35, 126, -65, -127, 107, 10, 8, -23, -77, -23, 45, 19, 112, -43, 8, 73, -87, 46, -57, 12, -110, 125, -100, -98, 95, 71, 18, -35, 46, 65, 37, 81, 126, 78, -3, 2, 3, 1, 0, 1, -93, 83, 48, 81, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, -69, -18, 126, 17, -78, 103, -43, 9, 2, -83, 98, -48, -48, -12, -44, 63, -118, -40, 80, 70, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, -128, 20, -69, -18, 126, 17, -78, 103, -43, 9, 2, -83, 98, -48, -48, -12, -44, 63, -118, -40, 80, 70, 48, 15, 6, 3, 85, 29, 19, 1, 1, -1, 4, 5, 48, 3, 1, 1, -1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 3, 65, 0, 104, 15, 61, 29, 8, 44, -92, -33, -4, 42, 92, -103, 39, 5, 101, -43, 81, -84, 34, -12, 54, 5, -8, 4, 79, -90, 51, 70, 69, 98, 29, -75, -126, -47, -102, -68, -73, -103, 93, -54, -116, 110, -68, 37, 125, -28, -107, 14, -2, -91, 72, -62, -126, 124, 1, 78, -110, -14, 15, -52, -63, -24, -89, 46};
    private byte[] certificateCommon = new byte[]{48, -126, 2, 32, 48, -126, 1, -54, 2, 1, 1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 48, -127, -103, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 24, 48, 22, 6, 3, 85, 4, 8, 12, 15, 79, 111, 115, 116, 45, 86, 108, 97, 97, 110, 100, 101, 114, 101, 110, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 90, 117, 108, 116, 101, 49, 22, 48, 20, 6, 3, 85, 4, 10, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 22, 48, 20, 6, 3, 85, 4, 3, 12, 13, 77, 105, 99, 104, 105, 101, 108, 32, 68, 104, 111, 110, 116, 49, 48, 48, 46, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 1, 22, 33, 109, 105, 99, 104, 105, 101, 108, 46, 100, 104, 111, 110, 116, 64, 115, 116, 117, 100, 101, 110, 116, 46, 107, 117, 108, 101, 117, 118, 101, 110, 46, 98, 101, 48, 30, 23, 13, 49, 55, 48, 51, 49, 53, 49, 54, 51, 49, 51, 53, 90, 23, 13, 49, 57, 48, 51, 49, 53, 49, 54, 51, 49, 51, 53, 90, 48, -127, -101, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 24, 48, 22, 6, 3, 85, 4, 8, 12, 15, 79, 111, 115, 116, 45, 86, 108, 97, 97, 110, 100, 101, 114, 101, 110, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 90, 117, 108, 116, 101, 49, 15, 48, 13, 6, 3, 85, 4, 10, 12, 6, 99, 111, 109, 109, 111, 110, 49, 15, 48, 13, 6, 3, 85, 4, 11, 12, 6, 99, 111, 109, 109, 111, 110, 49, 14, 48, 12, 6, 3, 85, 4, 3, 12, 5, 107, 97, 97, 114, 116, 49, 48, 48, 46, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 1, 22, 33, 109, 105, 99, 104, 105, 101, 108, 46, 100, 104, 111, 110, 116, 64, 115, 116, 117, 100, 101, 110, 116, 46, 107, 117, 108, 101, 117, 118, 101, 110, 46, 98, 101, 48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2, 65, 0, -58, 88, -3, -67, -12, 108, 65, -122, 16, 33, 47, -51, 105, 122, -89, 20, -29, -85, -89, 14, -57, -58, -118, 61, 105, -40, -15, 14, -117, 42, -87, 93, 74, 104, -52, 114, 91, -14, -87, 90, 86, 44, -20, 111, 63, 64, 2, -7, 65, -6, -42, -59, 32, 20, -36, -5, 57, -89, -61, -79, 10, -43, 82, -73, 2, 3, 1, 0, 1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 3, 65, 0, 86, -125, -124, 27, -123, 122, -41, 84, 90, 17, -39, 78, -23, 61, 63, 86, 90, -121, 56, 92, 71, -7, 106, -22, 69, -30, 2, 3, -110, 48, -64, 106, 95, -97, 58, 103, 86, -88, 21, -5, -54, 32, -11, 4, -23, -60, -36, 76, 76, -83, -71, -82, 121, 81, -106, -40, -19, 51, -31, -118, 33, 49, -98, -43};
	
	private byte[] serial = new byte[]{(byte)0x4A, (byte)0x61, (byte)0x6e};
	private OwnerPIN pin;
	
	// Personal info stored on card
	private byte[] last_validation_time;
	private byte[] sigma;
	private byte[] nym_egov_1; // unique identifier user by first service provider eGov
	private byte[] nym_egov_2;
	private byte[] nym_socnet_1;
	private byte[] nym_socnet_2;
	private byte[] nym_default_1;
	private byte[] nym_default_2;
	private byte[] nym_health_1; // our own created domain = healthcare
	private byte[] nym_health_2;
	private byte[] name;
	private byte[] address;
	private byte[] country;
	private byte[] birth_date;
	private byte[] age;
	private byte[] gender;
	private byte[] photo;
	private byte[] ssn;
	private RSAPrivateKey skey;
	
	//input above instance variables into info below
	private byte[] info;
	private short incomingData;
	//	private short newPin;
	
	
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE); // => miliseconds gebruiken?
		
		// Data of person
		last_validation_time  = new byte[]{49, 52, 57, 53, 50, 57, 54, 54, 52, 53, 48, 48, 48}; // 2017/05/20 18:10:45 in milliseconds = 1495296645000
		sigma = new byte[]{56, 54, 52, 48, 48, 48, 48, 48}; // 1 day = 86400000 milliseconds 
		name = new byte[]{70, 114, 97, 110, 107, 105, 101, 32, 76, 111, 111, 115, 118, 101, 108, 100}; // Frankie Loosveld
		address = new byte[]{69, 105, 108, 97, 110, 100, 108, 97, 97, 110, 32, 52, 53}; // Eilandlaan 45
		country = new byte[]{66, 69, 76, 71, 73, 85, 77}; // BELGIUM
		birth_date = new byte[]{51, 48, 47, 49, 50, 47, 49, 57, 54, 53}; // 30/12/1965
		age = new byte[]{53, 50}; // 52
		gender = new byte[]{77}; // M
		photo = new byte[]{104, 116, 116, 112, 58, 47, 47, 103, 105, 100, 115, 101, 110, 107, 111, 110, 116, 105, 99,
							104, 46, 98, 101, 47, 119, 112, 45, 99, 111, 110, 116, 101, 110, 116, 47, 117, 112, 108, 111, 
							97, 100, 115, 47, 50, 48, 49, 53, 47, 49, 48, 47, 70, 114, 97, 110, 107, 105, 101, 95, 76, 111, 
							111, 115, 118, 101, 108, 100, 46, 106, 112, 103}; 
							// http://gidsenkontich.be/wp-content/uploads/2015/10/Frankie_Loosveld.jpg
		ssn = new byte[]{54, 53, 49, 50, 51, 48, 56, 48, 48, 52, 48}; // 65123080040
		
		// CREATE PRIVATE KEY
		
		
		
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new IdentityCard();
	}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
			return;
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_NAME_INS:
			getName(apdu);
			break;
		case GET_ADDRESS_INS:
			getAddress(apdu);
			break;
		case GET_COUNTRY_INS:
			getCountry(apdu);
			break;
		case GET_BIRTH_DATE_INS:
			getBirthDate(apdu);
			break;
		case GET_AGE_INS:
			getAge(apdu);
			break;
		case GET_GENDER_INS:
			getGender(apdu);
			break;
		case GET_SSN_INS:
			getSSN(apdu);
			break;
		case GET_PHOTO_INS:
			getPhoto(apdu);
			break;
		case DO_HELLO_TIME:
			doHelloTime(apdu);
			break;
			
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
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
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the serial number.
	 */
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'serial' with offset '0' and length 'serial.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}	
	
	private void doHelloTime(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
    		byte[] buffer = apdu.getBuffer();
			//byte Lc = buffer[ISO7816.OFFSET_LC];			
			//byte bytesRead = (byte) apdu.setIncomingAndReceive();
			//if(bytesRead != Lc) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
			// Incoming= "Hello[TimeMilliseconds]"			
			//byte[] hello_string = new byte[]{72, 101, 108, 108, 111};
			
        }
    }
	
	private void getName(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)name.length);
            apdu.sendBytesLong(name,(short)0,(short)name.length);
        }
    }
	
	private void getAddress(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)address.length);
            apdu.sendBytesLong(address,(short)0,(short)address.length);
        }
    }
	
	private void getCountry(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)country.length);
            apdu.sendBytesLong(country,(short)0,(short)country.length);
        }
    }
	
	private void getBirthDate(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)birth_date.length);
            apdu.sendBytesLong(birth_date,(short)0,(short)birth_date.length);
        }
    }
	
	private void getAge(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)age.length);
            apdu.sendBytesLong(age,(short)0,(short)age.length);
        }
    }
	
	private void getGender(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)gender.length);
            apdu.sendBytesLong(gender,(short)0,(short)gender.length);
        }
    }
	
	private void getSSN(APDU apdu){
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)ssn.length);
            apdu.sendBytesLong(ssn,(short)0,(short)ssn.length);
        }
    }
	
	private void getPhoto(APDU apdu){
		// OPDELEN IN BLOKKEN
        if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)photo.length);
            apdu.sendBytesLong(photo,(short)0,(short)photo.length);
        }
    }
	
	private void setCurrentTime(APDU apdu){
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte buffer[] = apdu.getBuffer();
			

			// Lc byte denotes the number of bytes in the
			// data field of the command APDU
			byte numBytes = buffer[ISO7816.OFFSET_LC];
			// indicate that this APDU has incoming data
			// and receive data starting from the offset
			// ISO7816.OFFSET_CDATA following the 5 header
			// bytes.			
			
		}
	}
}
