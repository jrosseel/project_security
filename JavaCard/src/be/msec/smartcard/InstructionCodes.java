package be.msec.smartcard;

public class InstructionCodes {

	public static final byte IDENTITY_CARD_CLA =(byte)0x80;
	
	public static final byte VALIDATE_PIN_INS = 0x22;
	public static final byte VALIDATE_SERIAL_INS = 0x25;
	public static final byte REQ_VALIDATION_INS= 0x23;
	
	public static final byte GET_NAME_INS = 0x24;
	public static final byte GET_SERIAL_INS = 0x26;
	public static final byte DO_HELLO_TIME = 0x28;
	public static final byte GET_ADDRESS_INS = 0x29;
	public static final byte GET_COUNTRY_INS = 0x30;
	public static final byte GET_BIRTH_DATE_INS = 0x31;
	public static final byte GET_AGE_INS = 0x32;
	public static final byte GET_GENDER_INS = 0x33;
	public static final byte GET_PHOTO_INS = 0x34;
	public static final byte GET_SSN_INS = 0x35;
	public final static byte PIN_TRY_LIMIT =(byte)0x03;
	public final static byte PIN_SIZE =(byte)0x04;
	
	public final static byte GET_TIMESTAP_DATA=(byte)0x09;
		
	public final static short SW_VERIFICATION_FAILED = 0x6300;
	public final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
}
