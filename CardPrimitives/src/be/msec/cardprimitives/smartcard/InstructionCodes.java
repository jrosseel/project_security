package be.msec.cardprimitives.smartcard;

public class InstructionCodes {

	public static final byte IDENTITY_CARD_CLA =(byte)0x80;
	
	public static final byte VALIDATE_PIN_INS = (byte)0x22;
	public static final byte VALIDATE_SERIAL_INS = (byte)0x25;
	public static final byte REQ_VALIDATION_INS= (byte)0x23;
	
	public static final byte GET_NAME_INS = (byte)0x24;
	public static final byte GET_SERIAL_INS = (byte)0x26;
	public static final byte DO_HELLO_INS = (byte)0x28;
	public static final byte GET_ADDRESS_INS = (byte)0x29;
	public static final byte GET_COUNTRY_INS = (byte)0x30;
	public static final byte GET_BIRTH_DATE_INS = (byte)0x31;
	public static final byte GET_AGE_INS = (byte)0x32;
	public static final byte GET_GENDER_INS = (byte)0x33;
	public static final byte GET_PHOTO_INS = (byte)0x34;
	public static final byte GET_SSN_INS = (byte)0x35;
	public static final byte DO_NEW_TIME_INS = (byte)0x36;
	public static final byte DO_AUTH_SP = (byte)0x37;		
	public static final byte DO_AUTH_CARD = (byte)0x38;
	public static final byte DO_AUTH_SP_STEP = (byte)0x39;
	public static final byte GET_AUTH_SER_EKEY = (byte)0x40;
	public static final byte GET_AUTH_SER_EMSG = (byte)0x41;
	public static final byte DO_CHECK_SERVER_RESP = (byte)0x42;
	public static final byte DO_ATTRIBUTE_QUERY = (byte)0x43;
	
	public final static byte PIN_TRY_LIMIT =(byte)0x03;
	public final static byte PIN_SIZE =(byte)0x04;
	
	
}
