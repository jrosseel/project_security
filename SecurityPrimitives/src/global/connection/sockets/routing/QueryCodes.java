package global.connection.sockets.routing;

/**
 * Contains query codes. These highlight which data is requested.
 */
//Class mirrored in be.msec.cardprimitives
public class QueryCodes
{
	public static final byte NYM 				= (byte) 0x00;
	public static final byte NAME_REQUEST 		= (byte) 0x01;
	public static final byte ADDRESS_REQUEST 	= (byte) 0x02;
	public static final byte COUNTRY_REQUEST 	= (byte) 0x03;
	public static final byte BIRTHDATE_REQUEST 	= (byte) 0x04;
	public static final byte AGE_REQUEST 		= (byte) 0x05;
	public static final byte GENDER_REQUEST 	= (byte) 0x06;
	public static final byte PHOTO_REQUEST 		= (byte) 0x07;
	public static final byte SSN_REQUEST 		= (byte) 0x08;
	
	public static final byte STOP 				= (byte) 0x11;
}
