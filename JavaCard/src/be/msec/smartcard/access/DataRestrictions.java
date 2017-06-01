package be.msec.smartcard.access;

import be.msec.cardprimitives.smartcard.Domains;
import be.msec.cardprimitives.smartcard.QueryCodes;

public class DataRestrictions 
{
	private static final byte[] DEFAULT_ALLOWED 	= new byte[] { QueryCodes.NYM, QueryCodes.AGE_REQUEST };
	private static final byte[] GOVERNMENT_ALLOWED 	= new byte[] { QueryCodes.NYM, QueryCodes.NAME_REQUEST, QueryCodes.COUNTRY_REQUEST, QueryCodes.BIRTHDATE_REQUEST, QueryCodes.AGE_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.SSN_REQUEST};
	private static final byte[] SOCNET_ALLOWED 		= new byte[] { QueryCodes.NYM, QueryCodes.NAME_REQUEST, QueryCodes.COUNTRY_REQUEST, QueryCodes.AGE_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.PHOTO_REQUEST };
	private static final byte[] HEALTHCARE_ALLOWED	= new byte[] { QueryCodes.NYM, QueryCodes.NAME_REQUEST, QueryCodes.COUNTRY_REQUEST, QueryCodes.BIRTHDATE_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.PHOTO_REQUEST, QueryCodes.SSN_REQUEST };
	
	public static boolean IsAllowedAccess(byte[] requestedAttributes, byte domain) {
		boolean access = true;
		
		for(int i = 0; i < requestedAttributes.length; i++)
			access = access && _requestAllowedAccess(requestedAttributes[i], domain);
		
		return access;
	}
	
	public static boolean _requestAllowedAccess(byte requestedAttributeCode, byte domain) 
	{
		switch(domain)
		{
		case Domains.Default:
			return _member(requestedAttributeCode, DEFAULT_ALLOWED);

		case Domains.Government:
			return _member(requestedAttributeCode, GOVERNMENT_ALLOWED);

		case Domains.SocialNet:
			return _member(requestedAttributeCode, SOCNET_ALLOWED);

		case Domains.Healthcare:
			return _member(requestedAttributeCode, HEALTHCARE_ALLOWED);
		}
		
		return false;
	}

	private static boolean _member(byte request, byte[] allowed) {
		for(short i = 0; i < allowed.length; i++)
			if(request == allowed[i])
				return true;
		
		return false;
	}
}
