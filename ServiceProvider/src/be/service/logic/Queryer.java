package be.service.logic;

import global.connection.sockets.routing.QueryCodes;
import global.connection.sockets.routing.ServiceProviders;

public class Queryer 
{
	private int _spId;
	
	public Queryer(int spId) { 
		_spId = spId;
	}

	public byte[] makeQuery() 
	{
		switch(_spId) {
			// Will crash - Address not allowed
			case ServiceProviders.AnotherDefault:
				return new byte[]{ QueryCodes.ADDRESS_REQUEST, QueryCodes.AGE_REQUEST };
			
			// Will succeed
			case ServiceProviders.DefaultIdentity:
				return new byte[]{ QueryCodes.AGE_REQUEST };
				
			// Will succeed
			case ServiceProviders.BelgianFiscalAuthority:
				return new byte[]{ QueryCodes.NAME_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.ADDRESS_REQUEST, QueryCodes.BIRTHDATE_REQUEST };
			
			// Will fail - Gov cant see picture
			case ServiceProviders.BelgianGovernmentIdentity:
				return new byte[]{ QueryCodes.NAME_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.PHOTO_REQUEST, QueryCodes.SSN_REQUEST };
			
			// Will succeed
			case ServiceProviders.DoktersUnie:
				return new byte[]{ QueryCodes.NAME_REQUEST, QueryCodes.GENDER_REQUEST, QueryCodes.PHOTO_REQUEST, QueryCodes.SSN_REQUEST };
			
			// Will succeed
			case ServiceProviders.SociaalVerzekeringsFonds:
				return new byte[]{ QueryCodes.ADDRESS_REQUEST, QueryCodes.AGE_REQUEST };
				
			// Will fail - Cant see address
			case ServiceProviders.Facebook:
				return new byte[]{ QueryCodes.ADDRESS_REQUEST, QueryCodes.AGE_REQUEST };
			
			// Will succeed
			case ServiceProviders.Twitter:
				return new byte[]{ QueryCodes.GENDER_REQUEST, QueryCodes.AGE_REQUEST,QueryCodes.COUNTRY_REQUEST, QueryCodes.NAME_REQUEST };
		}
		throw new RuntimeException("Unkown Serviceprovider");
	}
	
	
}