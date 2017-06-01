package be.msec.smartcard.query;

import java.nio.ByteBuffer;

import be.msec.cardprimitives.smartcard.QueryCodes;
import be.msec.smartcard.CardData;

public class QueryResolver 
{
	private CardData _data;
	
	public QueryResolver(CardData data) {
		_data = data;
	}
	
	public byte[] resolveQuery(byte[] queryRequest)
			throws Exception 
	{
		byte[][] response = new byte[queryRequest.length][];
		
		for(int i = 0; i < queryRequest.length; i++)
			response[i] = _resolveRequest(queryRequest[i]);
		
		return _flatmapResponse((short) queryRequest.length, response);
	}

	private byte[] _resolveRequest(byte request) throws Exception 
	{
		byte[] requestAnswer = null;
		switch(request)
		{
		case QueryCodes.ADDRESS_REQUEST:
			requestAnswer = _data.getAddress();
			break;
		case QueryCodes.AGE_REQUEST:
			requestAnswer = _data.getAge();
			break;
		case QueryCodes.BIRTHDATE_REQUEST:
			requestAnswer = _data.getBirthDate();
			break;
		case QueryCodes.COUNTRY_REQUEST:
			requestAnswer = _data.getCountry();
			break;
		case QueryCodes.GENDER_REQUEST:
			requestAnswer = _data.getGender();
			break;
		case QueryCodes.NAME_REQUEST:
			requestAnswer = _data.getName();
			break;
		case QueryCodes.PHOTO_REQUEST:
			requestAnswer = _data.getPhoto();
			break;
		case QueryCodes.SSN_REQUEST:
			requestAnswer = _data.getSsn();
			break;
			// Something went wrong
		default:
			throw new Exception();
		}
		
		return ByteBuffer.allocate(3 + requestAnswer.length)
						 .put(request)
						 .putShort((short) requestAnswer.length)
						 .put(requestAnswer)
						 .array();
	}
	
	private byte[] _flatmapResponse(short reqLength, byte[][] response) 
	{
		// Structure: numberofattr - attribute[](attrType - attrLength - attr) - stop
		short totalLength = reqLength;
		for(int i = 0; i < reqLength; i++)
		{ 
			totalLength += response[i].length;
		}
		totalLength++;
		
		ByteBuffer flatResponse = ByteBuffer.allocate(totalLength); // numberofattr
		flatResponse.putShort(reqLength);
		
		for(int i = 0; i < reqLength; i++) // attribute[]
			flatResponse.put(response[i]); // 	(attrType - attrLength - attr)
		
		flatResponse.put(QueryCodes.STOP);
		
		return flatResponse.array();
	}
}
