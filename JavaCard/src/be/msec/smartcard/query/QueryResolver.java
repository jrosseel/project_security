package be.msec.smartcard.query;

import java.nio.ByteBuffer;

import com.sun.javacard.crypto.r;

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
		//ByteBuffer current;
		ByteBuffer temp = ByteBuffer.allocate(0);
		ByteBuffer result = ByteBuffer.allocate(0); 
		short len = 0;
		short len_res = 0;
		for(int i = 0; i < queryRequest.length; i++)
		{
			temp.clear();
			temp = clone(result);
			len_res = (short)result.array().length;
			result.clear();
			ByteBuffer current = clone(_resolveRequest(queryRequest[i]));
			len = (short)current.array().length;
			result = clone(ByteBuffer.allocate((short)(len_res+len)).put(temp).put(current));
		}
		temp = clone(result);
		//result.clear();
		result = ByteBuffer.allocate(temp.array().length+1).put(temp).put(QueryCodes.STOP);
		return result.array();
	}
	
	public static ByteBuffer clone(ByteBuffer original) {
	       ByteBuffer clone = ByteBuffer.allocate(original.capacity());
	       original.rewind();//copy from the beginning
	       clone.put(original);
	       original.rewind();
	       clone.flip();
	       return clone;
	}

	private ByteBuffer _resolveRequest(byte request) throws Exception 
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
						 .put(requestAnswer);
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