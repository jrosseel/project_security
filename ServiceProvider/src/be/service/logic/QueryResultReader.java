package be.service.logic;

import java.nio.ByteBuffer;
import java.util.Arrays;

import global.connection.sockets.routing.QueryCodes;

public class QueryResultReader 
{
	private byte[] _result;
	private int _cursor = 0;
	
	public QueryResultReader(byte[] result)
	{
		_result = result;
	}
	
	// Structure package: nym ++ rest
				      // 2 bytes					 1 byte		2 bytes		x bytes	 1 byte
	// Structure rest: numberofattr - attribute[](attrType - attrLength - attr) - stop
	public String[] read()
	{
		short nOfAttributes = _getNumberOfAttributes();
		
		String[] attributes = new String[nOfAttributes];

		for(int i = 0; i < nOfAttributes; i++) 
			attributes[i] = _parseAttribute();
		
		return attributes;
	}

	//							1 byte		2 bytes	  x bytes
	//				attribute: attrType - attrLength - attr
	private String _parseAttribute()
	{
		String attributeName = QueryCodes.GetAttributeName(_result[_cursor]);
		short len = _parseShort(Arrays.copyOfRange(_result, _cursor + 1, _cursor + 3));
		
		byte[] attrData = Arrays.copyOfRange(_result, _cursor + 3, _cursor + 3 + len);
		String attributeValue = new String(attrData);
		
		// increase cursor
		_cursor += 3 + len;
		return attributeName + ": " + attributeValue;
	}

	private short _getNumberOfAttributes()
	{
		short res = _parseShort(Arrays.copyOfRange(_result, _cursor, _cursor + 2));
		_cursor += 2;
		
		return res;
	}
	
	private static short _parseShort(byte[] aShort) {
		return ByteBuffer.wrap(aShort)
				  		 .getShort();
	}
}
