package be.service.logic;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
	
				// 2 bytes					 1 byte		2 bytes		x bytes	 1 byte
	// Structure: numberofattr - attribute[](attrType - attrLength - attr) - stop
	public String[] read()
	{
		short nOfAttributes = _getNumberOfAttributes();
		
		String[] attributes = new String[nOfAttributes];
		// Start from after the nOfAttributes byte
		_cursor = 2;
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
		return _parseShort(Arrays.copyOfRange(_result, 0, 2));
	}
	
	
	private static short _parseShort(byte[] aShort) {
		return ByteBuffer.wrap(aShort)
				  		 .order(ByteOrder.LITTLE_ENDIAN)
				  		 .getShort();
	}
}
