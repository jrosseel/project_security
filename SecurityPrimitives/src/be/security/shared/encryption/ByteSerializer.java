package be.security.shared.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;

/**
 * Class that converts serializable objects into bytestreams,
 * 		and the other way around.
 * 
 * @author JRosseel
 *
 */
public class ByteSerializer
{
	public static byte[] EncodeInt(int i) {
		ByteBuffer b = ByteBuffer.allocate(4);
		b.putInt(i);

		return b.array();
	}
	
	public static byte[] EncodeObject(Serializable obj) 
		throws IOException 
	{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		
		try 
		{
			out = new ObjectOutputStream(bos);   
			out.writeObject(obj);
			out.flush();
			byte[] result = bos.toByteArray();
		  
			return result;
		} 
		finally 
		{
			try {
				bos.close();
			} catch (IOException ex) {
				// ignore close exception
			}
		}
	}
	
	public static Object DecodeObject(byte[] bytes) 
			throws IOException, ClassNotFoundException 
	{
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		ObjectInput in = null;
		
		try 
		{
			in = new ObjectInputStream(bis);
			Object o = in.readObject(); 
			
			return o;
		}
		finally
		{
			try {
				if (in != null) {
					in.close();
				}
			} 
			catch (IOException ex) { /* ignore close exception */ }
		}
	}
	
	public static byte[] concatArrays(byte[] arr1, byte[] arr2) {
		byte[] result = new byte[arr1.length + arr2.length];
		
		for(int i = 0; i < arr1.length; i++) 
			result[i] = arr1[i];
		
		for(int i = 0; i < arr2.length; i++) 
			result[arr1.length + i] = arr2[i];
		
		return result;
	}
}
