package be.security.shared.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Class that converts serializable objects into bytestreams,
 * 		and the other way around.
 * 
 * @author JRosseel
 *
 */
public class ByteSerializer {
	
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
}
