package be.security.shared.settings;

public class GlobalConsts 
{
	public final static String CA_SUBJECT = "CN=Global Masterkey CA,OU=Master Key Holding Vault,O=Master Key Holding Ltd.,L=Luxembourg,ST=Brussels,C=BE,E=contact@jenterosseel.com";
	
	public final static String KEY_STORE_TYPE = "JKS";
	
	// Aanpassen bij veranderende gebruiker
	private final static String _LOCAL_FOLDER = "C:\\Users\\Tim\\Desktop\\project_sic";
	public final static String KEY_STORE_FOLDER = _LOCAL_FOLDER + "\\workspace\\KeysAndCertificates\\";
	
	public final static String CRYPTO_ALGORITHM = "RSA"; 
	public static final String HASH_ALGORITHM = "SHA-1";

	public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	
	
	// Simplification, should be a URI in a real-life case
	public final static String GOVERNMENT_SERVER_ADDRESS = "127.0.0.1";
	public final static int GOVERNMENT_PORT = 8081;
	
	public final static String SP_SERVER_ADDRESS = "127.0.0.1";
	public final static int SP_PORT = 8082;
}	
