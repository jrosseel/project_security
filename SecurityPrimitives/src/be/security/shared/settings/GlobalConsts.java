package be.security.shared.settings;

public class GlobalConsts 
{
	public final static String CA_SUBJECT = "CN=Global Masterkey CA,OU=Master Key Holding Vault,O=Master Key Holding Ltd.,L=Luxembourg,ST=Brussels,C=BE,E=contact@jenterosseel.com";
	
	public final static String KEY_STORE_TYPE = "JKS";
	
	// Aanpassen bij veranderende gebruiker
	private final static String _LOCAL_FOLDER = "C:\\Users\\JRosseel\\Google Drive\\School\\Master\\Semester 4\\Project Security";
	public final static String KEY_STORE_FOLDER = _LOCAL_FOLDER + "\\workspace\\KeysAndCertificates\\";
	
	public final static String CRYPTO_ALGORITHM = "RSA"; 
	public static final String HASH_ALGORITHM = "SHA-1";
	
	
	// Simplification, should be a URI in a real-life case
	public final static String GOVERNMENT_SERVER_ADDRESS = "127.0.0.1";
	public final static int GOVERNMENT_PORT = 8081;
}	
