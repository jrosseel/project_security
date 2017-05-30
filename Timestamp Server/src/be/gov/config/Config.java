package be.gov.config;

import be.security.shared.settings.GlobalConsts;

/**
 * Contains constants the system needs to run. 
 * 
 * E.g. to interact with the keystores.
 * 
 */
public class Config 
{
	
	//#region Keys
	public static final String KEYSTORE_LOC = GlobalConsts.KEY_STORE_FOLDER;
	public static final String KEY_STORE_NAME   = "government";
	public static final String KEY_STORE_PASSWD = "123456";
	
	public static final String SERVER_KEY_NAME	 = "government";
	public static final String SERVER_KEY_PASSWD = "";
	public static final String SERVER_ISSUER = "CN=Government Timestamp Server,OU=Government,O=Belgian Government,L=Brussels,ST=Brussels,C=BE,E=timestamp@gov.be";
	
	public static final String CA_NAME = "global_masterkey";

}