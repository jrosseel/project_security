package be.service.config;

import be.security.shared.settings.GlobalConsts;

/**
 * Contains constants the system needs to run. 
 * 
 * E.g. to interact with the keystores.
 * 
 * Also identifies the current server
 */
public class Config 
{
	public static final String KEYSTORE_LOC = GlobalConsts.KEY_STORE_FOLDER;
	public static final String KEYSTORE_PASSWD = "123456";
	
	// One store per service provider.
	// 	 All the SP keys are named me, and their passwords are ""
	public static final String SP_KEY_NAME = "me";
	public static final String SP_KEY_PASSWD = "";
}