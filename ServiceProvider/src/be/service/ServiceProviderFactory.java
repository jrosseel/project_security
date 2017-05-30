package be.service;

import global.connection.sockets.SocketTransmitter;
import global.connection.sockets.routing.Domains;
import global.connection.sockets.routing.ServiceProviders;

public class ServiceProviderFactory {	
	
	public static ServiceProvider makeSP(SocketTransmitter connection, int spChoice) 
	{
		switch(spChoice) 
		{
			case ServiceProviders.DefaultIdentity:
				return new ServiceProvider(connection, "default_identity", Domains.Default);
				
			case ServiceProviders.AnotherDefault:
				return new ServiceProvider(connection, "another_default", Domains.Default);
				
			case ServiceProviders.BelgianFiscalAuthority:
				return new ServiceProvider(connection, "belgian_fiscal_authority", Domains.Government);
				
			case ServiceProviders.BelgianGovernmentIdentity:
				return new ServiceProvider(connection, "belgian_gov_identity", Domains.Government);
				
			case ServiceProviders.DoktersUnie:
				return new ServiceProvider(connection, "dokters_unie", Domains.Healthcare);
				
			case ServiceProviders.SociaalVerzekeringsFonds:
				return new ServiceProvider(connection, "sociaal_verzekeringsfonds", Domains.Healthcare);
			
			case ServiceProviders.Facebook:
				return new ServiceProvider(connection, "facebook", Domains.SocialNet);
				
			case ServiceProviders.Twitter:
				return new ServiceProvider(connection, "twitter", Domains.SocialNet);

		}
		
		throw new RuntimeException("Requesting non-existing service provider");
	}

	
}
