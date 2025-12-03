package net.norcalcontrols.driver.snmp.client;

import net.norcalcontrols.driver.snmp.common.AbstractScriptModule;
import net.norcalcontrols.driver.snmp.common.FunctionInterface;
import com.inductiveautomation.ignition.client.gateway_interface.ModuleRPCFactory;

public class ClientScriptModule extends AbstractScriptModule {
	private final FunctionInterface rpc;
	
	public ClientScriptModule() {
		rpc = ModuleRPCFactory.create(
			"net.norcalcontrols.driver.snmp.NorcalSNMPDriver",
			FunctionInterface.class
		);
	}
    
    @Override
    protected String[] getImpl(String addr, int port, String[] OIDS, String... params){
        return rpc.get(addr, port, OIDS, params);
    }
    
    @Override
    protected String[] getImplV3(String addr, int port, String[] OIDS, int authLevel, String user, String pass, int authProt, int privProt, String... params) {
    	return rpc.getV3(addr, port, OIDS, authLevel, user, pass, authProt, privProt, params);
    }
    
    @Override
    protected String[] walkImpl(String addr, int port, String startOID, String... params){
        return rpc.walk(addr, port, startOID, params);
    }	
	
    @Override
    protected String[] walkImplV3(String addr, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String... params) {
    	return rpc.walkV3(addr, port, startOID, authLevel, user, pass, authProt, privProt, params);
    }    
}