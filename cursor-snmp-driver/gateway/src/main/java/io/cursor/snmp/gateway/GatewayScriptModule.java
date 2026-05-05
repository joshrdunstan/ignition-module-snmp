package io.cursor.snmp.gateway;

import io.cursor.snmp.common.AbstractScriptModule;
import io.cursor.snmp.common.CursorSNMPDriverModule;

public class GatewayScriptModule extends AbstractScriptModule {

    @Override
    protected String[] getImpl(String addr, int port, String[] OIDS, String... params) {
        return CursorSNMPDriverModule.snmpGet(addr, port, OIDS, params);
    }
    
    @Override
    protected String[] getImplV3(String addr, int port, String[] OIDS, int authLevel, String user, String pass, int authProt, int privProt, String... params) {
    	return CursorSNMPDriverModule.snmpGetV3(addr, port, OIDS, authLevel, user, pass, authProt, privProt, params);
    }

    @Override
    protected String[] walkImpl(String addr, int port, String startOID, String... params) {
        return CursorSNMPDriverModule.snmpWalk(addr, port, startOID, params);
    }
    
    @Override
    protected String[] walkImplV3(String addr, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String... params) {
    	return CursorSNMPDriverModule.snmpWalkV3(addr, port, startOID, authLevel, user, pass, authProt, privProt, params);
    }
}