package net.norcalcontrols.driver.snmp.common;

import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.script.hints.JythonElement;
import com.inductiveautomation.ignition.common.script.hints.ScriptArg;

public abstract class AbstractScriptModule implements FunctionInterface {

    static {
        BundleUtil.get().addBundle(
                AbstractScriptModule.class.getSimpleName(),
                AbstractScriptModule.class.getClassLoader(),
                AbstractScriptModule.class.getName().replace('.', '/')
        );
    }

    @JythonElement(docBundlePrefix = "AbstractScriptModule")
    public String[] get(
            @ScriptArg("address") String addr,
            @ScriptArg("port") int port,
            @ScriptArg("OID") String[] OIDS,
            @ScriptArg("others") String... params)
    {
        return NorcalSNMPDriverModule.snmpGet(addr, port, OIDS, params);
    }

    protected abstract String[] getImpl(String addr, int port, String[] OIDS, String... params);

    @JythonElement(docBundlePrefix = "AbstractScriptModule")
    public String[] getV3(
    		@ScriptArg("address") String addr,
    		@ScriptArg("port") int port,
    		@ScriptArg("OID") String[] OIDS,
    		@ScriptArg("authLevel") int authLevel,
    		@ScriptArg("user") String user,
    		@ScriptArg("pass") String pass,
    		@ScriptArg("authProt") int authProt,
    		@ScriptArg("privProt") int privProt,
    		@ScriptArg("others") String... params)
    {
    	return NorcalSNMPDriverModule.snmpGetV3(addr, port, OIDS, authLevel, user, pass, authProt, privProt, params);
    }
    
    protected abstract String[] getImplV3(String addr, int port, String[] OIDS, int authLevel, String user, String pass, int authProt, int privProt, String... params);

    @JythonElement(docBundlePrefix = "AbstractScriptModule")
    public String[] walk(
    		@ScriptArg("address") String addr,
    		@ScriptArg("port") int port,
    		@ScriptArg("startOID") String startOID,
    		@ScriptArg("others") String... params)
    {
    	return NorcalSNMPDriverModule.snmpWalk(addr, port, startOID, params);
    }
    
    protected abstract String[] walkImpl(String addr, int port, String startOID, String... params);

    @JythonElement(docBundlePrefix = "AbstractScriptModule")
    public String[] walkV3(
    		@ScriptArg("address") String addr,
    		@ScriptArg("port") int port,
    		@ScriptArg("startOID") String startOID,
    		@ScriptArg("authLevel") int authLevel,
    		@ScriptArg("user") String user,
    		@ScriptArg("pass") String pass,
    		@ScriptArg("authProt") int authProt,
    		@ScriptArg("privProt") int privProt,
    		@ScriptArg("others") String... params)
    {
    	return NorcalSNMPDriverModule.snmpWalkV3(addr, port, startOID, authLevel, user, pass, authProt, privProt, params);
    }
    
    protected abstract String[] walkImplV3(String addr, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String... params);    
}
