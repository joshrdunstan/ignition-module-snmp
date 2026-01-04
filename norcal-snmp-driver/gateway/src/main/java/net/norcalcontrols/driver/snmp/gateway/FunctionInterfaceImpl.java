package net.norcalcontrols.driver.snmp.gateway;

import com.inductiveautomation.ignition.common.project.ClientPermissionsConstants;
import com.inductiveautomation.ignition.gateway.rpc.RpcDelegate;
import net.norcalcontrols.driver.snmp.common.FunctionInterface;
import net.norcalcontrols.driver.snmp.common.NorcalSNMPDriverModule;

import java.util.function.Supplier;

/**
 * This is the actual implementation of the RPC functions that will be called by the client/designer.
 * The @RunsOnClient annotation is needed for <b>any</b> RPC function that will be allowed to be invoked by Vision
 * clients.
 * If you do not have a custom client permission ID registered with the rest of the system, use the special UNRESTRICTED
 * value, as below.
 */
@RpcDelegate.RunsOnClient(clientPermissionId = ClientPermissionsConstants.UNRESTRICTED)
public class FunctionInterfaceImpl implements FunctionInterface {

    public FunctionInterfaceImpl() {

    }

    @Override
    public String[] get(String addr, int port, String[] OIDS, String... params) {
        return NorcalSNMPDriverModule.snmpGet(addr, port, OIDS, params);
    }

    @Override
    public String[] getV3(String addr, int port, String[] OIDS, int authLevel, String user, String pass, int authProt, int privProt, String... params) {
        return NorcalSNMPDriverModule.snmpGetV3(addr, port, OIDS, authLevel, user, pass, authProt, privProt, params);
    }

    @Override
    public String[] walk(String ip, int port, String startOID, String[] params) {
        return NorcalSNMPDriverModule.snmpWalk(ip, port, startOID, params);
    }

    @Override
    public String[] walkV3(String ip, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String[] params) {
        return NorcalSNMPDriverModule.snmpWalkV3(ip, port, startOID, authLevel, user, pass, authProt, privProt, params);
    }
}
