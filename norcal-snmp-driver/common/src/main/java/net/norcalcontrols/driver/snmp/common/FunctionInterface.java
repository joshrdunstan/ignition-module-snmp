package net.norcalcontrols.driver.snmp.common;

import com.inductiveautomation.ignition.common.rpc.RpcInterface;
import com.inductiveautomation.ignition.common.rpc.RpcSerializer;
import com.inductiveautomation.ignition.common.rpc.proto.ProtoRpcSerializer;

@RpcInterface(packageId = "ignition-module-snmp")
public interface FunctionInterface {
    String[] get(String addr, int port, String[] OIDS, String... params);
    String[] getV3(String addr, int port, String[] OIDS, int authLevel, String user, String pass, int authProt, int privProt, String... params );
    String[] walk(String ip, int port, String startOID, String[] params);
    String[] walkV3(String ip, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String[] params);

    RpcSerializer SERIALIZER = ProtoRpcSerializer.newBuilder().build();
}
