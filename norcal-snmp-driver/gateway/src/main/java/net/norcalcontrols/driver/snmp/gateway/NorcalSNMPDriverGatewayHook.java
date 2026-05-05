package net.norcalcontrols.driver.snmp.gateway;

import com.inductiveautomation.ignition.common.licensing.LicenseState;
import com.inductiveautomation.ignition.common.script.ScriptManager;
import com.inductiveautomation.ignition.common.script.hints.PropertiesFileDocProvider;
import com.inductiveautomation.ignition.gateway.model.AbstractGatewayModuleHook;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.rpc.GatewayRpcImplementation;
import net.norcalcontrols.driver.snmp.common.FunctionInterface;
import net.norcalcontrols.driver.snmp.common.NorcalSNMPDriverModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class NorcalSNMPDriverGatewayHook extends AbstractGatewayModuleHook {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final GatewayScriptModule scriptModule = new GatewayScriptModule();

    @Override
    public void setup(GatewayContext gatewayContext) {
        logger.info("setup()");
    }

    @Override
    public void startup(LicenseState licenseState) {
        logger.info("startup()");
    }

    @Override
    public void shutdown() {
        logger.info("shutdown()");
        NorcalSNMPDriverModule.shutdown();
    }

    @Override
    public void initializeScriptManager(ScriptManager manager) {
        super.initializeScriptManager(manager);

        manager.addScriptModule(
                "system.snmp",
                scriptModule,
                new PropertiesFileDocProvider());
    }

    @Override
    public boolean isFreeModule(){
        return true;
    }

    @Override
    public Optional<GatewayRpcImplementation> getRpcImplementation() {
        return Optional.of(GatewayRpcImplementation.of(
                FunctionInterface.SERIALIZER,
                new FunctionInterfaceImpl() {}
        ));
    }
}
