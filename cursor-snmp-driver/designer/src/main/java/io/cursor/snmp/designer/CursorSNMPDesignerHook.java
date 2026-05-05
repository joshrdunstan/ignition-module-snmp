package io.cursor.snmp.designer;

import com.inductiveautomation.ignition.common.script.ScriptManager;
import com.inductiveautomation.ignition.common.script.hints.PropertiesFileDocProvider;
import com.inductiveautomation.ignition.designer.model.AbstractDesignerModuleHook;
import io.cursor.snmp.client.ClientScriptModule;

/**
 * Designer-scope module hook.
 */
public class CursorSNMPDesignerHook extends AbstractDesignerModuleHook {

    @Override
    public void initializeScriptManager(ScriptManager manager) {
        super.initializeScriptManager(manager);

        manager.addScriptModule("system.snmp",
                new ClientScriptModule(),
                new PropertiesFileDocProvider());
    }
}
