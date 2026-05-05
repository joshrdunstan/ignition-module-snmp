/*

Code taken from:

https://sites.google.com/site/mullais/logic/java/how-to-run-a-simple-snmp-get-program-using-java-with-eclipse?tmpl=%2Fsystem%2Fapp%2Ftemplates%2Fprint%2F&showPrintDialog=1

 */

package net.norcalcontrols.driver.snmp.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.snmp4j.CommunityTarget;
import org.snmp4j.UserTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.AuthSHA2;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

public class NorcalSNMPDriverModule {
    public static final String MODULE_ID = "net.norcalcontrols.driver.snmp.NorcalSNMPDriver";
    public static final int DEFAULT_VERSION = SnmpConstants.version2c;
    public static final String DEFAULT_PROTOCOL = "udp";
    public static final long DEFAULT_TIMEOUT = 3000L;
    public static final int DEFAULT_RETRY = 1;
    public static final int DEFAULT_AUTH_LVL = SecurityLevel.NOAUTH_NOPRIV;

    /**
     * SNMP4j registers v3 security state in process-wide singletons. Concurrent script calls
     * without coordination leak USM entries and corrupt shared protocol tables; serialize v3.
     */
    private static final Object SNMP_V3_LOCK = new Object();

    private static void applyCommunityTargetOptions(CommunityTarget target, String[] params) {
        if (params == null) {
            return;
        }
        for (String param : params) {
            if (param == null || param.isEmpty()) {
                continue;
            }
            int eq = param.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = param.substring(0, eq).trim();
            String val = param.substring(eq + 1).trim();
            if (val.isEmpty()) {
                continue;
            }
            try {
                if (key.equalsIgnoreCase("version")) {
                    target.setVersion(getVersion(val));
                } else if (key.equalsIgnoreCase("timeout")) {
                    target.setTimeout(Long.parseLong(val));
                } else if (key.equalsIgnoreCase("retry")) {
                    target.setRetries(Integer.parseInt(val));
                }
            } catch (NumberFormatException ignored) {
                // Ignore malformed numeric options so the request still uses defaults.
            }
        }
    }

    private static void applyUserTargetOptions(UserTarget target, String[] params) {
        if (params == null) {
            return;
        }
        for (String param : params) {
            if (param == null || param.isEmpty()) {
                continue;
            }
            int eq = param.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = param.substring(0, eq).trim();
            String val = param.substring(eq + 1).trim();
            if (val.isEmpty()) {
                continue;
            }
            try {
                if (key.equalsIgnoreCase("timeout")) {
                    target.setTimeout(Long.parseLong(val));
                } else if (key.equalsIgnoreCase("retry")) {
                    target.setRetries(Integer.parseInt(val));
                }
            } catch (NumberFormatException ignored) {
            }
        }
    }

    public static CommunityTarget createDefault(String ip, String community, int port, String[] params) {
        Address address = GenericAddress.parse(DEFAULT_PROTOCOL + ":" + ip + "/" + port);
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        target.setAddress(address);

        target.setVersion(DEFAULT_VERSION);
        target.setTimeout(DEFAULT_TIMEOUT);
        target.setRetries(DEFAULT_RETRY);

        applyCommunityTargetOptions(target, params);
        return target;
    }
    
    public static UserTarget createDefault(String ip, int authLevel, String user, String pass, int port, String[] params) {
    	Address address = GenericAddress.parse(DEFAULT_PROTOCOL + ":" + ip + "/" + port);
    	UserTarget target = new UserTarget();
    	target.setAddress(address);
    	target.setVersion(SnmpConstants.version3);
    	target.setTimeout(DEFAULT_TIMEOUT);
    	target.setRetries(DEFAULT_RETRY);
    	target.setSecurityLevel(getAuthLevel(authLevel));
    	target.setSecurityName(new OctetString(user));

    	applyUserTargetOptions(target, params);
    	return target;
    }
    

    private static int getVersion(String s) {
        if(s.equalsIgnoreCase("1")){
            return SnmpConstants.version1;
        } else if (s.equalsIgnoreCase("3")){
            return SnmpConstants.version3;
        } else {
            return SnmpConstants.version2c;
        }

    }
    
    private static int getAuthLevel(int s) {
    	if(s == 3) {
    		return SecurityLevel.AUTH_PRIV;
    	} else if (s == 2) {
    		return SecurityLevel.AUTH_NOPRIV;
    	} else {
    		return SecurityLevel.NOAUTH_NOPRIV;
    	}
    }   
    
    private static OID getAuthProtocol(int i) {
    	switch (i) {
	    	case 1: 
	    		return AuthMD5.ID;
	    	case 2:
	    		return AuthSHA.ID;
	    	case 3:
	    		return AuthHMAC128SHA224.ID;
	    	case 4:
	    		return AuthHMAC192SHA256.ID;
	    	case 5:
	    		return AuthHMAC256SHA384.ID;
	    	case 6:
	    		return AuthHMAC384SHA512.ID;
	    	default:
	    		return AuthHMAC384SHA512.ID;
    	}
    }
    
    private static OID getPrivProtocol(int i) {
    	switch(i) {
	    	case 1:
	    		return PrivDES.ID;
	    	case 2:
	    		return PrivAES128.ID;
	    	case 3:
	    		return PrivAES192.ID;
	    	case 4:
	    		return PrivAES256.ID;
	    	default:
	    		return PrivAES256.ID;
    	}
    }
    
    public static String[] snmpWalk(String ip, int port, String startOID, String[] params) {
        if (params == null || params.length == 0 || params[0] == null) {
            return new String[] { "[W000] Error: community string required as first parameter" };
        }
        String community = params[0];
        CommunityTarget target = createDefault(ip, community, port, params);
        return walk(target, new OID(startOID));
    }
    
    public static String[] snmpWalkV3(String ip, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String[] params) {
        UserTarget target = createDefault(ip, authLevel, user, pass, port, params);
        OID authProtocol = getAuthProtocol(authProt);
        OID privProtocol = getPrivProtocol(privProt);
        
        // Extract privacy key from params, default to auth password
        String privKey = pass;
        if (params != null) {
            for (String param : params) {
                if (param == null) {
                    continue;
                }
                int eq = param.indexOf('=');
                if (eq > 0 && param.substring(0, eq).trim().equalsIgnoreCase("privKey")) {
                    privKey = param.substring(eq + 1);
                    break;
                }
            }
        }
        
        // Create UsmUser based on security level
        UsmUser usr;
        if (authLevel == 3) {
        	// AUTH_PRIV: both authentication and privacy
        	usr = new UsmUser(
        			new OctetString(user),
        			authProtocol,
        			new OctetString(pass),
        			privProtocol,
        			new OctetString(privKey)
        	);
        } else if (authLevel == 2) {
        	// AUTH_NOPRIV: authentication only, no privacy
        	usr = new UsmUser(
        			new OctetString(user),
        			authProtocol,
        			new OctetString(pass),
        			null,
        			null
        	);
        } else {
        	// NOAUTH_NOPRIV: no authentication, no privacy
        	usr = new UsmUser(
        			new OctetString(user),
        			null,
        			null,
        			null,
        			null
        	);
        }
        return walkV3(target, new OID(startOID), usr, user, authProtocol);
    }

    public static String[] snmpGet(String ip, int port, String[] oids, String[] params) {
        if (params == null || params.length == 0 || params[0] == null) {
            return new String[] { "[G000] Error: community string required as first parameter" };
        }
    	String community = params[0];
        CommunityTarget target = createDefault(ip, community, port, params);
        PDU pdu = new PDU();
        pdu.addAll(getBindings(oids));
        return get(pdu, target);
    }
    
    public static String[] snmpGetV3(String ip, int port, String[] oids, int authLevel, String user, String pass, int authProt, int privProt, String[] params) {
    	UserTarget target = createDefault(ip, authLevel, user, pass, port, params);
    	OID authProtocol = getAuthProtocol(authProt);
    	OID privProtocol = getPrivProtocol(privProt);
    	
    	// Extract privacy key from params, default to auth password
    	String privKey = pass;
    	if (params != null) {
    		for (String param : params) {
    			if (param == null) {
    				continue;
    			}
    			int eq = param.indexOf('=');
    			if (eq > 0 && param.substring(0, eq).trim().equalsIgnoreCase("privKey")) {
    				privKey = param.substring(eq + 1);
    				break;
    			}
    		}
    	}
    	
    	PDU pdu = new ScopedPDU();
    	pdu.addAll(getBindings(oids));
    	
    	// Create UsmUser based on security level
    	UsmUser usr;
    	if (authLevel == 3) {
    		// AUTH_PRIV: both authentication and privacy
    		usr = new UsmUser(
    				new OctetString(user),
    				authProtocol,
    				new OctetString(pass),
    				privProtocol,
    				new OctetString(privKey)
    		);
    	} else if (authLevel == 2) {
    		// AUTH_NOPRIV: authentication only, no privacy
    		usr = new UsmUser(
    				new OctetString(user),
    				authProtocol,
    				new OctetString(pass),
    				null,
    				null
    		);
    	} else {
    		// NOAUTH_NOPRIV: no authentication, no privacy
    		usr = new UsmUser(
    				new OctetString(user),
    				null,
    				null,
    				null,
    				null
    		);
    	}
    	return getV3(pdu, target, usr, user, authProtocol);
    }

    private static VariableBinding[] getBindings(String[] oids) {
        ArrayList<VariableBinding> vars = new ArrayList<>();
        for (String oid : oids) {
            vars.add(new VariableBinding(new OID(oid)));
        }

        return vars.toArray(new VariableBinding[0]);
    }
    
    private static String[] walk(CommunityTarget target, OID startOID) {
        ArrayList<String> results = new ArrayList<>();
        Snmp snmp = null;

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            snmp.listen();

            // SNMPv1 does not support GETBULK; TreeUtils default factory uses GETBULK for v2c.
            DefaultPDUFactory pduFactory = target.getVersion() == SnmpConstants.version1
                    ? new DefaultPDUFactory(PDU.GETNEXT)
                    : new DefaultPDUFactory();
            TreeUtils treeUtils = new TreeUtils(snmp, pduFactory);
            List<TreeEvent> events = treeUtils.getSubtree(target, startOID);

            for (TreeEvent event : events) {
                if (event != null) {
                    if (event.isError()) {
                    	results.add("[W001] Error: " + event.getErrorMessage());
                    } else {
                        VariableBinding[] varBindings = event.getVariableBindings();
                        if (varBindings != null) {
                            for (VariableBinding varBinding : varBindings) {
                                results.add(varBinding.toString());
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            results.add("[W002] Error: IOException: " + e.getMessage());
        } finally {
            if (snmp != null) {
                try {
                    snmp.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return results.toArray(new String[0]);
    }  
    
    private static void registerAuthProtocolsForV3(OID authProt) {
        if (authProt != null && authProt.equals(AuthMD5.ID)) {
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
        } else if (authProt != null && authProt.equals(AuthSHA.ID)) {
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        } else {
            SecurityProtocols.getInstance().addDefaultProtocols();
        }
    }

    private static USM createAndRegisterUsm(UsmUser usr, String username, OID authProt) {
        registerAuthProtocolsForV3(authProt);
        byte[] localEngineID = MPv3.createLocalEngineID();
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(localEngineID), 0);
        usm.addUser(new OctetString(username), usr);
        SecurityModels.getInstance().addSecurityModel(usm);
        return usm;
    }

    private static void unregisterUsm(USM usm) {
        if (usm != null) {
            SecurityModels.getInstance().removeSecurityModel(usm.getID());
        }
    }

    private static String[] walkV3(UserTarget target, OID startOID, UsmUser usr, String username, OID authProt) {
        synchronized (SNMP_V3_LOCK) {
            ArrayList<String> results = new ArrayList<>();
            Snmp snmp = null;
            USM usm = null;

            try {
                DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
                snmp = new Snmp(transport);
                usm = createAndRegisterUsm(usr, username, authProt);
                snmp.listen();

                TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory(PDU.GETNEXT));
                List<TreeEvent> events = treeUtils.getSubtree(target, startOID);

                for (TreeEvent event : events) {
                    if (event != null) {
                        if (event.isError()) {
                            results.add("[WV02] Error: " + event.getErrorMessage());
                        } else {
                            VariableBinding[] varBindings = event.getVariableBindings();
                            if (varBindings != null) {
                                for (VariableBinding varBinding : varBindings) {
                                    results.add(varBinding.toString());
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                results.add("[WV03] Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            } finally {
                if (snmp != null) {
                    try {
                        snmp.close();
                    } catch (IOException ignored) {
                    }
                }
                unregisterUsm(usm);
            }

            return results.toArray(new String[0]);
        }
    }

    private static String[] get(PDU pdu, CommunityTarget target) {
        Snmp snmp = null;
        ArrayList<String> res = new ArrayList<>();
        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            snmp.listen();
            pdu.setType(PDU.GET);
            ResponseEvent respEvent = snmp.send(pdu, target);
            if (respEvent == null) {
                res.add("[G001] Error: No response event from SNMP stack");
                return res.toArray(new String[0]);
            }
            PDU response = respEvent.getResponse();

            if (response == null) {
                if (respEvent.getError() != null) {
                    res.add("[G001] Error: " + respEvent.getError().getMessage());
                } else {
                    res.add("[G001] Error: No response from device (timeout or unreachable)");
                }
            } else if (response.getErrorStatus() != PDU.noError) {
                res.add("[G003] Error: " + response.getErrorStatusText() + " at index " + response.getErrorIndex());
            } else {
                for (int i = 0; i < response.size(); i++) {
                    VariableBinding vb = response.get(i);
                    res.add(String.valueOf(vb.getVariable()));
                }
            }
            return res.toArray(new String[0]);
        } catch (Exception e) {
            res.add("[G002] Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return res.toArray(new String[0]);
        } finally {
            if (snmp != null) {
                try {
                    snmp.close();
                } catch (IOException ignored) {
                }
            }
        }
    }
    
    private static String[] getV3(PDU pdu, UserTarget target, UsmUser usr, String username, OID authProt) {
        synchronized (SNMP_V3_LOCK) {
            ArrayList<String> res = new ArrayList<>();
            Snmp snmp = null;
            USM usm = null;

            try {
                DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
                snmp = new Snmp(transport);
                usm = createAndRegisterUsm(usr, username, authProt);
                snmp.listen();

                StringBuilder debug = new StringBuilder();
                debug.append("Target: ").append(target.getAddress());
                debug.append(", Timeout: ").append(target.getTimeout());
                debug.append(", SecLevel: ").append(target.getSecurityLevel());
                debug.append(", User: ").append(username);

                pdu.setType(PDU.GET);

                ResponseEvent respEvent = snmp.send(pdu, target);
                if (respEvent == null) {
                    res.add("[GV05] Error: No response event from SNMP stack [" + debug + "]");
                    return res.toArray(new String[0]);
                }
                PDU response = respEvent.getResponse();

                if (response == null) {
                    if (respEvent.getError() != null) {
                        res.add("[GV01] Error: " + respEvent.getError().getMessage() + " [" + debug + "]");
                    } else {
                        res.add("[GV02] Error: No Response [" + debug + "]");
                    }
                } else if (response.getErrorStatus() != PDU.noError) {
                    res.add("[GV03] Error: " + response.getErrorStatusText() + " at index " + response.getErrorIndex());
                } else {
                    for (int i = 0; i < response.size(); i++) {
                        VariableBinding vb = response.get(i);
                        res.add(String.valueOf(vb.getVariable()));
                    }
                }
                return res.toArray(new String[0]);
            } catch (Exception e) {
                res.add("[GV04] Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                return res.toArray(new String[0]);
            } finally {
                if (snmp != null) {
                    try {
                        snmp.close();
                    } catch (IOException ignored) {
                    }
                }
                unregisterUsm(usm);
            }
        }
    }

}
