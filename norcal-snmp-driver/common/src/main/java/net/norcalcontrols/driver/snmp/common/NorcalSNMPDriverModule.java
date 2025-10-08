/*

Code taken from:

https://sites.google.com/site/mullais/logic/java/how-to-run-a-simple-snmp-get-program-using-java-with-eclipse?tmpl=%2Fsystem%2Fapp%2Ftemplates%2Fprint%2F&showPrintDialog=1

 */

package net.norcalcontrols.driver.snmp.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Dictionary;
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
import org.snmp4j.TransportMapping;
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

    public static CommunityTarget createDefault(String ip, String community, int port, String[] params) {
        Address address = GenericAddress.parse(DEFAULT_PROTOCOL + ":" + ip + "/" + port);
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        target.setAddress(address);

        target.setVersion(DEFAULT_VERSION);
        target.setTimeout(DEFAULT_TIMEOUT);
        target.setRetries(DEFAULT_RETRY);

        for(String param : params) {
            String[] value = param.split("=");
            if(value[0].equalsIgnoreCase("version")){
                target.setVersion(getVersion(value[1]));
            } else if(value[0].equalsIgnoreCase("timeout")){
                target.setTimeout(Integer.parseInt(value[1]));
            } else if(value[0].equalsIgnoreCase("retry")){
                target.setRetries(Integer.parseInt(value[1]));
            }
        }
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
    	
    	
    	for(String param : params) {
    		String[] value = param.split("=");
    		if(value[0].equalsIgnoreCase("timeout")) {
                target.setTimeout(Integer.parseInt(value[1]));
            } else if(value[0].equalsIgnoreCase("retry")){
                target.setRetries(Integer.parseInt(value[1]));
            }
    	}
    	
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
        String community = params[0];
        CommunityTarget target = createDefault(ip, community, port, params);
        return walk(target, new OID(startOID));
    }
    
    public static String[] snmpWalkV3(String ip, int port, String startOID, int authLevel, String user, String pass, int authProt, int privProt, String[] params) {
        UserTarget target = createDefault(ip, authLevel, user, pass, port, params);
        OID authProtocol = getAuthProtocol(authProt);
        OID privProtocol = getPrivProtocol(privProt);
    	UsmUser usr = new UsmUser(
    			new OctetString(user),
    			authProtocol,
    			new OctetString(pass),
    			privProtocol,
    			new OctetString(pass)
		);
        return walkV3(target, new OID(startOID), usr, user, authProtocol);
    }

    public static String[] snmpGet(String ip, int port, String[] oids, String[] params) { /// if anyone knows how to get rid of the first item from an array please let me know
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
    	PDU pdu = new ScopedPDU();
    	pdu.addAll(getBindings(oids));
    	UsmUser usr = new UsmUser(
    			new OctetString(user),
    			authProtocol,
    			new OctetString(pass),
    			privProtocol,
    			new OctetString(pass)
		);
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

            TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
            List<TreeEvent> events = treeUtils.getSubtree(target, startOID);

            for (TreeEvent event : events) {
                if (event != null) {
                    if (event.isError()) {
                        //System.err.println("Error: " + event.getErrorMessage());
                    	results.add("Error: " + event.getErrorMessage());
                    } else {
                        VariableBinding[] varBindings = event.getVariableBindings();
                        for (VariableBinding varBinding : varBindings) {
                            results.add(varBinding.toString());
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
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
    
    private static String[] walkV3(UserTarget target, OID startOID, UsmUser usr, String username, OID authProt) {
    	if (authProt == AuthMD5.ID) {
    		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
    	}
    	else if (authProt == AuthSHA.ID) {
    		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
    	}
        ArrayList<String> results = new ArrayList<>();
        Snmp snmp = null;

        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);

            // Add user to USM
        	usm.addUser(
        			new OctetString(username),
        			usr
            );

            snmp.listen();

            TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
            List<TreeEvent> events = treeUtils.getSubtree(target, startOID);

            for (TreeEvent event : events) {
                if (event != null) {
                    if (event.isError()) {
                        System.err.println("Error: " + event.getErrorMessage());
                    } else {
                        VariableBinding[] varBindings = event.getVariableBindings();
                        for (VariableBinding varBinding : varBindings) {
                            results.add(varBinding.toString());
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
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

    private static String[] get(PDU pdu, CommunityTarget target) {
        Snmp snmp = null;
        ArrayList<String> res = new ArrayList<>();
        try {
            DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            snmp.listen();
            pdu.setType(PDU.GET);
            ResponseEvent respEvent = snmp.send(pdu, target);
            PDU response = respEvent.getResponse();

            if (response == null) {
                res.add("Error: no Response");
            } else {
                for (int i = 0; i < response.size(); i++) {
                    VariableBinding vb = response.get(i);
                    res.add(String.valueOf(vb.getVariable()));
                }
            }
            return res.toArray(new String[0]);
        } catch (Exception e) {
            res.add("Error: " + e.getMessage());
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
    	if (authProt == AuthMD5.ID) {
    		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
    	}
    	else if (authProt == AuthSHA.ID) {
    		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
    	}
    	Snmp snmp= null;
    	ArrayList<String> res = new ArrayList<>();
    	
    	try {
    		DefaultUdpTransportMapping transport  = new DefaultUdpTransportMapping();
    		snmp = new Snmp(transport);
    		
        	USM usm = new USM(
        			SecurityProtocols.getInstance(),
        			new OctetString(MPv3.createLocalEngineID()),
        			0
    		);
        	usm.addUser(
        			new OctetString(username),
        			usr
			);
        	
        	SecurityModels.getInstance().addSecurityModel(usm);
        	
        	snmp.listen();
        	
        	/*snmp.getUSM().addUser(
        			new OctetString(username),
        			usr
			);*/
        	
        	pdu.setType(PDU.GET);
        	
        	ResponseEvent respEvent = snmp.send(pdu, target);
        	PDU response = respEvent.getResponse();
        	
            if (response == null) {
                res.add("Error: no Response");
            } else {
                for (int i = 0; i < response.size(); i++) {
                    VariableBinding vb = response.get(i);
                    res.add(String.valueOf(vb.getVariable()));
                }
            }
            return res.toArray(new String[0]);
    	} catch (Exception e) {
            res.add("Error: " + e.getMessage());
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

}
