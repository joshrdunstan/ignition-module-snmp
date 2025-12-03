# Snmp-Ignition-Module
A module that allows the user to use SNMP operations in Ignition scripts.

**Version:** 1.2.11

This module has been migrated to Gradle from Maven, so the namespace has changed.

## Available Operations

Four operations are available: SNMP Get, GetV3, Walk and WalkV3.

### SNMPv1/v2c Operations

**Get** - Retrieve values for specific OIDs:
```python
system.snmp.get('address', port, ['OID1', 'OID2', ...], 'community')
```
Returns a python list with the length equal to the number of OIDs provided.

**Walk** - Walk a subtree from a starting OID:
```python
system.snmp.walk('address', port, 'startOID', 'community')
```
Returns a python list with all OIDs and their current values under the specified OID.

### SNMPv3 Operations

**GetV3** - Retrieve values using SNMPv3 security:
```python
system.snmp.getV3('address', port, ['OID1', 'OID2', ...], authLevel, 'user', 'password', authProt, privProt)
```
Returns a python list with the length equal to the number of OIDs provided.

**WalkV3** - Walk a subtree using SNMPv3 security:
```python
system.snmp.walkV3('address', port, 'startOID', authLevel, 'user', 'password', authProt, privProt)
```
Returns a python list with all OIDs and their current values under the specified OID.

## Optional Parameters

You can specify additional options by adding `'var=value'` as extra parameters at the end of any command.

### For Get and Walk (v1/v2c)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `version` | SNMP version (1, 2c, or 3) | 2c |
| `timeout` | Timeout in milliseconds | 3000 |
| `retry` | Number of retries | 1 |

**Example:**
```python
system.snmp.get('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 'public', 'version=1', 'timeout=2000', 'retry=2')
```

### For GetV3 and WalkV3

| Parameter | Description | Default |
|-----------|-------------|---------|
| `timeout` | Timeout in milliseconds | 3000 |
| `retry` | Number of retries | 1 |
| `privKey` | Separate privacy key/password (only used when authLevel=3) | Same as auth password |

**Example with authentication and privacy (authLevel=3):**
```python
system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'myUser', 'authPassword', 6, 4, 'timeout=5000')
```

**Example with separate privacy key:**
```python
system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'myUser', 'authPassword', 6, 4, 'privKey=myPrivacyKey')
```

**Example with authentication only (authLevel=2):**
```python
# Note: privProt parameter is required but ignored when authLevel=2
system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 2, 'myUser', 'authPassword', 2, 1)
```

## SNMPv3 Security Parameters

### Security Level (authLevel)

| Value | Name | Description | Parameters Used |
|-------|------|-------------|-----------------|
| 1 | noAuthNoPriv | No authentication, no privacy | Only username |
| 2 | authNoPriv | Authentication only | username, password, authProt |
| 3 | authPriv | Authentication and privacy | All parameters |

**Important:** The `privProt` and `privKey` parameters are **only used when authLevel=3**. For authLevel=1 or 2, these parameters are required in the function call but will be ignored.

### Authentication Protocol (authProt)

| Value | Protocol | Notes |
|-------|----------|-------|
| 1 | MD5 | ⚠️ No longer safe, should not be used |
| 2 | SHA | ⚠️ Legacy, consider using SHA-2 variants |
| 3 | HMAC128SHA224 | SHA-2 variant |
| 4 | HMAC192SHA256 | SHA-2 variant (recommended) |
| 5 | HMAC256SHA384 | SHA-2 variant |
| 6 | HMAC384SHA512 | SHA-2 variant (default if invalid value) |

### Privacy Protocol (privProt)

| Value | Protocol | Notes |
|-------|----------|-------|
| 1 | DES | ⚠️ Legacy, consider using AES |
| 2 | AES128 | Recommended |
| 3 | AES192 | |
| 4 | AES256 | Default if invalid value |

## Error Codes

Error messages are prefixed with codes to help identify issues:

### v1/v2c Errors
| Code | Function | Description |
|------|----------|-------------|
| W001 | walk() | Tree event error during walk |
| W002 | walk() | IOException during walk |
| G001 | get() | No response from device |
| G002 | get() | Exception during get |

### v3 Errors
| Code | Function | Description |
|------|----------|-------------|
| WV01 | walkV3() | Engine ID discovery failed (warning) |
| WV02 | walkV3() | Tree event error during walk |
| WV03 | walkV3() | Exception during walk |
| GV01 | getV3() | Response error with message |
| GV02 | getV3() | No response from device |
| GV03 | getV3() | PDU error status returned |
| GV04 | getV3() | Exception during get |

## Complete Examples

```python
# Simple SNMPv2c get
result = system.snmp.get('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 'public')

# SNMPv2c walk with custom timeout
result = system.snmp.walk('192.168.1.1', 161, '1.3.6.1.2.1.1', 'public', 'timeout=5000')

# SNMPv3 with no auth/no priv (authLevel=1)
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 1, 'user', '', 1, 1)

# SNMPv3 with auth only (authLevel=2) - SHA authentication
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 2, 'admin', 'authPass', 2, 1)

# SNMPv3 with auth and privacy (authLevel=3) - SHA-512 + AES256
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'admin', 'authPass', 6, 4)

# SNMPv3 with separate privacy key
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'admin', 'authPass', 6, 4, 'privKey=privPass')

# SNMPv3 walk with all options
result = system.snmp.walkV3('192.168.1.1', 161, '1.3.6.1.2.1.1', 3, 'admin', 'authPass', 6, 4, 'privKey=privPass', 'timeout=5000', 'retry=3')
```

## Troubleshooting

### Common Errors

**"No Response from device"**
- Check network connectivity (can you ping the device?)
- Verify the IP address and port (default SNMP port is 161)
- Check firewall rules
- Try increasing the timeout: `'timeout=10000'`

**"Unknown security name"**
- Verify the username matches exactly what's configured on the device
- Check that the security level matches the device configuration

**"Unsupported security level"**
- The device may not support the requested security level
- If using authLevel=2, make sure the device is configured for authNoPriv
- If using authLevel=3, make sure the device is configured for authPriv

**"Authentication failure"**
- Verify the password is correct
- Check that the authentication protocol matches (MD5, SHA, SHA-256, etc.)

**"Decryption error" or "Privacy error"**
- Verify the privacy password/key is correct
- Check that the privacy protocol matches (DES, AES128, AES256, etc.)
- If using a separate privKey, ensure it's specified correctly: `'privKey=yourKey'`
