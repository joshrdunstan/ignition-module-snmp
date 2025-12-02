# Snmp-Ignition-Module
A module that allows the user to use snmp operations in scripts

This module has been migrated to gradle from Maven, so the namespace has changed.

## Available Operations

As of now there are four operations available: SNMP Get, GetV3, Walk and WalkV3.

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
This performs a get operation using SNMPv1, with a timeout of 2000ms and 2 retries.

### For GetV3 and WalkV3

| Parameter | Description | Default |
|-----------|-------------|---------|
| `timeout` | Timeout in milliseconds | 3000 |
| `retry` | Number of retries | 1 |
| `privKey` | Separate privacy key/password | Same as auth password |

**Example:**
```python
system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'myUser', 'authPassword', 6, 4, 'timeout=2000', 'retry=2')
```

**Example with separate privacy key:**
```python
system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'myUser', 'authPassword', 6, 4, 'privKey=myPrivacyKey')
```
By default, the privacy key is the same as the authentication password. Use `privKey` to specify a different privacy key for encryption.

## SNMPv3 Security Parameters

### Authorization Level (authLevel)

| Value | Description |
|-------|-------------|
| 1 | No authorization and no privacy |
| 2 | Authorization and no privacy |
| 3 | Authorization and privacy |

If a value outside the range is specified, it defaults to no authorization and no privacy.

### Authorization Protocol (authProt)

| Value | Protocol | Notes |
|-------|----------|-------|
| 1 | MD5 | ⚠️ No longer safe, should not be used |
| 2 | SHA | ⚠️ No longer safe, should not be used |
| 3 | HMAC128SHA224 | |
| 4 | HMAC192SHA256 | |
| 5 | HMAC256SHA384 | |
| 6 | HMAC384SHA512 | Default if invalid value |

With no authorization selected in the authorization level, this parameter is still required but will not be used.

### Privacy Protocol (privProt)

| Value | Protocol |
|-------|----------|
| 1 | DES |
| 2 | AES128 |
| 3 | AES192 |
| 4 | AES256 (default if invalid value) |

With no privacy selected in the authorization level, this parameter is still required but will not be used.

## Complete Examples

```python
# Simple SNMPv2c get
result = system.snmp.get('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 'public')

# SNMPv2c walk with custom timeout
result = system.snmp.walk('192.168.1.1', 161, '1.3.6.1.2.1.1', 'public', 'timeout=5000')

# SNMPv3 get with auth and privacy (same password for both)
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'admin', 'secretPass', 6, 4)

# SNMPv3 get with separate privacy key
result = system.snmp.getV3('192.168.1.1', 161, ['1.3.6.1.2.1.1.1.0'], 3, 'admin', 'authPass', 6, 4, 'privKey=privPass')

# SNMPv3 walk with all options
result = system.snmp.walkV3('192.168.1.1', 161, '1.3.6.1.2.1.1', 3, 'admin', 'authPass', 6, 4, 'privKey=privPass', 'timeout=5000', 'retry=3')
```
