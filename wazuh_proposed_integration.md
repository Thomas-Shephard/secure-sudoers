# Proposed Wazuh Integration for Secure-Sudoers

This document outlines the technical strategy for integrating `secure-sudoers` with the Wazuh SIEM platform. This integration provides real-time visibility into privilege escalation, automated response to policy violations, and file integrity monitoring for security policies.

---

## 1. Architectural Overview

The integration leverages three core Wazuh capabilities:
1.  **Log Analysis:** Ingesting structured JSON events from `secure-sudoers` via the local system logger.
2.  **File Integrity Monitoring (FIM):** Monitoring the `POLICY.md` file for unauthorized modifications.
3.  **Active Response:** Automatically taking action (e.g., locking a user account) when critical policy violations occur.

---

## 2. Telemetry & Logging Configuration

`secure-sudoers` already supports structured JSON logging. To integrate with Wazuh, the application should be configured to output JSON to `syslog`.

### Secure-Sudoers Policy Change (`POLICY.md`)
Update the global settings to ensure logs are sent to the system logger in JSON format:

```yaml
global:
  logging:
    destination: "syslog"
    format: "json"
    level: "info"
```

### Wazuh Agent Configuration (`ossec.conf`)
Configure the Wazuh agent on the endpoint to monitor the system log (e.g., `/var/log/auth.log` or `/var/log/syslog` depending on your OS) where `secure-sudoers` events will land.

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

---

## 3. Custom Wazuh Decoders & Rules

Wazuh's native JSON decoder will automatically parse the `SecurityEvent` fields. You only need to define **Rules** to trigger alerts based on the `event_id` field.

### Define Custom Rules (`/var/ossec/etc/rules/local_rules.xml`)

Add these rules to the Wazuh Manager to categorize `secure-sudoers` events:

```xml
<group name="secure-sudoers,privilege_escalation,">
  <!-- Base rule for all secure-sudoers events -->
  <rule id="110000" level="0">
    <decoded_as>json</decoded_as>
    <field name="event_id">^SEC-</field>
    <description>Secure-Sudoers event grouping.</description>
  </rule>

  <!-- Access Granted (SEC-101) -->
  <rule id="110001" level="3">
    <if_sid>110000</if_sid>
    <field name="event_id">SEC-101</field>
    <description>Secure-Sudoers: Privilege escalation granted for user $(identity.user) to run $(context.binary_path).</description>
    <group>pci_dss_10.2.2,pci_dss_10.2.5,gpg13_7.1,gdpr_IV_32.2,</group>
  </rule>

  <!-- Access Denied (SEC-403) -->
  <rule id="110002" level="9">
    <if_sid>110000</if_sid>
    <field name="event_id">SEC-403</field>
    <description>Secure-Sudoers: Access DENIED for user $(identity.user). Reason: $(denial_reason).</description>
    <group>pci_dss_10.2.4,pci_dss_10.2.5,invalid_login,gdpr_IV_35.7.d,</group>
  </rule>

  <!-- Policy Violation / Exploit Attempt (SEC-500) -->
  <rule id="110003" level="12">
    <if_sid>110000</if_sid>
    <field name="event_id">SEC-500</field>
    <description>Secure-Sudoers: CRITICAL policy violation or exploit attempt detected from user $(identity.user)!</description>
    <group>exploit_attempt,pci_dss_11.4,gdpr_IV_35.7.d,</group>
  </rule>
</group>
```

---

## 4. File Integrity Monitoring (FIM)

To ensure the `POLICY.md` file isn't tampered with, configure Wazuh `syscheck`.

### Wazuh Agent Configuration (`ossec.conf`)

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/secure-sudoers/POLICY.md</directories>
</syscheck>
```

---

## 5. Active Response (Automated Mitigation)

You can configure Wazuh to automatically "shun" a user or lock an account if they trigger a high-severity alert (e.g., multiple `SEC-403` events or a single `SEC-500`).

### Active Response Script (`/var/ossec/active-response/bin/block-user.sh`)

```bash
#!/bin/bash
# Simple script to lock a user account via passwd -l
# Wazuh passes JSON alert to STDIN

read -r INPUT
USER_TO_BLOCK=$(echo "$INPUT" | jq -r '.data.identity.user')

if [ "$USER_TO_BLOCK" != "null" ]; then
    /usr/sbin/passwd -l "$USER_TO_BLOCK"
    echo "$(date) - Blocked user $USER_TO_BLOCK due to Secure-Sudoers violation" >> /var/ossec/logs/active-responses.log
fi
```

### Enable Active Response (`/var/ossec/etc/ossec.conf` on Manager)

```xml
<command>
  <name>block-user</name>
  <executable>block-user.sh</executable>
  <expect>user</expect>
</command>

<active-response>
  <command>block-user</command>
  <location>local</location>
  <rules_id>110003</rules_id> <!-- Trigger on SEC-500 -->
</active-response>
```

---

## 6. Testing & Validation

### Step 1: Verify Log Output
Run a command through `secure-sudoers` and verify it appears in syslog as JSON:
```bash
tail -f /var/log/auth.log | grep secure-sudoers
```

### Step 2: Test Wazuh Rule Matching
Use the `wazuh-logtest` utility on the Wazuh Manager to ensure the JSON is parsed and triggers the correct rule:
```bash
/var/ossec/bin/wazuh-logtest
# Paste a JSON log line from SEC-403 here
```

### Step 3: Test FIM
Modify `POLICY.md` and verify a "File modified" alert appears in the Wazuh Dashboard.

### Step 4: Test Active Response
Simulate a critical violation (e.g., a path traversal attempt) and verify the `block-user.sh` script executes.
