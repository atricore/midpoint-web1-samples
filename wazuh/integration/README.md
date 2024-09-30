# Wazuh Integration 

Enable this integratin for a rule for example, in your Wazuh configuration file (ossec.conf), in the master/worker nodes:

```xml
  <integration>
    <name>custom-midpoint</name>
    <hook_url>http://mp-server-svc/midpoint</hook_url>
    <alert_format>json</alert_format>
    <rule_id>100903</rule_id>
  </integration>
```

The sample integration looks for a data.principal attribute in the alert to the the username, modify the code to match your needs
