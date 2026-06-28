## Event Count rules

These are rules that count certain events and alert if too many or not enough number of these events occur within a timeframe.
Common examples of detecting many events within a certain time period are for detecting password guessing attacks, password spray attacks and denial of service attacks.
You could also use these rules to detect log source reliability issues, such as when certain events fall below a certain threshold.

### Event Count rule example:

The following example uses two rules to detect password guessing attacks.
There will be an alert when the referenced rule matches 5 or more times within 5 minutes and the `IpAddress` field is the same for those events.

> Note that we have only included the necessary fields in order to understand the concept.
> The full rule that this example is based on is located [here](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) for your reference.

### Event Count correlation rule:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Failed Logon - Incorrect Password rule:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Deprecated `count` rule example:

The above correlation and referenced rules provide the same results as the following rule which uses the older `count` modifier:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Event Count rule output:

The rules above will create the following output:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Value Count rules

These rules counts the same events within a time frame with  **different** values of a given field.

Examples:
- Network scans where a single source IP address tries to connect to many different destination IP addresses and/or ports.
- Password spraying attacks where a single source fails to authenticate with many different users.
- Detect tools like BloodHound that enumerate many high-privilege AD groups within a short time frame.

### Value Count rule example:

The following rule detects when an attacker is trying to guess usernames.
That is, when the **same** source IP address (`IpAddress`) fails to logon with more than 3 **different** usernames (`TargetUserName`) within 5 minutes.

> Note that we have only included the necessary fields in order to understand the concept.
> The full rule that this example is based on is located [here](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) for your reference.

### Value Count correlation rule:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Value Count Logon Failure (Non-existant User) rule:

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Deprecated `count` modifier rule:

The above correlation and referenced rules provide the same results as the following rule which uses the older `count` modifier:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Value Count rule output:

The rules above will create the following output:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Temporal Proximity rules

All events defined by the rules referred by the rule field must occur in the time frame defined by timespan.
The values of fields defined in `group-by` must all have the same value (ex: same host, user, etc...).

### Temporal Proximity rule example:

Example: Reconnaissance commands defined in three Sigma rules are invoked in arbitrary order within 5 minutes on a system by the same user.

### Temporal Proximity correlation rule:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Ordered Temporal Proximity rules

The `temporal_ordered` correlation type behaves like `temporal` and requires in addition that the events appear in the order provided in the `rules` attribute.

### Ordered Temporal Proximity rule example:

Example: many failed logins as defined above are followed by a successful login by of the same user account within 1 hour:

### Ordered Temporal Proximity correlation rule:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Notes on correlation rules

1. You should include all of your correlation and referenced rules in a single file and separate them with a YAML separator of `---`.

2. By default, referenced correlation rules will not be outputted. If you want to see the output of the referenced rules, then you need to add `generate: true` under `correlation`. This is very useful to turn on and check when creating correlation rules.

    Example:
    ```
    correlation:
        generate: true
    ```
3. You can use alias names instead of rule IDs when referencing rules in order to make things easier to understand.

4. You can reference multiple rules.

5. You can use multiple fields in `group-by`. If you do, then all of the values in those fields need to be the same or else you will not get an alert. Most of the time, you will write rules that filter on certain fields with `group-by` in order to reduce false positives, however, it is possible to omit `group-by` to create a more generic rule.

6. The timestamp of the correlation rule will be the very beginning of the attack so you should check events after that to confirm if it is a false positive or not.
