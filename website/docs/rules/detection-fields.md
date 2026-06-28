# Detection field

## Selection fundamentals

First, the fundamentals of how to create a selection rule will be explained.

### How to write AND and OR logic

To write AND logic, we use nested dictionaries.
The detection rule below defines that **both conditions** have to be true in order for the rule to match.

- EventID has to exactly be `7040`.
- **AND**
- Channel has to exactly be `System`.

```yaml
detection:
    selection:
        Event.System.EventID: 7040
        Event.System.Channel: System
    condition: selection
```

To write OR logic, we use lists (Dictionaries that start with `-`).
In the detection rule below, **either one** of the conditions will result in the rule being triggered.

- EventID has to exactly be `7040`.
- **OR**
- Channel has to exactly be `System`.

```yaml
detection:
    selection:
        - Event.System.EventID: 7040
        - Event.System.Channel: System
    condition: selection
```

We can also combine `AND` and `OR` logic as shown below.
In this case, the rule matches when the following two conditions are both true.

- EventID is either exactly `7040` **OR** `7041`.
- **AND**
- Channel is exactly `System`.

```yaml
detection:
    selection:
        Event.System.EventID:
          - 7040
          - 7041
        Event.System.Channel: System
    condition: selection
```

### Eventkeys

The following is an excerpt of a Windows event log, formatted in the original XML.
The `Event.System.Channel` field in the rule file example above refers to the original XML tag: `<Event><System><Channel>System<Channel><System></Event>`
Nested XML tags are replaced by tag names seperated by dots (`.`).
In hayabusa rules, these field strings connected together with dots are refered to as  `eventkeys`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7040</EventID>
        <Channel>System</Channel>
    </System>
    <EventData>
        <Data Name='param1'>Background Intelligent Transfer Service</Data>
        <Data Name='param2'>auto start</Data>
    </EventData>
</Event>
```

#### Eventkey Aliases

Long eventkeys with many `.` seperations are common, so hayabusa will use aliases to make them easier to work with. Aliases are defined in the `rules/config/eventkey_alias.txt` file. This file is a CSV file made up of `alias` and `event_key` mappings. You can rewrite the rule above as shown below with aliases making the rule easier to read.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
    condition: selection
```

#### Caution: Undefined Eventkey Aliases

Not all eventkey aliases are defined in `rules/config/eventkey_alias.txt`. If you are not getting the correct data in the `details` (`Alert details`) message, and instead are getting `n/a` (not available) or if the selection in your detection logic is not working properly, then you may need to update `rules/config/eventkey_alias.txt` with a new alias.

### How to use XML attributes in conditions

XML elements may have attributes set by adding a space to the element. For example, `Name` in `Provider Name` below is an XML attribute of the `Provider` element.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
        <EventID>4672</EventID>
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
</Event>
```

To specify XML attributes in an eventkey, use the format `{eventkey}_attributes.{attribute_name}`. For example, to specify the `Name` attribute of the `Provider` element in a rule file, it would look like this:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4672
        Event.System.Provider_attributes.Name: 'Microsoft-Windows-Security-Auditing'
    condition: selection
```

### grep search

Hayabusa can perform grep searches in Windows event log files by not specifying any eventkeys.

To do a grep search, specify the detection as shown below. In this case, if the strings `mimikatz` or `metasploit` are included in the Windows Event log, it will match. It is also possible to specify wildcards.

```yaml
detection:
    selection:
        - mimikatz
        - metasploit
```

> Note: Hayabusa internally converts Windows event log data to JSON format before processing the data so it is not possible to match on XML tags.

### EventData

Windows event logs are divided into two parts: the `System` part where the fundamental data (Event ID, Timestamp, Record ID, Log name (Channel)) is written, and the `EventData` or `UserData` part where arbitrary data is written depending on the Event ID.
One problem that arises often is that the names of the fields nested in `EventData` are all called `Data` so the eventkeys described so far cannot distinguish between `SubjectUserSid` and `SubjectUserName`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <TimeCreated SystemTime='2021-10-20T10:16:18.7782563Z' />
        <EventRecordID>607469</EventRecordID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-1-11-1111111111-111111111-1111111111-1111</Data>
        <Data Name='SubjectUserName'>hayabusa</Data>
        <Data Name='SubjectDomainName'>DESKTOP-HAYABUSA</Data>
        <Data Name='SubjectLogonId'>0x11111111</Data>
    </EventData>
</Event>
```

To deal with this problem, you can specify the value assigned in `Data Name`. For example, if you want to use `SubjectUserName` and `SubjectDomainName` in the EventData as a condition of a rule, you can describe it as follows:

```yaml
detection:
    selection:
        Channel: System
        EventID: 7040
        Event.EventData.SubjectUserName: hayabusa
        Event.EventData.SubjectDomainName: DESKTOP-HAYBUSA
    condition: selection
```

### Abnormal patterns in EventData

Some of the tags nested in `EventData` do not have a `Name` attribute.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Security />
    </System>
    <EventData>
        <Data>Available</Data>
        <Data>None</Data>
        <Data>NewEngineState=Available PreviousEngineState=None (...)</Data>
    </EventData>
</Event>
```

To detect an event log like the one above, you can specify an eventkey named `Data`.
In this case, the condition will match as long as any one of the nested `Data` tags equals `None`.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 5379
        Data: None
    condition: selection
```

#### Outputting field data from multiple field names with the same name

Some events will save their data to field names all called `Data` like in the previous example.
If you specify `%Data%` in `details:`, all of the data will be outputted in an array.

For example:
`["rundll32.exe","6.1.7600.16385","4a5bc637","KERNELBASE.dll","6.1.7601.23392","56eb2fb9","c0000005"]`

If you want to print out just the first `Data` field data, you can specify `%Data[1]%` in your `details:` alert string and only `rundll32.exe` will be outputted.

## Field Modifiers

A pipe character can be used with eventkeys as shown below for matching strings.
All of the conditions we have described so far use exact matches, but by using field modifiers, you can describe more flexible detection rules.
In the following example, if a value of `Data` contains the string  `EngineVersion=2`, it will match the condition.

```yaml
detection:
    selection:
        Channel: 'Windows PowerShell'
        EventID: 400
        Data|contains: 'EngineVersion=2'
    condition: selection
```

String matches are case insensitive. However, they become case sensitive whenever `|re` or `|equalsfield` are used.

### Supported Sigma Field Modifiers

Hayabusa is currently the only open-source tool that fully supports all of the Sigma specification.

You can check the current status of all of the supported field modifiers as well as how many times these modifiers are used in Sigma and Hayabusa rules at https://github.com/Yamato-Security/hayabusa-rules/blob/main/field-modifiers.md .
This document is dynamically updated every time there is an update to Sigma or Hayabusa rules.

- `'|all':`: This field modifier is different from those above because it does not get applied to a certain field but to all fields.

    In this example, both strings `Keyword-1` and `Keyword-2` need to exist but can exist anywhere in any field:
    ```
    detection:
        keywords:
            '|all':
                - 'Keyword-1'
                - 'Keyword-2'
        condition: keywords
    ```
- `|base64offset|contains`: Data will be encoded to base64 in three different ways depending on its position in the encoded string. This modifier will encoded a string to all three variations and check if the string is encoded somewhere in the base64 string.
- `|cased`: Makes the search case-sensitive.
- `|cidr`: Checks if a field value matches on a IPv4 or IPv6 CIDR notation. (Ex: `192.0.2.0/24`)
- `|contains`: Checks if a field value contains a certain string.
- `|contains|all`: Checks if multiple words are contained in the data.
- `|contains|all|windash`: Same as `|contains|windash` but all of the keywords need to be present.
- `|contains|cased`: Checks if a field value contains a certain case-sensitive string.
- `|contains|expand`: Checks if a field value contains a string in the `expand` config file inside `/config/expand/`.
- `|contains|windash`: Will check the string as-is, as well as convert the first `-` character to `/`, `–` (en dash), `—` (em dash), and `―` (horizontal bar) character permutations.
- `|endswith`: Checks if a field value ends with a certain string.
- `|endswith|cased`: Checks if a field value ends with a certain case-sensitive string.
- `|endswith|windash`: Checks the end of the string and performs variations for dashes.
- `|exists`: Checks if a field exists.
- `|expand`: Checks if a field value equals a string in the `expand` config file inside `/config/expand/`.
- `|fieldref`: Checks to see if the values in two fields are the same. You can use `not` in the `condition` if you want to check if two fields are different.
- `|fieldref|contains`: Checks to see if the value of one field is contained in another field.
- `|fieldref|endswith`: Check if the field on the left ends with the string of the field on the right. You can use `not` in the `condition` to check if they are different.
- `|fieldref|startswith`: Check if the field on the left starts with the string of the field on the right. You can use `not` in the `condition` to check if they are different.
- `|gt`: Checks if a field value is greater than a certain number.
- `|gte`: Checks if a field value is greater than or equal to a certain number.
- `|lt`: Checks if a field value is less than a certain number.
- `|lte`: Checks if a field value is less than or equal to a certain number.
- `|re`: Use case-sensitive regular expressions. (We are using the regex crate so please out the documentation at <https://docs.rs/regex/latest/regex/#syntax> to learn how to write supported regular expressions.)
    > Caution: [Regular expression syntax in Sigma rules](https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-modifiers-appendix.md#regular-expression) uses PCRE with certain metacharacters for character classes, lookbehind, atomic grouping, etc... being unsupported. The Rust regex crate should be able to use all regular expressions in Sigma rules but there is a possibility of incompatibility. 
- `|re|i`: (Insensitive) Use case-insensitive regular expressions.
- `|re|m`: (Multi-line) Match across multiple lines. `^` / `$` match the start/end of line.
- `|re|s`: (Single-line) dot (`.`) matches all characters, including the newline character.
- `|startswith`: Checks if a field value starts with a certain string.
- `|startswith|cased`: Checks if a field value starts with a certain case-sensitive string.
- `|utf16|base64offset|contains`: Checks to see if a certain UTF-16 string is encoded inside a base64 string.
- `|utf16be|base64offset|contains`: Checks to see if a certain UTF-16 big-endian string is encoded inside a base64 string.
- `|utf16le|base64offset|contains`: Checks to see if a certain UTF-16 little-endian string is encoded inside a base64 string.
- `|wide|base64offset|contains`: Alias for `utf16le|base64offset|contains`, checking for UTF-16 little-endian strings.

### Deprecated Field Modifiers

The following modifiers are now deprecated and replaced by modifiers that adhere more to the sigma specifications.

- `|equalsfield`: Now is replaced by `|fieldref`.
- `|endswithfield`: Now is replaced by `|fieldref|endswith`.

### Expand Field Modifiers

The `expand` field modifiers are unique in that they are the only field modifier that requires configuration beforehand to use.
For example, they use placeholders such as `%DC-MACHINE-NAME%` and require a config file named `/config/expand/DC-MACHINE-NAME.txt` that contains all of the possible DC machine names.

How to configure this is explained more in detail [here](https://github.com/Yamato-Security/hayabusa?tab=readme-ov-file#expand-list-command).

## Wildcards

Wildcards can be used in eventkeys. In the example below, if `ProcessCommandLine` starts with the string "malware", the rule will match.
The specification is fundamentally the same as sigma rule wildcards so will be case insensitive.

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4688
        ProcessCommandLine: malware*
    condition: selection
```

The following two wildcards can be used.

- `*`: Matches any string of zero or more characters. (Internally it is converted to the regular expression `.*`)
- `?`: Matches any single character. (Internally converted to the regular expression `.`)

About escaping wildcards:

- Wildcards (`*` and `?`) can be escaped by using a backslash: `\*`, `\?`.
- If you want to use a backslash right before a wildcard then write `\\*` or `\\?`.
- Escaping is not required if you are using backslashes by themselves.

## null keyword

The `null` keyword can be used to check if field does not exist.

```yaml
detection:
    selection:
        EventID: 4688
        ProcessCommandLine: null
    condition: selection
```

Note: This is different from `ProcessCommandLine: ''` which checks if the value of a field is empty.

## condition

With the notation we explained above, you can express `AND` and `OR` logic but it will be confusing if you are trying to define complex logic.
When you want to make more complex rules, you should use the `condition` keyword as shown below.

```yaml
detection:
  SELECTION_1:
    EventID: 3
  SELECTION_2:
    Initiated: 'true'
  SELECTION_3:
    DestinationPort:
    - '4444'
    - '666'
  SELECTION_4:
    Image: '*\Program Files*'
  SELECTION_5:
    DestinationIp:
    - 10.*
    - 192.168.*
    - 172.16.*
    - 127.*
  SELECTION_6:
    DestinationIsIpv6: 'false'
  condition: (SELECTION_1 and (SELECTION_2 and SELECTION_3) and not ((SELECTION_4 or (SELECTION_5 and SELECTION_6))))
```

The following expressions can be used for `condition`.

- `{expression1} and {expression2}`: Require both {expression1} AND {expression2}
- `{expression1} or {expression2}`: Require either {expression1} OR {expression2}
- `not {expression}`: Reverse the logic of {expression}
- `( {expression} )`: Set precedance of {expression}. It follows the same precedance logic as in mathematics.

In the above example, selection names such as `SELECTION_1`, `SELECTION_2`, etc... are used but they can be named anything as long as they only contain the following characters: `a-z A-Z 0-9 _`
> However, please use the standard convention of `selection_1`, `selection_2`, `filter_1`, `filter_2`, etc... to make things easy to read whenever possible.

## not logic

Many rules will result in false positives so it is very common to have a selection for signatures to search for but also a filter selection to not alert on false positives.
For example:

```yaml
detection:
    selection:
        Channel: Security
        EventID: 4673
    filter:
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\System32\lsass.exe
        - ProcessName: C:\Windows\System32\audiodg.exe
        - ProcessName: C:\Windows\System32\svchost.exe
        - ProcessName: C:\Windows\System32\mmc.exe
        - ProcessName: C:\Windows\System32\net.exe
        - ProcessName: C:\Windows\explorer.exe
        - ProcessName: C:\Windows\System32\SettingSyncHost.exe
        - ProcessName: C:\Windows\System32\sdiagnhost.exe
        - ProcessName|startswith: C:\Program Files
        - SubjectUserName: LOCAL SERVICE
    condition: selection and not filter
```

# Sigma correlations

We have implemented all of the Sigma version 2.0.0 correlations as defined [here](https://github.com/SigmaHQ/sigma-specification/blob/version_2/specification/sigma-correlation-rules-specification.md).

Supported correlations:

- Event Count (`event_count`)
- Value Count (`value_count`)
- Temporal Proximity (`temporal`)
- Ordered Temporal Proximity (`temporal_ordered`)

The new "metrics" correlation rules (`value_sum`, `value_avg`, `value_percentile`) released on September 12, 2025 in Sigma version 2.1.0 are currently not supported.
