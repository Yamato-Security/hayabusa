# Table of Contents

- [Table of Contents](#table-of-contents)
- [Analysing Hayabusa Results with JQ](#analysing-hayabusa-results-with-jq)
  - [Author](#author)
  - [About](#about)
  - [Installing JQ](#installing-jq)
  - [About the JSON Format](#about-the-json-format)
  - [About the JSON and JSONL Formats with Hayabusa](#about-the-json-and-jsonl-formats-with-hayabusa)
  - [Creating JSON Results Files](#creating-json-results-files)
    - [Benefits of Using Details Over AllFieldInfo](#benefits-of-using-details-over-allfieldinfo)
  - [JQ Lessons/Recipes](#jq-lessonsrecipes)
    - [1. Manual Checking with JQ and Less In Color](#1-manual-checking-with-jq-and-less-in-color)
    - [2. Metrics](#2-metrics)
    - [3. Filtering on Certain Data](#3-filtering-on-certain-data)
    - [4. Saving Output to CSV](#4-saving-output-to-csv)
    - [5. Finding Dates With Most Alerts](#5-finding-dates-with-most-alerts)
    - [6. Reconstructing PowerShell Logs](#6-reconstructing-powershell-logs)


# Analysing Hayabusa Results with JQ

## Author

Zach Mathis ([@yamatosecurity](https://twitter.com/yamatosecurity)) - 2022/12/21

## About

Being able to identify, extract out and create metrics against important fields in logs is an essential skill for DFIR and threat hunting analysts.
Hayabusa results are usually saved to `.csv` files in order to import into programs like Excel or Timeline Explorer for timeline analysis.
However, when there are hundreds or more of the same event, it become impractical or impossible to manually check them.
In these situations, analysts will usually sort and count similar types of data looking for outliers.
This is also known as long tail analysis, stack ranking, frequency analysis, etc...
This can be accomplished with Hayabusa by outputting the results to `.json` or `.jsonl` files and then analyze with `jq`.

For example, an analyst could compare the installed services on all of the workstations in an organization.
While it is possible that a certain piece of malware could get installed on every workstation, it is more than likely that it will only exist on a handful of systems.
In this case, the services that are installed on all systems are more likely to be benign, while rare services will tend to be more suspicious and should be periodically checked.

Another use case is to help determine how suspicious something is.
For example, an analyst could analyze the `4625` failed logon logs to determine how many times a certain IP address failed to logon.
If there were only a few failed logons, then it is likely that an administrator just mistyped their password.
However, if there were hundreds or more failed logons in a short period of time by a certain IP address, then it is likely that the IP address is malicious.

Learning how to use `jq` will help you master not just analyzing Windows event logs, but all JSON formatted logs.
Now that JSON has become a very popular log format and most cloud providers use it for their logs, being able to parse them with `jq` has become an essential skill for the modern security engineer.

In this guide, I will fist explain how to utilize `jq` for those who have never used it before and then explain more complex usages along with real world examples.
I recommend using linux, macOS or linux on Windows in order to be able to combine `jq` with other useful commands such as `sort`, `uniq`, `grep`, `sed`, etc...

## Installing JQ

Please refer to [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/).

## About the JSON Format

JSON logs are a list of objects contained in curly brackets `{` `}`.
Inside these objects are key-value pairs separated by colons.
The keys must be strings but the values may be one of the following:
  * string (Ex: `"string"`)
  * number (Ex: `10`)
  * another object (Ex: `{ xxxx }`)
  * array (Ex: `["string", 10]`)
  * boolean (Ex: `true`, `false`)
  * `null`

You can nest as many objects inside objects.

Example:
```
{
    "Timestamp": "2016-08-19 08:06:57.658 +09:00",
    "Computer": "IE10Win7",
    "Channel": "Sec",
    "EventID": 4688,
    "Level": "info",
    "RecordID": 6845,
    "RuleTitle": "Proc Exec",
    "Details": {
        "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
        "Path": "C:\\Windows\\System32\\ipconfig.exe",
        "PID": "0xcf4",
        "User": "IE10WIN7$",
        "LID": "0x3e7"
    }
}
```

## About the JSON and JSONL Formats with Hayabusa

In earlier versions, Hayabusa would use the traditional JSON format of putting all of the `{ xxx }` log objects into one giant array.

Example:
```
[
    {
        "Timestamp": "2016-08-19 08:06:57.658 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6845,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "C:\\Windows\\system32\\ipconfig /release",
            "Path": "C:\\Windows\\System32\\ipconfig.exe",
            "PID": "0xcf4",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    },
    {
        "Timestamp": "2016-08-19 11:07:47.489 +09:00",
        "Computer": "IE10Win7",
        "Channel": "Sec",
        "EventID": 4688,
        "Level": "info",
        "RecordID": 6847,
        "RuleTitle": "Proc Exec",
        "Details": {
            "CmdLine": "taskhost.exe $(Arg0)",
            "Path": "C:\\Windows\\System32\\taskhost.exe",
            "PID": "0x228",
            "User": "IE10WIN7$",
            "LID": "0x3e7"
        }
    }
]
```

There are two problems with this.
The first issue is that `jq` queries will become more cumbersome as everything has to start with an extra `.[]` to tell it to look into that array.
The much bigger issue is that in order for anything to parse such logs, it is necessary to load in all of the data in the array.
This becomes a problem if you have very big JSON files and not an abundance of memory.
In order to lessen the required CPU and memory usage, the JSONL (JSON Lines) format, which does not put everything into a giant array, has become more popular.
Hayabusa outputs in JSON and JSONL formats, however the JSON format is not outputted inside an array anymore.
The only difference is that the JSON format is easier to read in a text editor or on the console, while the JSONL format stores every JSON object on one single line.
JSONL format will be slightly faster and smaller in size so is ideal if you are only going to import the logs into something else but not look at them.
JSON format is ideal if you are also going to do some manual checking.

## Creating JSON Results Files

In the 1.x version of Hayabusa, you can save the results in JSON with `-j -o results.json` or `-J -o results.jsonl`.

Hayabusa will use the default `standard` profile and only save the minimal amount of data for analysis in the `Details` object.
If you want to save all of the original field information in the .evtx logs, you can use the `all-field-info` profile with the option `--profile all-field-info`.
This will save all of the field information to the `AllFieldInfo` object.
If you want to save both the `Details` and `AllFieldInfo` objects just in case, you can use the `super-verbose` option.

### Benefits of Using Details Over AllFieldInfo

The first benefit of using `Details` over `AllFieldInfo` is that only the important fields are saved and the field names have been shortened to save file space.
The downside is that there is a possibility of missing data that you actually cared about but was missed.
The second benefit is that Hayabusa will save the fields in a more uniform manner.
For example, in original Windows logs, the username is usually in a `SubjectUserName` or `TargetUserName` field. 
However, sometimes the username will be in the `AccountName` field, sometimes the target user will actually be in the `SubjectUserName` field, etc...
Hayabusa tries to normalize these fields so an analyst only has to parse out a common name instead of having to understand the infinite amount of quirks and discrepancies between event IDs in Windows.

One example of this is the user field.
Hayabusa will normalize `SubjectUserName`, `TargetUserName`, `AccountName`, etc... in the following manner:
  * `SrcUser` (Source User): when an action happens **from** a remote user.
  * `TgtUser` (Target User): when an action happens **to** a user. (For example, a logon **to** a user.)
  * `User`: when an action happens by a currently logged in user.

Another example are processes.
In the original Windows event logs, the process field is referred to with multiple naming conventions: `ProcessName`, `Image`, `processPath`, `Application`, `WindowsDefenderProcessName`, etc...
The analyst will have to first be knowledgeable about all of the different field names, then extract out all the logs with these field names, then combine them together. 

An analyst can save a lot of time and trouble just using the normalized single `Proc` field that Hayabusa provides in the `Details` object.

## JQ Lessons/Recipes

I will now list several lessons/recipes of practical examples that may help you in your work.

### 1. Manual Checking with JQ and Less In Color

This is one of the first things to do to understand what fields are in the logs.
You could simply do a `less results.json` but a better way is the following:
`cat results.json | jq -C | less -R`

By passing to `jq`, it will neatly format all of the fields for you if they were not formated neatly to begin with.
By using the `-C` (color) option with `jq` and `-R` (raw output) option with less, you can scroll up and down in color.

### 2. Metrics

Hayabusa already has functionality to print the number and percent of events based on event IDs, however, this is also good to know how to do with `jq`.
This will let you customize the data you are taking metrics on.

Let's first extract a list of Event IDs with the following command:

`cat results.json | jq '.EventID'`

This will extract just the Event ID number from each log.
After `jq`, in single quotes just type a `.` and the field name you want to extract.
You should see a long list like this:

```
4624
4688
4688
4634
1337
1
1
1
1
10
27
11
11
```

Now lets pipe the results to the `sort` and `uniq -c` commands to count how many times the event IDs occurred:

`cat results.json | jq '.EventID' | sort | uniq -c`

The `-c` option for `uniq` will count how many times a unique event ID occurred.

You should see something like this:

```
 168 59
  23 6
  38 6005
  37 6006
   3 6416
 129 7
   1 7040
1382 7045
   2 770
 391 8
 ```

 The left is the count and the right is the Event ID.
 As you can see it is not sorted so hard to tell what event IDs happened the most.

 You can add a `sort -n` at the end to fix this:

`cat results.json | jq '.EventID' | sort | uniq -c | sort -n`

The `-n` option tells `sort` to sort by number.

You should see something like this:
```
 400 4624
 433 5140
 682 4103
1131 4104
1382 7045
2322 1
2584 5145
7135 4625
12277 4688
```

We can see that `4688` (Process creation) events were recorded the most.
The second most recorded event was `4625` (Failed Logon).

If you want to print the most recorded events at the top then you can reverse the sort with `sort -n -r` or `sort -nr`.
You can also just print the top 10 most recorded events by piping the results to `head -n 10`.

`cat results.json | jq '.EventID' | sort | uniq -c | sort -nr | head -n 10`

This will give you:
```
12277 4688
7135 4625
2584 5145
2322 1
1382 7045
1131 4104
 682 4103
 433 5140
 400 4624
 391 8
 ```

 You may know that EIDs (Event IDs) are not unique and you may have completely different events but the same Event ID.
 Therefore, it is important to also check the `Channel`.

 We can add this field information like this:

 `cat sample-super.json | jq -j '.Channel, " ", .EventID, "\n"' | sort | uniq -c | sort -nr | head -n 10`

 We add the `-j` (join) option to `jq` to join all the fields together delimited by commas and ending with a `\n` new line character.
 This will give us:
 ```
 12277 Sec 4688
7135 Sec 4625
2584 Sec 5145
2321 Sysmon 1
1382 Sys 7045
1131 PwSh 4104
 682 PwSh 4103
 433 Sec 5140
 400 Sec 4624
 391 Sysmon 8
 ```

 Note: `Security` is abbreviated to `Sec`, `System` to `Sys`, and `PowerShell` to `PwSh`.

We can add the rule title as follows:

`cat sample-super.json | jq -j '.Channel, " ", .EventID, " ", .RuleTitle, "\n"' | sort | uniq -c | sort -nr | head -n 10`

This will give us:
```
9714 Sec 4688 Proc Exec
3564 Sec 4625 Logon Failure (Wrong Password)
3561 Sec 4625 Metasploit SMB Authentication
2564 Sec 5145 NetShare File Access
1459 Sysmon 1 Proc Exec
1418 Sec 4688 Susp CmdLine (Possible LOLBIN)
 789 PwSh 4104 PwSh Scriptblock
 680 PwSh 4103 PwSh Pipeline Exec
 433 Sec 5140 NetShare Access
 342 Sec 4648 Explicit Logon
 ```

 You can now freely extract any data from the logs and count the occurrences.


### 3. Filtering on Certain Data

Many times you will want to filter on certain Event IDs, users, processes, LIDs(Logon IDs), etc...
You can do that with `select` inside the `jq` query.

For example, lets extract all of the `4624` successful logon events:

`cat results.json | jq 'select (.EventID == 4624)'`

This will return all of the JSON objects for EID `4624`:
```
{
  "Timestamp": "2021-12-12 16:16:04.237 +09:00",
  "Computer": "fs03vuln.offsec.lan",
  "Channel": "Sec",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventID": 4624,
  "Level": "info",
  "RecordID": 1160369,
  "RuleTitle": "Logon (Network)",
  "RuleAuthor": "Zach Mathis",
  "RuleCreationDate": "2020/11/08",
  "RuleModifiedDate": "2022/12/16",
  "Status": "stable",
  "Details": {
    "Type": 3,
    "TgtUser": "admmig",
    "SrcComp": "",
    "SrcIP": "10.23.123.11",
    "LID": "0x87249a8"
  },
  "RuleFile": "Sec_4624_Info_Logon-Type-3-Network.yml",
  "EvtxFile": "../hayabusa-sample-evtx/EVTX-to-MITRE-Attack/TA0007-Discovery/T1046-Network Service Scanning/ID4624-Anonymous login with domain specified (DonPapi).evtx",
  "AllFieldInfo": {
    "AuthenticationPackageName": "NTLM",
    "ImpersonationLevel": "%%1833",
    "IpAddress": "10.23.123.11",
    "IpPort": 60174,
    "KeyLength": 0,
    "LmPackageName": "NTLM V2",
    "LogonGuid": "00000000-0000-0000-0000-000000000000",
    "LogonProcessName": "NtLmSsp",
    "LogonType": 3,
    "ProcessId": "0x0",
    "ProcessName": "-",
    "SubjectDomainName": "-",
    "SubjectLogonId": "0x0",
    "SubjectUserName": "-",
    "SubjectUserSid": "S-1-0-0",
    "TargetDomainName": "OFFSEC",
    "TargetLogonId": "0x87249a8",
    "TargetUserName": "admmig",
    "TargetUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1111",
    "TransmittedServices": "-",
    "WorkstationName": ""
  }
  ```

  If you want to filter on multiple conditions you can use keywords like `and`, `or` and `not`.

  For example, lets search for `4624` events where the type is `3` (Network logon).

`cat results.json | jq 'select ( (.EventID == 4624) and (.Details.Type == 3) )'`

This will return all objects where the `EventID` is `4624` and the nested `"Details": { "Type" }` field is `3`.

There is a problem though.
You may notice errors saying `jq: error (at <stdin>:10636): Cannot index string with string "Type"`.
Any time you see the error `Cannot index string with string`, it means that you are telling `jq` to output a field that does not exist and therefore is a wrong type.
You can get rid of the errors by adding a `?` to the end of the field.
This tells `jq` to ignore the errors.

Example: `cat results.json | jq 'select ( (.EventID == 4624) and (.Details.Type? == 3) )'`

Now, after filtering on certain criteria, we can use a `|` inside the `jq` query to now select certain fields of interest.

For example, lets extract out the target username `TgtUser` and source IP address `SrcIP`:

`cat results.json | jq -j 'select ( (.EventID == 4624) and (.Details.Type? == 3)) | .Details.TgtUser, " ", .Details.SrcIP, "\n"'`

Again, we add the `-j` (join) option to `jq` to select multiple fields to output.
You can then run `sort`, `uniq -c`, etc... like in the previous examples to find out how many times a certain IP address logged into a user via a type 3 network logon.

### 4. Saving Output to CSV

Unfortunately, the fields in Windows event logs will differ completely according the type of event, so it is not easily possible to create comma separated timelines by fields without having hundreds of columns.
However, it is possible to create field separated timelines with single types of events.
Two common examples are Security `4624` (Successful logon) and `4625` (Failed logons) to check for lateral movement and password guessing/spraying.

In this example, we are extracting out just Security 4624 logs and outputting the timestamp, computer name and all `Details` information.
We save it to a CSV file by using `| @csv`, however, we need to pass the data as an array.
We can do that by selecting the fields we want to output as we did previously and enclose them with `[ ]` square brackets to turn them into an array.

Example: `cat results.json | jq 'select ( (.Channel == "Sec") and (.EventID == 4624) ) | [.Timestamp, .Computer, .Details[]?] | @csv' -r`

Notes:
  * To select all of the fields in the `Details` object we add `[]`.
  * There are cases where `Details` is a string and not an array and will give `Cannot iterate over string` errors so you need to add a `?`.
  * We add the `-r` (Raw output) option to `jq` to not backslash escape double quotes.

Results:
```
"2019-03-19 08:23:52.491 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"user01","","10.0.2.17","0x15e1a7"
"2019-03-19 08:23:57.397 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x15e25f"
"2019-03-19 09:02:04.179 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"ANONYMOUS LOGON","NULL","10.0.2.17","0x17e29a"
"2019-03-19 09:02:04.210 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2aa"
"2019-03-19 09:02:04.226 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"Administrator","","10.0.2.17","0x17e2c0"
"2019-03-19 09:02:21.929 +09:00","WIN-77LTAPHIQ1R.example.corp",3,"WIN-77LTAPHIQ1R$","","fe80::79bf:8ee2:433c:2567","0x18423d"
"2019-05-12 02:10:10.889 +09:00","IEWIN7",9,"IEUser","","::1","0x1bbdce"
```

If we are just checking who had successful logons, we may not need the last LID (Logon ID) field.
You can delete any unneeded column with the `del` function.

Example: `cat results.json | jq 'select ( (.Channel == "Sec") and (.EventID == 4624) ) | [.Timestamp, .Computer, .Details[]?] | del(.[6]) | @csv' -r`

The array counts from `0` so to remove the 7th field, we use `6`.

You can now save the CSV file by adding `> 4624-logs.csv` and then import it into Excel or Timeline Explorer for further analysis.

Note that you will need to add a header to do filtering.
While it is possible to add a heading inside the `jq` query, it is usually easiest just to manually add a top row after saving the file.

### 5. Finding Dates With Most Alerts

Hayabusa will, by default, tell you the dates that had the most alerts according to severity levels.
However, you may want to find the second, third, etc... most dates with alerts as well.
We can do that with string slicing the timestamp to group by year, month or date depending on our needs.

Example: `cat results.json | jq '.Timestamp | .[:10]' -r | sort | uniq -c | sort`

`.[:10]` tells `jq` to extract just the first 10 bytes from `Timestamp`.

This will give us the dates with the most events:
```
1066 2021-12-12
1093 2016-09-02
1571 2021-04-22
1750 2016-09-03
2271 2016-08-19
2932 2021-11-03
8095 2016-09-20
```

If you want to know the month with the most events, you can just change `.[:10]` to `.[:7]` to extract the first 7 bytes.

If you want to list up the dates with the most `high` alerts, you can do this:
`cat results.json | jq 'select (.Level == "high") | .Timestamp | .[:10]' -r | sort | uniq -c | sort`

You can keep addind conditions to the `select` function according to computer name, event ID, etc... depending on your needs.

### 6. Reconstructing PowerShell Logs

An unfortunate thing about PowerShell logs is that the logs will often be broken up into multiple logs making them hard to read.
We can make the logs much easier to read by extracting out just the commands that the attacker ran.

For example, if have `4104` ScriptBlock logs, we can extract out just that field to create an easy to read timeline.

`cat results.json | jq 'select(.EventID == 4104) | .Timestamp[:16], " ", .Details.ScriptBlock, "\n"' -jr`

This will result in a timeline as follows:
```
2022-12-24 10:56 ipconfig
2022-12-24 10:56 prompt
2022-12-24 10:56 pwd
2022-12-24 10:56 prompt
2022-12-24 10:56 whoami
2022-12-24 10:56 prompt
2022-12-24 10:57 cd..
2022-12-24 10:57 prompt
2022-12-24 10:57 ls
```
