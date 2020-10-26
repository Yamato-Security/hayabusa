use crate::detections::utils;
use crate::models::event;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Security {
    max_total_sensitive_privuse: i32,
    max_passspray_login: i32,
    max_passspray_uniquser: i32,
    max_failed_logons: i32,
    alert_all_admin: i32,
    total_admin_logons: i32,
    total_failed_logons: i32,
    total_failed_account: i32,
    total_sensitive_privuse: i32,
    admin_logons: HashMap<String, HashMap<String, i32>>,
    multiple_admin_logons: HashMap<String, i32>,
    account_2_failedcnt: HashMap<String, i32>,
    passspray_2_user: HashMap<String, i32>,
    empty_str: String,
}

impl Security {
    pub fn new() -> Security {
        Security {
            max_total_sensitive_privuse: 4,
            max_passspray_login: 6,
            max_passspray_uniquser: 6,
            max_failed_logons: 5,
            alert_all_admin: 0,
            total_admin_logons: 0,
            total_failed_logons: 0,
            total_failed_account: 0,
            total_sensitive_privuse: 0,
            admin_logons: HashMap::new(),
            multiple_admin_logons: HashMap::new(),
            account_2_failedcnt: HashMap::new(),
            passspray_2_user: HashMap::new(),
            empty_str: String::default(),
        }
    }

    pub fn disp(&self) {
        self.disp_admin_logons().and_then(Security::print_console);
        self.disp_login_failed().and_then(Security::print_console);
    }

    fn disp_admin_logons(&self) -> Option<Vec<String>> {
        if self.total_admin_logons < 1 {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push(format!("total_admin_logons:{}", self.total_admin_logons));
        msges.push(format!("admin_logons:{:?}", self.admin_logons));
        msges.push(format!(
            "multiple_admin_logons:{:?}",
            self.multiple_admin_logons
        ));

        return Option::Some(msges);
    }

    fn disp_login_failed(&self) -> Option<Vec<String>> {
        let exceed_failed_logons = self.total_failed_logons <= self.max_failed_logons;

        let exist_failed_account = self.account_2_failedcnt.keys().count() as i32 <= 1;
        if exceed_failed_logons || exist_failed_account {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push(format!(
            "High number of total logon failures for multiple accounts"
        ));
        msges.push(format!(
            "Total accounts: {}",
            self.account_2_failedcnt.keys().count()
        ));
        msges.push(format!(
            "Total logon failures: {}",
            self.total_failed_logons
        ));

        return Option::Some(msges);
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        user_data: &Option<event::UserData>,
        event_data: HashMap<String, String>,
    ) {
        self.process_created(&event_id, &event_data);
        self.se_debug_privilege(&event_id, &event_data);
        self.account_created(&event_id, &event_data)
            .and_then(Security::print_console);
        self.add_member_security_group(&event_id, &event_data)
            .and_then(Security::print_console);
        self.failed_logon(&event_id, &event_data);
        self.sensitive_priviledge(&event_id, &event_data)
            .and_then(Security::print_console);
        self.attempt_priviledge(&event_id, &event_data)
            .and_then(Security::print_console);
        self.pass_spray(&event_id, &event_data)
            .and_then(Security::print_console);
        self.audit_log_cleared(&event_id, &user_data)
            .and_then(Security::print_console);
    }

    fn print_console(v: Vec<String>) -> Option<Vec<String>> {
        v.iter().for_each(|s| println!("{}", s));
        println!("\n");
        return Option::Some(v);
    }

    fn process_created(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4688" {
            return;
        }

        let commandline = event_data.get("CommandLine").unwrap_or(&self.empty_str);
        let creator = event_data
            .get("ParentProcessName")
            .unwrap_or(&self.empty_str);
        utils::check_command(4688, &commandline, 1000, 0, &self.empty_str, &creator);
    }

    //
    // Special privileges assigned to new logon (possible admin access)
    //
    fn se_debug_privilege(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4672" {
            return;
        }

        if let Some(privileage_list) = event_data.get("PrivilegeList") {
            if let Some(_data) = privileage_list.find("SeDebugPrivilege") {
                // alert_all_adminが有効であれば、標準出力して知らせる
                // DeepBlueCLIでは必ず0になっていて、基本的には表示されない。
                if self.alert_all_admin == 1 {
                    println!("Logon with SeDebugPrivilege (admin access)");
                    println!("Username:{}", event_data["SubjectUserName"]);
                    println!("Domain:{}", event_data["SubjectDomainName"]);
                    println!("User SID:{}", event_data["SubjectUserSid"]);
                    println!("Domain:{}", event_data["PrivilegeList"]);
                }

                self.total_admin_logons += 1;

                // admin_logons配列にusernameが含まれているか確認
                match self.admin_logons.get(&event_data["SubjectUserName"]) {
                    Some(sid) => {
                        // 含まれていれば、マルチユーザが管理者としてログインしているか確認
                        // マルチログオンのデータをセット
                        if event_data["SubjectUserName"] != event_data["SubjectUserSid"] {
                            // One username with multiple admin logon SIDs
                            self.multiple_admin_logons
                                .insert(event_data["SubjectUserName"].to_string(), 1);

                            let mut count_hash: HashMap<String, i32> = HashMap::new();
                            count_hash.insert(
                                event_data["SubjectUserSid"].to_string(),
                                sid[&event_data["SubjectUserSid"]] + 1,
                            );
                            self.admin_logons
                                .insert(event_data["SubjectUserName"].to_string(), count_hash);
                        }
                    }
                    None => {
                        // admin_logons配列にセットUserNameとSIDとカウンタをセット
                        let mut count_hash: HashMap<String, i32> = HashMap::new();
                        count_hash.insert(event_data["SubjectUserSid"].to_string(), 1);
                        self.admin_logons
                            .insert(event_data["SubjectUserName"].to_string(), count_hash);
                    }
                }
            }
        }
    }

    // account craeted:OK
    fn account_created(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        if event_id != "4720" {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push("New User Created".to_string());

        let username = event_data.get("TargetUserName").unwrap_or(&self.empty_str);
        msges.push(format!("Username: {}", username));
        let sid = event_data.get("TargetSid").unwrap_or(&self.empty_str);
        msges.push(format!("User SID: {}", sid));

        return Option::Some(msges);
    }

    // add member to security group
    fn add_member_security_group(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        // check if group is Administrator, may later expand to all groups
        if event_data.get("TargetUserName").unwrap_or(&self.empty_str) != "Administrators" {
            return Option::None;
        }

        // A member was added to a security-enabled (global|local|universal) group.
        let mut msges: Vec<String> = Vec::new();
        if event_id == "4728" {
            msges.push("User added to global Administrators group".to_string());
        } else if event_id == "4732" {
            msges.push("User added to local Administrators group".to_string());
        } else if event_id == "4756" {
            msges.push("User added to universal Administrators group".to_string());
        } else {
            return Option::None;
        }

        let username = event_data.get("MemberName").unwrap_or(&self.empty_str);
        msges.push(format!("Username: {}", username));
        let sid = event_data.get("MemberSid").unwrap_or(&self.empty_str);
        msges.push(format!("User SID: {}", sid));

        return Option::Some(msges);
    }

    // An account failed to log on.:OK
    // Requires auditing logon failures
    // https://technet.microsoft.com/en-us/library/cc976395.aspx
    fn failed_logon(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4625" {
            return;
        }

        // see fn disp()
        self.total_failed_logons += 1;
        let username = event_data.get("TargetUserName").unwrap_or(&self.empty_str);
        let failed_cnt = self.account_2_failedcnt.get(username).unwrap_or(&0) + 1;
        self.account_2_failedcnt
            .insert(username.to_string(), failed_cnt);
    }

    // Sensitive Privilege Use (Mimikatz)
    fn sensitive_priviledge(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        if event_id != "4673" {
            return Option::None;
        }

        self.total_sensitive_privuse += 1;
        let mut msges: Vec<String> = Vec::new();
        // use == operator here to avoid multiple log notices
        if self.max_total_sensitive_privuse != self.total_sensitive_privuse {
            return Option::None;
        }

        msges.push("Sensititive Privilege Use Exceeds Threshold".to_string());
        msges.push(
            "Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made"
                .to_string(),
        );

        let username = event_data.get("SubjectUserName").unwrap_or(&self.empty_str);
        msges.push(format!("Username: {}", username));

        let domainname = event_data
            .get("SubjectDomainName")
            .unwrap_or(&self.empty_str);
        msges.push(format!("Domain Name: {}", domainname));

        return Option::Some(msges);
    }

    fn attempt_priviledge(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        if event_id != "4674" {
            return Option::None;
        }

        // "%%1539" means WRITE_DAC(see detail: https://docs.microsoft.com/ja-jp/windows/security/threat-protection/auditing/event-4663)
        let servicename = event_data
            .get("ProcessName")
            .unwrap_or(&self.empty_str)
            .to_uppercase();
        let accessname = event_data.get("AccessMask").unwrap_or(&self.empty_str);
        if servicename != r"C:\WINDOWS\SYSTEM32\SERVICES.EXE" || accessname != "%%1539" {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push("Possible Hidden Service Attempt".to_string());
        msges.push("User requested to modify the Dynamic Access Control (DAC) permissions of a sevice, possibly to hide it from view".to_string());

        let username = event_data.get("SubjectUserName").unwrap_or(&self.empty_str);
        msges.push(format!("User: {}", username));

        let servicename = event_data.get("ObjectName").unwrap_or(&self.empty_str);
        msges.push(format!("Target service: {}", servicename));

        msges.push("WRITE_DAC".to_string());

        return Option::Some(msges);
    }

    // A logon was attempted using explicit credentials.
    fn pass_spray(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        if event_id != "4648" {
            return Option::None;
        }

        let targetusername = event_data.get("TargetUserName").unwrap_or(&self.empty_str);
        let spray_cnt = self.passspray_2_user.get(targetusername).unwrap_or(&0) + 1;
        self.passspray_2_user
            .insert(targetusername.to_string(), spray_cnt);

        // check exceeded targetuser count.
        let spray_uniq_user = self
            .passspray_2_user
            .values()
            .filter(|value| value > &&self.max_passspray_login)
            .count() as i32;
        if spray_uniq_user <= self.max_passspray_uniquser {
            return Option::None;
        }

        // let v_username  = Vec::new();
        let mut v_username = Vec::new();
        self.passspray_2_user
            .keys()
            .for_each(|u| v_username.push(u));
        v_username.sort();
        let usernames: String = v_username.iter().fold(
            self.empty_str.to_string(),
            |mut acc: String, cur| -> String {
                acc.push_str(cur);
                acc.push_str(" ");
                return acc;
            },
        );

        let mut msges: Vec<String> = Vec::new();
        msges.push(
            "Distributed Account Explicit Credential Use (Password Spray Attack)".to_string(),
        );
        msges.push(
            "The use of multiple user account access attempts with explicit credentials is "
                .to_string(),
        );
        msges.push("an indicator of a password spray attack".to_string());

        msges.push(format!("Target Usernames: {}", usernames.trim()));
        let access_username = event_data.get("SubjectUserName").unwrap_or(&self.empty_str);

        msges.push(format!("Accessing Username: {}", access_username));

        let access_hostname = event_data
            .get("SubjectDomainName")
            .unwrap_or(&self.empty_str);
        msges.push(format!("Accessing Host Name: {}", access_hostname));

        // reset
        self.passspray_2_user = HashMap::new();

        return Option::Some(msges);
    }

    fn audit_log_cleared(
        &mut self,
        event_id: &String,
        user_data: &Option<event::UserData>,
    ) -> Option<Vec<String>> {
        if event_id != "1102" {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push("Audit Log Clear".to_string());
        msges.push("The Audit log was cleared".to_string());
        let username = user_data
            .as_ref()
            .and_then(|u| u.log_file_cleared.as_ref())
            .and_then(|l| l.subject_user_name.as_ref());
        msges.push(format!(
            "Security ID: {}",
            username.unwrap_or(&self.empty_str)
        ));

        return Option::Some(msges);
    }
}

#[cfg(test)]
mod tests {
    extern crate quick_xml;

    use crate::detections::security;
    use crate::models::event;

    // 正しくヒットするパターン
    #[test]
    fn test_account_created_hit() {
        let xml_str = get_account_created_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.account_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"New User Created".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: IEUser".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"User SID: S-1-5-21-3463664321-2923530833-3546627382-1000",
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // event idが異なるパターン
    #[test]
    fn test_account_created_noteq_eventid() {
        let xml_str =
            get_account_created_xml().replace("<EventID>4720</EventID>", "<EventID>4721</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.account_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        assert_eq!(Option::None, option_v);
    }

    // 実在するかどうか不明だが、EventDataの必要なフィールドがないパターン
    #[test]
    fn test_account_created_none_check() {
        let xml_str = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4720</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>13824</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime='2013-10-23T16:22:39.9735000Z'/>
                <EventRecordID>112</EventRecordID>
                <Correlation/>
                <Execution ProcessID='508' ThreadID='1032'/>
                <Channel>Security</Channel>
                <Computer>IE8Win7</Computer>
                <Security/>
            </System>
            <EventData></EventData>
        </Event>"#;
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.account_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"New User Created".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: ".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(&"User SID: ", ite.next().unwrap_or(&"".to_string()));
        assert_eq!(Option::None, ite.next());
    }

    fn get_account_created_xml() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4720</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>13824</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime='2013-10-23T16:22:39.9735000Z'/>
                <EventRecordID>112</EventRecordID>
                <Correlation/>
                <Execution ProcessID='508' ThreadID='1032'/>
                <Channel>Security</Channel>
                <Computer>IE8Win7</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name='TargetUserName'>IEUser</Data>
                <Data Name='TargetDomainName'>IE8Win7</Data>
                <Data Name='TargetSid'>S-1-5-21-3463664321-2923530833-3546627382-1000</Data>
                <Data Name='SubjectUserSid'>S-1-5-18</Data>
                <Data Name='SubjectUserName'>WIN-QALA5Q3KJ43$</Data>
                <Data Name='SubjectDomainName'>WORKGROUP</Data>
                <Data Name='SubjectLogonId'>0x3e7</Data>
                <Data Name='PrivilegeList'>-</Data>
                <Data Name='SamAccountName'>IEUserSam</Data>
                <Data Name='DisplayName'>%%1793</Data>
                <Data Name='UserPrincipalName'>-</Data>
                <Data Name='HomeDirectory'>%%1793</Data>
                <Data Name='HomePath'>%%1793</Data>
                <Data Name='ScriptPath'>%%1793</Data>
                <Data Name='ProfilePath'>%%1793</Data>
                <Data Name='UserWorkstations'>%%1793</Data>
                <Data Name='PasswordLastSet'>%%1794</Data>
                <Data Name='AccountExpires'>%%1794</Data>
                <Data Name='PrimaryGroupId'>513</Data>
                <Data Name='AllowedToDelegateTo'>-</Data>
                <Data Name='OldUacValue'>0x0</Data>
                <Data Name='NewUacValue'>0x15</Data>
                <Data Name='UserAccountControl'>
                %%2080
                %%2082
                %%2084</Data>
                <Data Name='UserParameters'>%%1793</Data>
                <Data Name='SidHistory'>-</Data>
                <Data Name='LogonHours'>%%1797</Data>
            </EventData>
        </Event>"#.to_string();
    }

    // 正しくヒットするパターン(eventid=4732)
    #[test]
    fn test_add_member_security_group_hit_4732() {
        let xml_str = get_add_member_security_group_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"User added to local Administrators group".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: testnamess".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"User SID: S-1-5-21-3463664321-2923530833-3546627382-1000",
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // 正しくヒットするパターン(eventid=4728は一行目が変わる)
    #[test]
    fn test_add_member_security_group_hit_4728() {
        let xml_str = get_add_member_security_group_xml()
            .replace(r"<EventID>4732</EventID>", r"<EventID>4728</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"User added to global Administrators group".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: testnamess".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"User SID: S-1-5-21-3463664321-2923530833-3546627382-1000",
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // 正しくヒットするパターン(eventid=4756は一行目が変わる)
    #[test]
    fn test_add_member_security_group_hit_4756() {
        let xml_str = get_add_member_security_group_xml()
            .replace(r"<EventID>4732</EventID>", r"<EventID>4756</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"User added to universal Administrators group".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: testnamess".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"User SID: S-1-5-21-3463664321-2923530833-3546627382-1000",
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_add_member_security_group_noteq_eventid() {
        let xml_str = get_add_member_security_group_xml()
            .replace(r"<EventID>4732</EventID>", r"<EventID>4757</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );
        assert_eq!(Option::None, option_v);
    }

    // グループがAdministratorsじゃなくてHitしないパターン
    #[test]
    fn test_add_member_security_not_administrators() {
        let xml_str = get_add_member_security_group_xml().replace(
            r"<Data Name='TargetUserName'>Administrators</Data>",
            r"<Data Name='TargetUserName'>local</Data>",
        );
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );
        assert_eq!(Option::None, option_v);
    }

    // hitするけど表示するフィールドがない場合
    #[test]
    fn test_add_member_security_group_none() {
        let xml_str = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4732</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>13826</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime='2013-10-23T16:22:40.0047500Z'/>
                <EventRecordID>116</EventRecordID>
                <Correlation/>
                <Execution ProcessID='508' ThreadID='1032'/>
                <Channel>Security</Channel>
                <Computer>IE8Win7</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name='TargetUserName'>Administrators</Data>
            </EventData>
        </Event>"#;
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                println!("{}", e.to_string());
            })
            .unwrap();

        let mut sec = security::Security::new();
        let option_v = sec.add_member_security_group(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"User added to local Administrators group".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Username: ".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(&"User SID: ", ite.next().unwrap_or(&"".to_string()));
        assert_eq!(Option::None, ite.next());
    }

    fn get_add_member_security_group_xml() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4732</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>13826</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime='2013-10-23T16:22:40.0047500Z'/>
                <EventRecordID>116</EventRecordID>
                <Correlation/>
                <Execution ProcessID='508' ThreadID='1032'/>
                <Channel>Security</Channel>
                <Computer>IE8Win7</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name='MemberName'>testnamess</Data>
                <Data Name='MemberSid'>S-1-5-21-3463664321-2923530833-3546627382-1000</Data>
                <Data Name='TargetUserName'>Administrators</Data>
                <Data Name='TargetDomainName'>Builtin</Data>
                <Data Name='TargetSid'>S-1-5-32-544</Data>
                <Data Name='SubjectUserSid'>S-1-5-18</Data>
                <Data Name='SubjectUserName'>WIN-QALA5Q3KJ43$</Data>
                <Data Name='SubjectDomainName'>WORKGROUP</Data>
                <Data Name='SubjectLogonId'>0x3e7</Data>
                <Data Name='PrivilegeList'>-</Data>
            </EventData>
        </Event>"#.to_string();
    }

    // ユーザー数が一つなら、ログ数が幾らあっても、メッセージは表示されないはず。
    #[test]
    fn test_failed_logon_nothit_onlyoneuser() {
        let xml_str = get_failed_logon_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();

        sec.max_failed_logons = 5;
        let ite = [1, 2, 3, 4, 5, 6, 7].iter();
        ite.for_each(|i| {
            sec.failed_logon(
                &event.system.event_id.to_string(),
                &event.parse_event_data(),
            );
            assert_eq!(i, &sec.total_failed_logons);
            assert_eq!(Option::None, sec.disp_login_failed());
        });
    }

    // 失敗回数を増やしていき、境界値でメッセージが表示されることのテスト。
    #[test]
    fn test_failed_logon_hit() {
        let xml_str = get_failed_logon_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();
        let event_another: event::Evtx = quick_xml::de::from_str(&xml_str.replace(
            r"<Data Name='TargetUserName'>Administrator</Data>",
            r"<Data Name='TargetUserName'>localuser</Data>",
        ))
        .unwrap();

        let mut sec = security::Security::new();
        sec.max_failed_logons = 5;

        // メッセージが表示されるには2ユーザー以上失敗している必要がある。まず一人目
        sec.failed_logon(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );
        assert_eq!(1, sec.total_failed_logons);

        let ite = [1, 2, 3, 4, 5, 6, 7].iter();
        ite.for_each(|i| {
            sec.failed_logon(
                &event_another.system.event_id.to_string(),
                &event_another.parse_event_data(),
            );
            let fail_cnt = i + 1;
            assert_eq!(fail_cnt, sec.total_failed_logons);
            if fail_cnt > 5 {
                let v = sec.disp_login_failed().unwrap();
                let mut ite = v.iter();
                assert_eq!(
                    &"High number of total logon failures for multiple accounts".to_string(),
                    ite.next().unwrap_or(&"".to_string())
                );
                assert_eq!(
                    &"Total accounts: 2".to_string(),
                    ite.next().unwrap_or(&"".to_string())
                );
                assert_eq!(
                    &format!("Total logon failures: {}", fail_cnt),
                    ite.next().unwrap_or(&"".to_string())
                );
            // assert_eq!(Option::None, ite.next());
            } else {
                assert_eq!(Option::None, sec.disp_login_failed());
            }
        });

        // hitするけど表示するフィールドがない場合
        let xml_nofield = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2016-09-19T16:52:49.3996746Z'/><EventRecordID>6016</EventRecordID><Correlation ActivityID='{b864d168-0b7b-0000-89d1-64b87b0bd201}'/><Execution ProcessID='752' ThreadID='496'/><Channel>Security</Channel><Computer>DESKTOP-M5SN04R</Computer><Security/>
            </System>
        </Event>"#;

        // エラーにならなければOK
        let event_nofield: event::Evtx = quick_xml::de::from_str(xml_nofield).unwrap();
        sec.failed_logon(
            &event_nofield.system.event_id.to_string(),
            &event_nofield.parse_event_data(),
        );
    }

    // 失敗回数を増やしていき、境界値でメッセージが表示されることのテスト。
    #[test]
    fn test_failed_logon_noteq_eventid() {
        let xml_str = get_failed_logon_xml();
        let event: event::Evtx = quick_xml::de::from_str(
            &xml_str.replace(r"<EventID>4625</EventID>", r"<EventID>4626</EventID>"),
        )
        .unwrap();
        let event_another: event::Evtx = quick_xml::de::from_str(
            &xml_str
                .replace(r"<EventID>4625</EventID>", r"<EventID>4626</EventID>")
                .replace(
                    r"<Data Name='TargetUserName'>Administrator</Data>",
                    r"<Data Name='TargetUserName'>localuser</Data>",
                ),
        )
        .unwrap();

        let mut sec = security::Security::new();
        sec.max_failed_logons = 5;

        // メッセージが表示されるには2ユーザー以上失敗している必要がある。まず一人目
        sec.failed_logon(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );
        assert_eq!(0, sec.total_failed_logons);

        let ite = [1, 2, 3, 4, 5, 6, 7].iter();
        ite.for_each(|_i| {
            sec.failed_logon(
                &event_another.system.event_id.to_string(),
                &event_another.parse_event_data(),
            );
            assert_eq!(0, sec.total_failed_logons);
            assert_eq!(Option::None, sec.disp_login_failed());
        });
    }

    fn get_failed_logon_xml() -> String {
        return r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4625</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>12544</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8010000000000000</Keywords>
                <TimeCreated SystemTime='2016-09-19T16:52:49.3996746Z'/>
                <EventRecordID>6016</EventRecordID>
                <Correlation ActivityID='{b864d168-0b7b-0000-89d1-64b87b0bd201}'/>
                <Execution ProcessID='752' ThreadID='496'/>
                <Channel>Security</Channel>
                <Computer>DESKTOP-M5SN04R</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name='SubjectUserSid'>S-1-0-0</Data>
                <Data Name='SubjectUserName'>-</Data>
                <Data Name='SubjectDomainName'>-</Data>
                <Data Name='SubjectLogonId'>0x0</Data>
                <Data Name='TargetUserSid'>S-1-0-0</Data>
                <Data Name='TargetUserName'>Administrator</Data>
                <Data Name='TargetDomainName'>.</Data>
                <Data Name='Status'>0xc000006d</Data>
                <Data Name='FailureReason'>%%2313</Data>
                <Data Name='SubStatus'>0xc000006a</Data>
                <Data Name='LogonType'>3</Data>
                <Data Name='LogonProcessName'>NtLmSsp </Data>
                <Data Name='AuthenticationPackageName'>NTLM</Data>
                <Data Name='WorkstationName'>fpEbpiox2Q3Qf8av</Data>
                <Data Name='TransmittedServices'>-</Data>
                <Data Name='LmPackageName'>-</Data>
                <Data Name='KeyLength'>0</Data>
                <Data Name='ProcessId'>0x0</Data>
                <Data Name='ProcessName'>-</Data>
                <Data Name='IpAddress'>192.168.198.149</Data>
                <Data Name='IpPort'>33083</Data>
            </EventData>
        </Event>"#
            .to_string();
    }

    // Hitするパターンとしないパターンをまとめてテスト
    #[test]
    fn test_sensitive_priviledge_hit() {
        let xml_str = get_sensitive_prividedge_hit();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();
        sec.max_total_sensitive_privuse = 6;

        let ite = [1, 2, 3, 4, 5, 6, 7].iter();
        ite.for_each(|i| {
            let msg = sec.sensitive_priviledge(&event.system.event_id.to_string(), &event.parse_event_data());
            // i == 7ときにHitしない
            if i == &6 {
                let v = msg.unwrap();
                let mut ite = v.iter();
                assert_eq!(
                    &"Sensititive Privilege Use Exceeds Threshold".to_string(),
                    ite.next().unwrap_or(&"".to_string())
                );
                assert_eq!(
                    &"Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made".to_string(),
                    ite.next().unwrap_or(&"".to_string())
                );
                assert_eq!(
                    &"Username: Sec504".to_string(),
                    ite.next().unwrap_or(&"".to_string())
                );
                assert_eq!(
                    &"Domain Name: SEC504STUDENT",
                    ite.next().unwrap_or(&"".to_string())
                );
            } else {
                assert_eq!(Option::None, msg);
            }
        });
    }

    // eventidが異なるので、Hitしないテスト
    #[test]
    fn test_sensitive_priviledge_noteq_eventid() {
        let xml_str = get_sensitive_prividedge_hit()
            .replace(r"<EventID>4673</EventID>", r"<EventID>4674</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();
        sec.max_total_sensitive_privuse = 6;

        let ite = [1, 2, 3, 4, 5, 6, 7].iter();
        ite.for_each(|_i| {
            let msg = sec.sensitive_priviledge(
                &event.system.event_id.to_string(),
                &event.parse_event_data(),
            );
            assert_eq!(Option::None, msg);
        });
    }

    fn get_sensitive_prividedge_hit() -> String {
        return r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                <EventID>4673</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>13056</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8010000000000000</Keywords>
                <TimeCreated SystemTime='2019-04-30T18:08:29.1380587Z'/>
                <EventRecordID>8936</EventRecordID>
                <Correlation/>
                <Execution ProcessID='4' ThreadID='1664'/>
                <Channel>Security</Channel>
                <Computer>Sec504Student</Computer>
                <Security/>
            </System>
            <EventData>
                <Data Name='SubjectUserSid'>S-1-5-21-2977773840-2930198165-1551093962-1000</Data>
                <Data Name='SubjectUserName'>Sec504</Data>
                <Data Name='SubjectDomainName'>SEC504STUDENT</Data>
                <Data Name='SubjectLogonId'>0x1e3dd</Data>
                <Data Name='ObjectServer'>Security</Data>
                <Data Name='Service'>-</Data>
                <Data Name='PrivilegeList'>SeTcbPrivilege</Data>
                <Data Name='ProcessId'>0x15a8</Data>
                <Data Name='ProcessName'>C:\Tools\mimikatz\mimikatz.exe</Data>
            </EventData>
        </Event>"#.to_string();
    }

    // Hitするテスト
    #[test]
    fn test_attempt_priviledge_hit() {
        let xml_str = get_attempt_priviledge_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();
        let msg = sec.attempt_priviledge(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        assert_ne!(Option::None, msg);
        let v = msg.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Possible Hidden Service Attempt".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(&"User requested to modify the Dynamic Access Control (DAC) permissions of a sevice, possibly to hide it from view".to_string(), ite.next().unwrap_or(&"".to_string()));
        assert_eq!(
            &"User: Sec504".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Target service: nginx".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"WRITE_DAC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // accessmaskが異なるので、Hitしないテスト
    #[test]
    fn test_attempt_priviledge_noteq_accessmask() {
        let xml_str = get_attempt_priviledge_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str.replace(
            r"<Data Name='AccessMask'>%%1539",
            r"<Data Name='AccessMask'>%%1538",
        ))
        .unwrap();

        let mut sec = security::Security::new();
        let msg = sec.attempt_priviledge(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        assert_eq!(Option::None, msg);
    }

    // Serviceが違うのでHitしないテスト
    #[test]
    fn test_attempt_priviledge_noteq_service() {
        let xml_str = get_attempt_priviledge_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str.replace(
            r"<Data Name='ProcessName'>C:\Windows\System32\services.exe</Data>",
            r"<Data Name='ProcessName'>C:\Windows\System32\lsass.exe</Data>",
        ))
        .unwrap();

        let mut sec = security::Security::new();
        let msg = sec.attempt_priviledge(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        assert_eq!(Option::None, msg);
    }

    // EventIDが違うのでHitしないテスト
    #[test]
    fn test_attempt_priviledge_noteq_eventid() {
        let xml_str = get_attempt_priviledge_xml();
        let event: event::Evtx = quick_xml::de::from_str(
            &xml_str.replace(r"<EventID>4674</EventID>", r"<EventID>4675</EventID>"),
        )
        .unwrap();

        let mut sec = security::Security::new();
        let msg = sec.attempt_priviledge(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
        );

        assert_eq!(Option::None, msg);
    }

    fn get_attempt_priviledge_xml() -> String {
        return r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                    <EventID>4674</EventID>
                    <Version>0</Version>
                    <Level>0</Level>
                    <Task>13056</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8020000000000000</Keywords>
                    <TimeCreated SystemTime='2020-09-14T14:48:28.6830484Z'/>
                    <EventRecordID>39406</EventRecordID>
                    <Correlation/>
                    <Execution ProcessID='4' ThreadID='5756'/>
                    <Channel>Security</Channel>
                    <Computer>Sec504Student</Computer>
                    <Security/>
                </System>
                <EventData>
                    <Data Name='SubjectUserSid'>S-1-5-21-2977773840-2930198165-1551093962-1000</Data>
                    <Data Name='SubjectUserName'>Sec504</Data>
                    <Data Name='SubjectDomainName'>SEC504STUDENT</Data>
                    <Data Name='SubjectLogonId'>0x99e3d</Data>
                    <Data Name='ObjectServer'>SC Manager</Data>
                    <Data Name='ObjectType'>SERVICE OBJECT</Data>
                    <Data Name='ObjectName'>nginx</Data>
                    <Data Name='HandleId'>0xffff820cb1d95928</Data>
                    <Data Name='AccessMask'>%%1539
                    </Data>
                    <Data Name='PrivilegeList'>SeSecurityPrivilege</Data>
                    <Data Name='ProcessId'>0x21c</Data>
                    <Data Name='ProcessName'>C:\Windows\System32\services.exe</Data>
                </EventData>
            </Event>"#.to_string();
    }

    #[test]
    fn test_pass_spray_hit() {
        let mut sec = security::Security::new();
        // 6ユーザまでは表示されず、7ユーザー以上で表示されるようになる。
        sec.max_passspray_login = 6;
        sec.max_passspray_uniquser = 6;

        test_pass_spray_hit_1cycle(&mut sec, "4648".to_string(), true);
        // counterがreset確認のため、2回実行
        test_pass_spray_hit_1cycle(&mut sec, "4648".to_string(), true);
    }

    // eventid異なるので、Hitしないはず
    #[test]
    fn test_pass_spray_noteq_eventid() {
        let mut sec = security::Security::new();
        // 6ユーザまでは表示されず、7ユーザー以上で表示されるようになる。
        sec.max_passspray_login = 6;
        sec.max_passspray_uniquser = 6;

        test_pass_spray_hit_1cycle(&mut sec, "4649".to_string(), false);
        // counterがreset確認のため、2回実行
        test_pass_spray_hit_1cycle(&mut sec, "4649".to_string(), false);
    }

    fn test_pass_spray_hit_1cycle(sec: &mut security::Security, event_id: String, is_eq: bool) {
        [1,2,3,4,5,6,7].iter().for_each(|i| {
            let rep_str = format!(r#"<Data Name='TargetUserName'>smisenar{}</Data>"#,i);
            let event_id_tag = format!("<EventID>{}</EventID>", event_id);
            let xml_str = get_passs_pray_hit().replace(r#"<Data Name='TargetUserName'>smisenar</Data>"#, &rep_str).replace(r"<EventID>4648</EventID>", &event_id_tag);
            let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();
            [1,2,3,4,5,6,7].iter().for_each(|k|{
                let ret = sec.pass_spray(&event.system.event_id.to_string(), &event.parse_event_data());
                if i == &7 && k == &7 && is_eq {
                    let v = ret.unwrap();
                    let mut ret_ite = v.iter();
                    assert_eq!(&"Distributed Account Explicit Credential Use (Password Spray Attack)".to_string(),ret_ite.next().unwrap());
                    assert_eq!(&"The use of multiple user account access attempts with explicit credentials is ".to_string(),ret_ite.next().unwrap());
                    assert_eq!(&"an indicator of a password spray attack".to_string(),ret_ite.next().unwrap());
                    assert_eq!("Target Usernames: smisenar1 smisenar2 smisenar3 smisenar4 smisenar5 smisenar6 smisenar7",ret_ite.next().unwrap());
                    assert_eq!(&"Accessing Username: jwrig".to_string(),ret_ite.next().unwrap());
                    assert_eq!(&"Accessing Host Name: DESKTOP-JR78RLP".to_string(),ret_ite.next().unwrap());
                    assert_eq!(Option::None,ret_ite.next());
                } else {
                    assert_eq!(Option::None,ret);
                }
            });
        });
    }

    fn get_passs_pray_hit() -> String {
        return r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
                    <EventID>4648</EventID>
                    <Version>0</Version>
                    <Level>0</Level>
                    <Task>12544</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8020000000000000</Keywords>
                    <TimeCreated SystemTime='2019-04-30T19:32:17.4749955Z'/>
                    <EventRecordID>43097</EventRecordID>
                    <Correlation ActivityID='{f4bf8b01-fea7-0000-e78b-bff4a7fed401}'/>
                    <Execution ProcessID='648' ThreadID='3388'/>
                    <Channel>Security</Channel>
                    <Computer>DESKTOP-JR78RLP</Computer>
                    <Security/>
                </System>
                <EventData>
                    <Data Name='SubjectUserSid'>S-1-5-21-979008924-657238111-836329461-1002</Data>
                    <Data Name='SubjectUserName'>jwrig</Data>
                    <Data Name='SubjectDomainName'>DESKTOP-JR78RLP</Data>
                    <Data Name='SubjectLogonId'>0x3069d</Data>
                    <Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data>
                    <Data Name='TargetUserName'>smisenar</Data>
                    <Data Name='TargetDomainName'>DOMAIN</Data>
                    <Data Name='TargetLogonGuid'>{00000000-0000-0000-0000-000000000000}</Data>
                    <Data Name='TargetServerName'>DESKTOP-JR78RLP</Data>
                    <Data Name='TargetInfo'>DESKTOP-JR78RLP</Data>
                    <Data Name='ProcessId'>0x4</Data>
                    <Data Name='ProcessName'></Data>
                    <Data Name='IpAddress'>172.16.144.128</Data>
                    <Data Name='IpPort'>445</Data>
                </EventData>
            </Event>"#.to_string();
    }

    // 普通にHitするテスト
    #[test]
    fn test_audit_log_cleared_hit() {
        let xml_str = get_audit_log_cleared_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();
        let msg = sec.audit_log_cleared(&event.system.event_id.to_string(), &event.user_data);

        assert_ne!(Option::None, msg);
        let v = msg.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Audit Log Clear".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"The Audit log was cleared".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Security ID: jwrig".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventid違うのでHitしないはず
    #[test]
    fn test_audit_log_cleared_noteq_eventid() {
        let xml_str = get_audit_log_cleared_xml()
            .replace(r"<EventID>1102</EventID>", r"<EventID>1103</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str).unwrap();

        let mut sec = security::Security::new();
        let msg = sec.audit_log_cleared(&event.system.event_id.to_string(), &event.user_data);
        assert_eq!(Option::None, msg);
    }

    fn get_audit_log_cleared_xml() -> String {
        return r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                <System>
                    <Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/>
                    <EventID>1102</EventID>
                    <Version>0</Version>
                    <Level>4</Level>
                    <Task>104</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x4020000000000000</Keywords>
                    <TimeCreated SystemTime='2019-04-30T19:27:00.2974504Z'/>
                    <EventRecordID>42803</EventRecordID>
                    <Correlation/>
                    <Execution ProcessID='1228' ThreadID='6280'/>
                    <Channel>Security</Channel>
                    <Computer>DESKTOP-JR78RLP</Computer>
                    <Security/>
                </System>
                <UserData>
                    <LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
                        <SubjectUserSid>S-1-5-21-979008924-657238111-836329461-1002</SubjectUserSid>
                        <SubjectUserName>jwrig</SubjectUserName>
                        <SubjectDomainName>DESKTOP-JR78RLP</SubjectDomainName>
                        <SubjectLogonId>0x30550</SubjectLogonId>
                    </LogFileCleared>
                </UserData>
            </Event>"#.to_string();
    }
}
