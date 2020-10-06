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
        self.fmt_admin_logons().and_then(Security::print_console);
        self.fmt_passspray().and_then(Security::print_console);
    }

    fn fmt_admin_logons(&self) -> Option<Vec<String>> {
        if self.total_admin_logons < 1 {
            return Option::None;
        }

        let mut msges: Vec<String> = Vec::new();
        msges.push(format!("total_admin_logons:{}", self.total_admin_logons));
        msges.push(format!("admin_logons:{:?}", self.admin_logons));
        msges.push(format!(
            "multiple_admin_logons:{:?}\n\n",
            self.multiple_admin_logons
        ));

        return Option::Some(msges);
    }

    fn fmt_passspray(&self) -> Option<Vec<String>> {
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
            "Total logon failures: {}\n\n",
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

    fn process_created(&mut self, event_id: &String, _event_data: &HashMap<String, String>) {
        if event_id != "4688" {
            return;
        }
        // TODO Check-Commnad
        return;
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
        msges.push(format!("TargetSid: {}", sid));

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

        let username = event_data.get("TargetUserName").unwrap_or(&self.empty_str);
        msges.push(format!("Username: {}", username));
        let sid = event_data.get("TargetSid").unwrap_or(&self.empty_str);
        msges.push(format!("TargetSid: {}", sid));

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
        msges.push("User requested to modify the Dynamic Access Control (DAC) permissions of a sevice, possibly to hide it from view.".to_string());

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

        // check targetuser's attempt count.
        if self.passspray_2_user.get(targetusername).unwrap_or(&0) <= &self.max_passspray_login {
            return Option::None;
        }

        // check exceeded targetuser count.
        let spray_uniq_user = self
            .passspray_2_user
            .values()
            .filter(|value| value > &&self.max_passspray_login)
            .count() as i32;
        if spray_uniq_user <= self.max_passspray_uniquser {
            return Option::None;
        }

        let usernames: String = self.passspray_2_user.keys().fold(
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
        msges.push("an indicator of a password spray attack.".to_string());

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
        msges.push("The Audit log was cleared.".to_string());
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
