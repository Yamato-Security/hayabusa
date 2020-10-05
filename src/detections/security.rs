use crate::models::event;
use std::collections::HashMap;

// eventlogが用意できていない
// 4674
// 4756

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
        if self.total_admin_logons > 0 {
            println!("total_admin_logons:{}", self.total_admin_logons);
            println!("admin_logons:{:?}", self.admin_logons);
            println!("multiple_admin_logons:{:?}\n", self.multiple_admin_logons);
        }

        let exceed_failed_logons = self.total_failed_logons > self.max_failed_logons;
        let exist_failed_account = self.account_2_failedcnt.keys().count() as i32 > 1;
        if exceed_failed_logons && exist_failed_account {
            println!("High number of total logon failures for multiple accounts");
            println!(
                "Total accounts: {}",
                self.account_2_failedcnt.keys().count()
            );
            println!("Total logon failures: {}\n", self.total_failed_logons);
        }
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        user_data: &Option<event::UserData>,
        event_data: HashMap<String, String>,
    ) {
        self.process_craeted(&event_id, &event_data);
        self.se_debug_privilege(&event_id, &event_data);
        self.account_created(&event_id, &event_data);
        self.add_member_security_group(&event_id, &event_data);
        self.failed_logon(&event_id, &event_data);
        self.sensitive_priviledge(&event_id, &event_data);
        self.attempt_priviledge(&event_id, &event_data);
        self.pass_spray(&event_id, &event_data);
        self.audit_log_cleared(&event_id, &user_data);
    }

    fn process_craeted(&mut self, event_id: &String, _event_data: &HashMap<String, String>) {
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
    fn account_created(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4720" {
            return;
        }

        println!("New User Created");
        println!(
            "Username: {}",
            event_data.get("TargetUserName").unwrap_or(&"".to_string())
        );
        println!(
            "User SID:: {}\n",
            event_data.get("TargetSid").unwrap_or(&"".to_string())
        );
    }

    // add member to security group
    fn add_member_security_group(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
    ) {
        // check if group is Administrator, may later expand to all groups
        if event_data.get("TargetUserName").unwrap_or(&self.empty_str) != "Administrators" {
            return;
        }

        // A member was added to a security-enabled (global|local|universal) group.
        if event_id == "4728" {
            println!("User added to global Administrators group");
        } else if event_id == "4732" {
            println!("User added to local Administrators group");
        } else if event_id == "4756" {
            println!("User added to universal Administrators group");
        } else {
            return;
        }

        println!(
            "Username: {}",
            event_data.get("TargetUserName").unwrap_or(&"".to_string())
        );
        println!(
            "User SID:: {}\n",
            event_data.get("TargetSid").unwrap_or(&"".to_string())
        );
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
        let failed_cnt = self.account_2_failedcnt.get(username).unwrap_or(&0) + &1;
        self.account_2_failedcnt
            .insert(username.to_string(), failed_cnt);
    }

    // Sensitive Privilege Use (Mimikatz)
    fn sensitive_priviledge(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4673" {
            return;
        }

        self.total_sensitive_privuse += 1;
        // use == operator here to avoid multiple log notices
        if self.max_total_sensitive_privuse == self.total_sensitive_privuse {
            println!("Sensititive Privilege Use Exceeds Threshold");
            println!(
                "Username: {}",
                event_data.get("SubjectUserName").unwrap_or(&self.empty_str)
            );
            println!(
                "Domain Name: {}",
                event_data
                    .get("SubjectDomainName")
                    .unwrap_or(&self.empty_str)
            );
        }
    }

    fn attempt_priviledge(&mut self, _event_id: &String, _event_data: &HashMap<String, String>) {
        // event log cannot get...
    }

    // A logon was attempted using explicit credentials.
    fn pass_spray(&mut self, event_id: &String, event_data: &HashMap<String, String>) {
        if event_id != "4648" {
            return;
        }

        let targetusername = event_data.get("TargetUserName").unwrap_or(&self.empty_str);
        let spray_cnt = self.passspray_2_user.get(targetusername).unwrap_or(&0) + 1;
        self.passspray_2_user
            .insert(targetusername.to_string(), spray_cnt);

        // check targetuser's attempt count.
        if self.passspray_2_user.get(targetusername).unwrap_or(&0) <= &self.max_passspray_login {
            return;
        }

        // check exceeded targetuser count.
        let spray_uniq_user = self
            .passspray_2_user
            .values()
            .filter(|value| value > &&self.max_passspray_login)
            .count() as i32;
        if spray_uniq_user <= self.max_passspray_uniquser {
            return;
        }

        let usernames: String = self.passspray_2_user.keys().fold(
            self.empty_str.to_string(),
            |mut acc: String, cur| -> String {
                acc.push_str(cur);
                acc.push_str(" ");
                return acc;
            },
        );

        println!("Distributed Account Explicit Credential Use (Password Spray Attack)");
        println!("The use of multiple user account access attempts with explicit credentials is ");
        println!("an indicator of a password spray attack.");
        println!("Target Usernames: {}", usernames.trim());
        println!(
            "Accessing Username: {}",
            event_data.get("SubjectUserName").unwrap_or(&self.empty_str)
        );
        println!(
            "Accessing Host Name: {}\n\n",
            event_data
                .get("SubjectDomainName")
                .unwrap_or(&self.empty_str)
        );

        // reset
        self.passspray_2_user = HashMap::new();
    }

    fn audit_log_cleared(&mut self, event_id: &String, user_data: &Option<event::UserData>) {
        if event_id != "1102" {
            return;
        }

        println!("Audit Log Clear");
        println!("The Audit log was cleared.");

        let username = user_data.as_ref().and_then(|u| {
            u.log_file_cleared
                .as_ref()
                .and_then(|l| l.subject_user_name.as_ref())
        });
        println!("Security ID: {}", username.unwrap_or(&"".to_string()));
    }
}
