use std::collections::HashMap;

pub fn detection(event_id: String, event_data: HashMap<String, String>,
    alert_all_admin: i32, total_admin_logons: &mut i32,
    admin_logons: &mut HashMap<String, HashMap<String, i32>>, 
    multiple_admin_logons: &mut HashMap<String, i32>) {

    if event_id == "4672" {
        se_debug_privilege(event_data, alert_all_admin, total_admin_logons,
            admin_logons, multiple_admin_logons);
    }
}

//
// Special privileges assigned to new logon (possible admin access)
//
fn se_debug_privilege(event_data: HashMap<String, String>,
    alert_all_admin: i32, total_admin_logons: &mut i32,
    admin_logons: &mut HashMap<String, HashMap<String, i32>>, 
    multiple_admin_logons: &mut HashMap<String, i32>) {

    match event_data.get("PrivilegeList") {
        Some(privileage_list) => {
            match privileage_list.find("SeDebugPrivilege") {
                Some(data) => {

                    // alert_all_adminが有効であれば、標準出力して知らせる
                    // DeepBlueCLIでは必ず0になっていて、基本的には表示されない。
                    if alert_all_admin == 1 {
                        println!("Logon with SeDebugPrivilege (admin access)");
                        println!("Username:{}", event_data["SubjectUserName"]);
                        println!("Domain:{}", event_data["SubjectDomainName"]);
                        println!("User SID:{}", event_data["SubjectUserSid"]);
                        println!("Domain:{}", event_data["PrivilegeList"]);
                    }

                    *total_admin_logons += 1;

                    // admin_logons配列にusernameが含まれているか確認
                    match admin_logons.get(&event_data["SubjectUserName"]) {
                        Some(sid) => {
                            // 含まれていれば、マルチユーザが管理者としてログインしているか確認
                            // マルチログオンのデータをセット
                            if event_data["SubjectUserName"] != event_data["SubjectUserSid"] { // One username with multiple admin logon SIDs 
                                multiple_admin_logons.insert(event_data["SubjectUserName"].to_string(),1);
                                
                                let mut count_hash: HashMap<String, i32> = HashMap::new();
                                count_hash.insert(event_data["SubjectUserSid"].to_string(), sid[&event_data["SubjectUserSid"]] + 1);
                                admin_logons.insert(event_data["SubjectUserName"].to_string(), count_hash);
                            }
                        },
                        None => {
                            // admin_logons配列にセットUserNameとSIDとカウンタをセット
                            let mut count_hash: HashMap<String, i32> = HashMap::new();
                            count_hash.insert(event_data["SubjectUserSid"].to_string(), 1);
                            admin_logons.insert(event_data["SubjectUserName"].to_string(), count_hash);
                            
                        }
                    }
                },
                None => (),
            }
        },
        None => (),
        
    }
    
}

