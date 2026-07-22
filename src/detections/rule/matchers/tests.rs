use super::super::selectionnodes::{
    LeafSelectionNode, LogicalOp, NarySelectionNode, SelectionNode,
};
use super::FastMatch;
use super::{
    AllowlistFileMatcher, DefaultMatcher, MinlengthMatcher, PipeElement, RegexesFileMatcher,
};
use crate::detections::configs::{Action, Config, DfirTimelineOption, OutputOption, StoredStatic};
use crate::detections::rule::tests::parse_rule_from_str;
use crate::detections::{self, utils};

fn check_select(rule_str: &str, record_str: &str, expect_select: bool) {
    let mut rule_node = parse_rule_from_str(rule_str);
    let dummy_stored_static = StoredStatic::create_static_data(Config {
        action: Some(Action::DfirTimeline(DfirTimelineOption {
            output_options: OutputOption {
                min_level: "informational".to_string(),
                no_wizard: true,
                ..Default::default()
            },
            ..Default::default()
        })),
        ..Default::default()
    });

    match serde_json::from_str(record_str) {
        Ok(record) => {
            let keys = detections::rule::get_detection_keys(&rule_node);
            let recinfo = utils::create_rec_info(
                record,
                "testpath".to_owned(),
                &keys,
                &false,
                &false,
                &dummy_stored_static.eventkey_alias,
            );
            assert_eq!(
                rule_node.select(
                    &recinfo,
                    dummy_stored_static.verbose_flag,
                    dummy_stored_static.quiet_errors_flag,
                    dummy_stored_static.json_input_flag,
                    &dummy_stored_static.eventkey_alias,
                    &dummy_stored_static.error_log_stack,
                ),
                expect_select
            );
        }
        Err(_rec) => {
            panic!("Failed to parse json record.");
        }
    }
}

#[test]
fn test_rule_parse() {
    // Load the rule file in YAML format.
    let rule_str = r#"
        title: PowerShell Execution Pipeline
        description: hogehoge
        enabled: true
        author: Yea
        logsource:
            product: windows
        detection:
            selection:
                Channel: Microsoft-Windows-PowerShell/Operational
                EventID: 4103
                ContextInfo:
                    - Host Application
                    - ホスト アプリケーション
                ImagePath:
                    min_length: 1234321
                    regexes: test_files/config/regex/detectlist_suspicous_services.txt
                    allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        falsepositives:
            - unknown
        level: medium
        details: 'command=%CommandLine%'
        creation_date: 2020/11/8
        updated_date: 2020/11/8
        "#;
    let rule_node = parse_rule_from_str(rule_str);
    let selection_node = &rule_node.detection.name_to_selection["selection"];

    // Root
    let detection_children = selection_node.get_children();
    assert_eq!(detection_children.len(), 4);

    // Channel
    {
        // Verify that LeafSelectionNode is correctly loaded.
        let child_node = detection_children[0];
        assert!(child_node.is::<LeafSelectionNode>());
        let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
        assert_eq!(child_node.get_key(), "Channel");
        assert_eq!(child_node.get_children().len(), 0);

        // Verify that the comparison matcher is correct.
        let matcher = &child_node.matcher;
        assert!(matcher.is_some());
        let matcher = child_node.matcher.as_ref().unwrap();
        assert!(matcher.is::<DefaultMatcher>());
        let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();

        assert!(matcher.fast_match.is_some());
        let fast_match = matcher.fast_match.as_ref().unwrap();
        assert_eq!(
            *fast_match,
            vec![FastMatch::Exact(
                "Microsoft-Windows-PowerShell/Operational".to_string()
            )]
        );
    }

    // EventID
    {
        // Verify that LeafSelectionNode is correctly loaded.
        let child_node = detection_children[1] as &dyn SelectionNode;
        assert!(child_node.is::<LeafSelectionNode>());
        let child_node = child_node.downcast_ref::<LeafSelectionNode>().unwrap();
        assert_eq!(child_node.get_key(), "EventID");
        assert_eq!(child_node.get_children().len(), 0);

        // Verify that the comparison matcher is correct.
        let matcher = &child_node.matcher;
        assert!(matcher.is_some());
        let matcher = child_node.matcher.as_ref().unwrap();
        assert!(matcher.is::<DefaultMatcher>());
        let matcher = matcher.downcast_ref::<DefaultMatcher>().unwrap();
        assert!(matcher.fast_match.is_some());
    }

    // ContextInfo
    {
        // Verify that an OR-op NarySelectionNode is correctly loaded.
        let child_node = detection_children[2] as &dyn SelectionNode;
        assert!(child_node.is::<NarySelectionNode>());
        let child_node = child_node.downcast_ref::<NarySelectionNode>().unwrap();
        assert_eq!(child_node.op, LogicalOp::Any);
        let ancestors = child_node.get_children();
        assert_eq!(ancestors.len(), 2);

        // Test patterns where LeafSelectionNode is under the OR node.
        // Verify that the Host Application node, which is a LeafSelectionNode, is correct.
        let hostapp_en_node = ancestors[0] as &dyn SelectionNode;
        assert!(hostapp_en_node.is::<LeafSelectionNode>());
        let hostapp_en_node = hostapp_en_node.downcast_ref::<LeafSelectionNode>().unwrap();

        let hostapp_en_matcher = &hostapp_en_node.matcher;
        assert!(hostapp_en_matcher.is_some());
        let hostapp_en_matcher = hostapp_en_matcher.as_ref().unwrap();
        assert!(hostapp_en_matcher.is::<DefaultMatcher>());
        let hostapp_en_matcher = hostapp_en_matcher.downcast_ref::<DefaultMatcher>().unwrap();
        assert!(hostapp_en_matcher.fast_match.is_some());
        let fast_match = hostapp_en_matcher.fast_match.as_ref().unwrap();
        assert_eq!(
            *fast_match,
            vec![FastMatch::Exact("Host Application".to_string())]
        );

        // Verify that the Japanese-locale host application node, which is a LeafSelectionNode,
        // is correct.
        let hostapp_jp_node = ancestors[1] as &dyn SelectionNode;
        assert!(hostapp_jp_node.is::<LeafSelectionNode>());
        let hostapp_jp_node = hostapp_jp_node.downcast_ref::<LeafSelectionNode>().unwrap();

        let hostapp_jp_matcher = &hostapp_jp_node.matcher;
        assert!(hostapp_jp_matcher.is_some());
        let hostapp_jp_matcher = hostapp_jp_matcher.as_ref().unwrap();
        assert!(hostapp_jp_matcher.is::<DefaultMatcher>());
        let hostapp_jp_matcher = hostapp_jp_matcher.downcast_ref::<DefaultMatcher>().unwrap();
        assert!(hostapp_jp_matcher.fast_match.is_some());
        let fast_match = hostapp_jp_matcher.fast_match.as_ref().unwrap();
        assert_eq!(
            *fast_match,
            vec![FastMatch::Exact("ホスト アプリケーション".to_string())]
        );
    }

    // ImagePath
    {
        // Verify that an AND-op NarySelectionNode is correctly loaded.
        let child_node = detection_children[3] as &dyn SelectionNode;
        assert!(child_node.is::<NarySelectionNode>());
        let child_node = child_node.downcast_ref::<NarySelectionNode>().unwrap();
        assert_eq!(child_node.op, LogicalOp::All);
        let ancestors = child_node.get_children();
        assert_eq!(ancestors.len(), 3);

        // Verify that min-len is correctly loaded.
        {
            let ancestor_node = ancestors[0] as &dyn SelectionNode;
            assert!(ancestor_node.is::<LeafSelectionNode>());
            let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let ancestor_node = &ancestor_node.matcher;
            assert!(ancestor_node.is_some());
            let ancestor_matcher = ancestor_node.as_ref().unwrap();
            assert!(ancestor_matcher.is::<MinlengthMatcher>());
            let ancestor_matcher = ancestor_matcher.downcast_ref::<MinlengthMatcher>().unwrap();
            assert_eq!(ancestor_matcher.min_len, 1234321);
        }

        // Verify that regexes are correctly loaded.
        {
            let ancestor_node = ancestors[1] as &dyn SelectionNode;
            assert!(ancestor_node.is::<LeafSelectionNode>());
            let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let ancestor_node = &ancestor_node.matcher;
            assert!(ancestor_node.is_some());
            let ancestor_matcher = ancestor_node.as_ref().unwrap();
            assert!(ancestor_matcher.is::<RegexesFileMatcher>());
            let ancestor_matcher = ancestor_matcher
                .downcast_ref::<RegexesFileMatcher>()
                .unwrap();

            // Verify that the contents match the regexes file.
            let csvcontent = &ancestor_matcher.regexes;

            assert_eq!(csvcontent.len(), 16);
            assert_eq!(
                csvcontent[0].as_str().to_string(),
                r"^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$"
            );
            assert_eq!(
                csvcontent[13].as_str().to_string(),
                r"\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp"
            );
        }

        // Verify that the allowlist file can be loaded.
        {
            let ancestor_node = ancestors[2] as &dyn SelectionNode;
            assert!(ancestor_node.is::<LeafSelectionNode>());
            let ancestor_node = ancestor_node.downcast_ref::<LeafSelectionNode>().unwrap();

            let ancestor_node = &ancestor_node.matcher;
            assert!(ancestor_node.is_some());
            let ancestor_matcher = ancestor_node.as_ref().unwrap();
            assert!(ancestor_matcher.is::<AllowlistFileMatcher>());
            let ancestor_matcher = ancestor_matcher
                .downcast_ref::<AllowlistFileMatcher>()
                .unwrap();

            let csvcontent = &ancestor_matcher.regexes;
            assert_eq!(csvcontent.len(), 2);

            assert_eq!(
                csvcontent[0].as_str().to_string(),
                r#"^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe""#.to_string()
            );
            assert_eq!(
                csvcontent[1].as_str().to_string(),
                r#"^"C:\\Program Files\\Google\\Update\\GoogleUpdate\.exe""#.to_string()
            );
        }
    }
}

#[test]
fn test_notdetect_regex_eventid() {
    // Since it is an exact match, verify that prefix matching does not detect.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 410}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_notdetect_regex_eventid2() {
    // Since it is an exact match, verify that suffix matching does not detect.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_regex_eventid() {
    // This should be detected for EventID=4103.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_notdetect_regex_str() {
    // Also verify with string-like data.
    // Since it is an exact match, verify that it does not match as a prefix.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Securit"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_notdetect_regex_str2() {
    // Also verify with string-like data.
    // Since it is an exact match, verify that it does not match as a suffix.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ecurity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_regex_str() {
    // Verify that exact matching also works with string-like data.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_notdetect_regex_emptystr() {
    // Verify that an empty string value does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"Channel": ""}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_notdetect_minlen() {
    // Verify that min_length does not match when the value is shorter.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security9", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_minlen() {
    // Verify that minlen is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_minlen2() {
    // Verify that minlen is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security.11", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_minlen_and() {
    // Verify that minlen is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_notdetect_minlen_and() {
    // Verify that min_length does not match when the value is shorter.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 11
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_regex() {
    // Verify that regex can be used.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel|re: ^Program$
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_regex_partial_match() {
    // Partial regex match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re: DESKTOP
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_regexes() {
    // Verify that the allowlist file is correctly handled (despite the test name, the rule
    // only uses an allowlist).
    // In this case, the EventID matches, but since it matches the allowlist, it should not be
    // detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

    // Note that when using double quotes as values in JSON, \ escape is required.
    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_allowlist() {
    // Verify that the allowlist is correctly handled.
    // In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

    // Note that when using double quotes as values in JSON, \ escape is required.
    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_allowlist2() {
    // Verify that the allowlist is correctly handled.
    // In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_startswith1() {
    // Verify that startswith is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_startswith2() {
    // Verify that startswith is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_startswith_case_insensitive() {
    // Verify that startswith is case-insensitive.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "ADMINISTRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_startswith_cased() {
    // Verify that startswith|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_startswith_cased2() {
    // Verify that startswith|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_endswith1() {
    // Verify that endswith is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_endswith2() {
    // Verify that endswith is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_endswith_case_insensitive() {
    // Test to verify that endswith detects without distinguishing case.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "ADministRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_endswith_cased1() {
    // Verify that endswith|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_endswith_cased2() {
    // Verify that endswith|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "test"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_endswith_cased3() {
    // Verify that endswith|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "sTest"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_contains1() {
    // Verify that contains is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_contains2() {
    // Verify that contains is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_contains_case_insensitive() {
    // Test to verify that contains detects without distinguishing case.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "ADminIstraTOrS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_contains_cased1() {
    // Verify that contains|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_contains_cased2() {
    // Verify that contains|cased is correctly detected.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "MinistratorS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_wildcard_multibyte() {
    // Verification with multi-byte characters.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホストアプリケーション
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_wildcard_multibyte_notdetect() {
    // Verification with multi-byte characters.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホスとアプリケーション
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_case_insensitive() {
    // Wildcards match regardless of case.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_question_fullmatch() {
    // A "?" wildcard matches exactly one character of the full value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Sec?rity
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Sec1rity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_question_no_substring_match() {
    // Patterns that fall back to regex matching (here because of "?") must match the whole
    // value, not a substring of it (regression test for #1815).
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: Sec?rity
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "MySec1rityLog"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_midstring_asterisk_fullmatch() {
    // A mid-string "*" wildcard (not convertible to a fast match) matches the full value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: net*user
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "netXYZuser"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_midstring_asterisk_no_substring_match() {
    // A mid-string "*" wildcard must not match a value with extra leading/trailing
    // characters (regression test for #1815).
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: net*user
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "mynetXuserZ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_multibyte_asterisk_fullmatch() {
    // Non-ASCII patterns with "*" always take the regex path; the prefix part must still
    // be anchored to the start of the value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホスト*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_multibyte_asterisk_no_substring_match() {
    // A non-ASCII prefix pattern must not match a value that merely contains the prefix
    // (regression test for #1815).
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel: ホスト*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Myホストログ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_grep_substring_match_still_works() {
    // Keyword (grep) searches with no field name intentionally keep substring semantics:
    // anchoring added for field matches (#1815) must not apply here.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                - ecurit
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_all_keyword_wildcard_substring_match() {
    // A keyless `|all` selection is matched against the whole-record string with substring
    // (contains) semantics, even when a value falls back to regex matching (here because of
    // the `?` wildcard). The anchoring added for field matches (#1815) must not apply to the
    // `|all` whole-record search, otherwise it would require the entire record to equal the
    // pattern and never match. `Windo?s` matches the "Windows" contained in the Channel value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                '|all':
                    - 'Windo?s'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Microsoft-Windows-Sysmon/Operational"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_startswith_multibyte_fallback_fullmatch() {
    // |startswith normally uses the fast path, but a non-ASCII event value makes
    // starts_with_ignore_case() return None, so matching falls back to the wildcard regex.
    // That fallback must remain a prefix match: "Secあ" starts with "Sec".
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel|startswith: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Secあ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_startswith_multibyte_fallback_no_substring_match() {
    // The non-ASCII |startswith regex fallback must be anchored to the start of the value, so
    // a value that merely contains the prefix later on does not match (#1815).
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel|startswith: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "xSecあ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_pipe_pattern_wildcard_asterisk() {
    let value = PipeElement::pipe_pattern_wildcard(r"*ho*ge*".to_string());
    assert_eq!(
        "(?i)(.|\\a|\\f|\\t|\\n|\\r|\\v)*ho(.|\\a|\\f|\\t|\\n|\\r|\\v)*ge(.|\\a|\\f|\\t|\\n|\\r|\\v)*",
        value
    );
}

#[test]
fn test_pipe_pattern_wildcard_asterisk2() {
    let value = PipeElement::pipe_pattern_wildcard(r"\*ho\*\*ge\*".to_string());
    // The wildcard "\*" represents the literal "*".
    // In regex, "*" must be escaped, so \* is correct.
    assert_eq!(r"(?i)\*ho\*\*ge\*", value);
}

#[test]
fn test_pipe_pattern_wildcard_asterisk3() {
    // The wildcard "\\\\*" represents the literal "\\" and the regex ".*".
    // The literal "\\" is escaped, so "\\\\.*" is correct.
    let value = PipeElement::pipe_pattern_wildcard(r"\\*ho\\*ge\\*".to_string());
    assert_eq!(
        r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*ho\\(.|\a|\f|\t|\n|\r|\v)*ge\\(.|\a|\f|\t|\n|\r|\v)*",
        value
    );
}

#[test]
fn test_pipe_pattern_wildcard_question() {
    let value = PipeElement::pipe_pattern_wildcard(r"?ho?ge?".to_string());
    assert_eq!(r"(?i).ho.ge.", value);
}

#[test]
fn test_pipe_pattern_wildcard_question2() {
    let value = PipeElement::pipe_pattern_wildcard(r"\?ho\?ge\?".to_string());
    assert_eq!(r"(?i)\?ho\?ge\?", value);
}

#[test]
fn test_pipe_pattern_wildcard_question3() {
    let value = PipeElement::pipe_pattern_wildcard(r"\\?ho\\?ge\\?".to_string());
    assert_eq!(r"(?i)\\.ho\\.ge\\.", value);
}

#[test]
fn test_pipe_pattern_wildcard_backslash() {
    let value = PipeElement::pipe_pattern_wildcard(r"\\ho\\ge\\".to_string());
    assert_eq!(r"(?i)\\\\ho\\\\ge\\\\", value);
}

#[test]
fn test_pipe_pattern_wildcard_mixed() {
    let value = PipeElement::pipe_pattern_wildcard(r"\\*\****\*\\*".to_string());
    assert_eq!(
        r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*\*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*\*\\(.|\a|\f|\t|\n|\r|\v)*",
        value
    );
}

#[test]
fn test_pipe_pattern_wildcard_many_backslashes() {
    let value = PipeElement::pipe_pattern_wildcard(r"\\\*ho\\\*ge\\\".to_string());
    assert_eq!(
        r"(?i)\\\\(.|\a|\f|\t|\n|\r|\v)*ho\\\\(.|\a|\f|\t|\n|\r|\v)*ge\\\\\\",
        value
    );
}

#[test]
fn test_grep_match() {
    // A selection written as a bare list (no field name) performs a grep-style match against
    // the whole record.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4103
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_grep_not_match() {
    // A grep-style match (bare list, no field name) does not match a record that does not
    // contain the value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                - 4104
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_value_keyword() {
    // Verify that the "value:" keyword form matches exactly.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_notdetect_value_keyword() {
    // Verify that the "value:" keyword form is an exact match: a similar but different
    // value (rule "Securiteen" vs record "Security") does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Securiteen
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_endswith_field() {
    // Verify that endswithfield is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_endswith_field2() {
    // Verify that endswithfield is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_endswith_field_caseinsensitive() {
    // Verify that endswithfield detects case-insensitively.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "iTy" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_endswith_field_caseinsensitive2() {
    // Verify that endswithfield detects case-insensitively.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "SecuriTy", "Computer": "ity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_endswith_field_notdetect() {
    // Patterns correctly not detected by endswithfield.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "rity", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_endswith_field_notdetect2() {
    // Patterns correctly not detected by endswithfield.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field_ref() {
    // Verify that fieldref is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_eq_field_ref_notdetect() {
    // Patterns that fieldref cannot detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field_ref_endswith() {
    // Verify that fieldref is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|endswith: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_eq_field_ref_notdetect_endswith() {
    // Patterns that fieldref cannot detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field_ref_startswith() {
    // Verify that fieldref is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_eq_field_ref_notdetect_startswith() {
    // Patterns that fieldref cannot detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field_ref_contains() {
    // Verify that fieldref is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_eq_field_ref_notdetect_contains() {
    // Patterns that fieldref cannot detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_neq_detect() {
    // `neq` matches when the field value is different from the specified value.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_neq_notdetect() {
    // `neq` does not match when the field value equals the specified value.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_neq_case_insensitive_notdetect() {
    // Like the plain value match, `neq` equality is case-insensitive, so "security" == "Security"
    // and therefore `neq` does not match.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_neq_missing_field_detect() {
    // A missing field is treated as different from the value (consistent with `not` in condition),
    // so `neq` matches.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_neq_wildcard_notdetect() {
    // Wildcards still apply to the value being negated: "Sec*" matches "Security", so `neq` does not match.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: Sec*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_neq_wildcard_detect() {
    // "Sec*" does not match "PowerShell", so `neq` matches.
    let rule_str = r#"
        detection:
            selection:
                Channel|neq: Sec*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_contains_neq_detect() {
    // `contains|neq` matches when the field does NOT contain the value.
    let rule_str = r#"
        detection:
            selection:
                Channel|contains|neq: cur
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_contains_neq_notdetect() {
    // `contains|neq` does not match when the field contains the value ("Security" contains "cur").
    let rule_str = r#"
        detection:
            selection:
                Channel|contains|neq: cur
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_startswith_neq_detect() {
    // `startswith|neq` matches when the field does NOT start with the value.
    let rule_str = r#"
        detection:
            selection:
                Channel|startswith|neq: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_startswith_neq_notdetect() {
    // `startswith|neq` does not match when the field starts with the value.
    let rule_str = r#"
        detection:
            selection:
                Channel|startswith|neq: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_endswith_neq_detect() {
    // `endswith|neq` matches when the field does NOT end with the value.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswith|neq: rity
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_endswith_neq_notdetect() {
    // `endswith|neq` does not match when the field ends with the value.
    let rule_str = r#"
        detection:
            selection:
                Channel|endswith|neq: rity
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_fieldref_neq_detect() {
    // `fieldref|neq` matches when the two field values are different.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_fieldref_neq_notdetect() {
    // `fieldref|neq` does not match when the two field values are the same.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_fieldref_neq_missing_ref_detect() {
    // If the referenced field is missing, the values are considered different, so `fieldref|neq` matches.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_fieldref_contains_neq_detect() {
    // `fieldref|contains|neq` matches when the left field does NOT contain the right field's value.
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains|neq: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "xyz" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_fieldref_contains_neq_notdetect() {
    // `fieldref|contains|neq` does not match when the left field contains the right field's value
    // ("Security" contains "cur").
    let rule_str = r#"
        detection:
            selection:
                Channel|fieldref|contains|neq: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_re_neq_detect() {
    // `re|neq` matches when the (case-sensitive) regex does NOT match.
    let rule_str = r#"
        detection:
            selection:
                Channel|re|neq: ^Sec.*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_re_neq_notdetect() {
    // `re|neq` does not match when the regex matches.
    let rule_str = r#"
        detection:
            selection:
                Channel|re|neq: ^Sec.*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_re_i_neq_notdetect() {
    // The `i` (case-insensitive) flag still composes with `neq`: "^sec.*" matches "Security"
    // case-insensitively, so `re|i|neq` does not match.
    let rule_str = r#"
        detection:
            selection:
                Channel|re|i|neq: ^sec.*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_gt_neq_equal_detect() {
    // Numeric `gt|neq`: the value equal to the bound is NOT greater than it, so the base `gt`
    // is false and `neq` matches.
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 1040 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_gt_neq_greater_notdetect() {
    // A value greater than the bound satisfies the base `gt`, so `gt|neq` does not match.
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 1041 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_gt_neq_missing_field_detect() {
    // A missing (or non-numeric) field makes the base `gt` false, so `gt|neq` matches
    // (consistent with the missing-field behavior of the other `neq` forms).
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
            "Event": {"System": {"Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_cidr_neq_detect() {
    // `cidr|neq` matches when the IP is NOT in the range (e.g. excluding an internal subnet).
    let rule_str = r#"
        detection:
            selection:
                IpAddress|cidr|neq: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "10.0.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_cidr_neq_notdetect() {
    // `cidr|neq` does not match when the IP is in the range.
    let rule_str = r#"
        detection:
            selection:
                IpAddress|cidr|neq: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.1.5"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_contains_cased_neq_detect() {
    // `contains|cased|neq` is case-sensitive: "security" does not contain "Sec" (different case),
    // so `neq` matches.
    let rule_str = r#"
        detection:
            selection:
                Channel|contains|cased|neq: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_contains_cased_neq_notdetect() {
    // "Security" contains "Sec" (same case), so `contains|cased|neq` does not match.
    let rule_str = r#"
        detection:
            selection:
                Channel|contains|cased|neq: Sec
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field() {
    // Verify that equalsfields is correctly detected.
    let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_eq_field_notdetect() {
    // Patterns that equalsfields cannot detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_eq_field_emptyfield() {
    // If a non-existent field is specified, do not detect.
    let rule_str = r#"
        detection:
            selection:
                Channel|equalsfield: NoField
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Securiti" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);

    let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: Channel
        details: 'command=%CommandLine%'
        "#;
    check_select(rule_str, record_json_str, false);

    let rule_str = r#"
        detection:
            selection:
                NoField|equalsfield: NoField1
        details: 'command=%CommandLine%'
        "#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_field_null() {
    // Verify that a null value matches when the target field does not exist in the record.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
                Takoyaki:
                    value: null
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_field_null_not_detect() {
    // Test that a null value requires the target field to be absent: here the field exists,
    // so the rule does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                EventID: null
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_converted_starts_with() {
    // When a single wildcard is at the end, it is equivalent to starts_with matching.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_converted_starts_with_notdetect() {
    // When a single wildcard is at the end, it is equivalent to starts_with matching.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: AA-*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_converted_starts_with_exact_val() {
    // When a single wildcard is at the end and the characters to compare (excluding *) exactly match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_converted_starts_with_shorter_val_notdetect() {
    // When a single wildcard is at the end but the event value is shorter than the pattern,
    // it does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: A-HOST-*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_wildcard_converted_starts_with_multibytes() {
    // Patterns containing wildcards and non-ASCII characters use regex matching.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: 社員端末*
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "社員端末A"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_converted_ends_with() {
    // When a single wildcard is at the beginning, it is equivalent to ends_with matching.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_converted_ends_with_starts_with_exact_val() {
    // When a single wildcard is at the beginning and the characters to compare (excluding *) exactly match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*A-HOST'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_wildcard_converted_ends_with_shorter_val_notdetect() {
    // When a single wildcard is at the beginning, a value that does not end with the
    // pattern's suffix does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOSTA'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_only_wildcard() {
    // A pattern consisting of only a wildcard is converted to ends_with("") and therefore
    // matches any value.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_two_wildcards() {
    // When two or more wildcards are included, use regex matching.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer: '*-HOST-*'
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST-1"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_base64_contains() {
    // A pattern that matches base64|contains.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_base64offset_contains() {
    // A pattern that matches base64offset|contains.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

// The following tests pin the order-independent behavior introduced with `MatchPlan`: a
// non-canonical modifier order is now normalized the same as the canonical order, instead of
// missing the former index-based fast-path table and silently falling back to a wildcard regex
// that ignored the modifier. Sigma fixes modifier order, so real rules only ever use the
// canonical order (covered by the tests above); these lock in the non-canonical behavior.
#[test]
fn test_reordered_cased_contains_is_case_sensitive() {
    // |cased|contains == |contains|cased (case-sensitive substring). The old order-sensitive
    // table missed this order and fell back to a case-insensitive regex (ignoring |cased).
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                TargetUserName|cased|contains: "Administrators"
        details: 'user %MemberName%'
        "#;
    let match_rec = r#"{"Event": {"System": {"EventID": 4732, "Channel": "Security"}, "EventData": {"TargetUserName": "TestAdministratorsTest"}}}"#;
    let case_mismatch_rec = r#"{"Event": {"System": {"EventID": 4732, "Channel": "Security"}, "EventData": {"TargetUserName": "testadministratorstest"}}}"#;
    check_select(rule_str, match_rec, true);
    // Case-sensitive: a value differing only in case must NOT match.
    check_select(rule_str, case_mismatch_rec, false);
}

#[test]
fn test_reordered_contains_base64() {
    // |contains|base64 == |base64|contains (pattern is base64-encoded before the substring
    // search). The old order-sensitive table ignored base64 in this order.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|contains|base64:
                    - "http://"
        details: 'x'
        "#;
    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_reordered_contains_base64offset() {
    // |contains|base64offset == |base64offset|contains.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|contains|base64offset:
                    - "http://"
        details: 'x'
        "#;
    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_utf16_base64_contains_canonical_and_reordered() {
    // |utf16|base64|contains encodes the pattern as UTF-16LE (with a BOM) then base64. This
    // path had no unit coverage before; verify both the canonical order and the reordered
    // |base64|utf16|contains (which the old index-based table did not recognize).
    let canonical = r#"
        enabled: true
        detection:
            selection:
                Payload|utf16|base64|contains:
                    - "http://"
        details: 'x'
        "#;
    let reordered = r#"
        enabled: true
        detection:
            selection:
                Payload|base64|utf16|contains:
                    - "http://"
        details: 'x'
        "#;
    // Payload holds base64(BOM + UTF-16LE("http://")).
    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "//5oAHQAdABwADoALwAvAA"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;
    check_select(canonical, record_json_str, true);
    check_select(reordered, record_json_str, true);
}

#[test]
fn test_base64offset_contains_not_match() {
    // A pattern that does not match base64offset|contains.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "test"
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_cidr_ipv4_detect() {
    // IPs matching CIDR.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_cidr_ipv4_not_detect() {
    // IPs not matching CIDR.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2600:1f18:130c:d900::/56
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "8.8.8.8"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_cidr_ipv6_detect() {
    // IPs matching CIDR.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1234:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_cidr_ipv6_not_detect() {
    // IPs not matching CIDR.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1111:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_cidr_ip_field_not_exists_not_detect() {
    // When the IP address field does not exist in the record, the rule does not match.
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4624} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_backslash_exact_match() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory: 'C:\Windows\'
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_startswith_backslash1() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_startswith_backslash2() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false); // Expect false: the backslash must match literally.
}

#[test]
fn test_detect_contains_backslash1() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_contains_backslash2() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_detect_backslash_endswith() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|endswith: 'C:\Windows\system32\'
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_detect_backslash_regex() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|re: '.*system32\\'
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_all_only_detect_case() {
    let rule_str = r"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_all_only_no_detect_case() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_all_only_detected_and_selection_false() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 'dummy'
            condition: selection1 and selection2
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_all_only_not_detect_and_selection_false() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 3
                - 2
            condition: selection1 and selection2
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_contains_windash() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '-addstore'
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

    let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -addstore"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, true);
    check_select(rule_str, record_json_str2, true);
}

#[test]
fn test_contains_all_windash() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '-addstore'
                    - '-test-test'
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -test-test /addstore"
            }
          }
        }"#;

    let record_json_str2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test -addstore"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, true);
    check_select(rule_str, record_json_str2, false);
}

#[test]
fn test_contains_windash_multitype_dash() {
    let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '–addstore'
            condition: selection1
        "#;
    let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '—addstore'
            condition: selection1
        "#;
    let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '―addstore'
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"#;

    let record_json_str_en = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –addstore"
            }
          }
        }"#;

    let record_json_str_em = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —addstore"
            }
          }
        }"#;

    let record_json_str_horizontal = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―addstore"
            }
          }
        }"#;

    check_select(rule_str_en_dash, record_json_str, true);
    check_select(rule_str_en_dash, record_json_str_en, true);
    check_select(rule_str_en_dash, record_json_str_em, true);
    check_select(rule_str_en_dash, record_json_str_horizontal, true);
    check_select(rule_str_em_dash, record_json_str, true);
    check_select(rule_str_em_dash, record_json_str_en, true);
    check_select(rule_str_em_dash, record_json_str_em, true);
    check_select(rule_str_em_dash, record_json_str_horizontal, true);
    check_select(rule_str_horizontal_bar, record_json_str, true);
    check_select(rule_str_horizontal_bar, record_json_str_en, true);
    check_select(rule_str_horizontal_bar, record_json_str_em, true);
    check_select(rule_str_horizontal_bar, record_json_str_horizontal, true);
}

#[test]
fn test_contains_all_windash_multitype_dash() {
    let rule_str_en_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '–addstore'
                    - '–test–test'
            condition: selection1
        "#;

    let rule_str_em_dash = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '—addstore'
                    - '—test—test'
            condition: selection1
        "#;

    let rule_str_horizontal_bar = r#"
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '―addstore'
                    - '―test―test'
            condition: selection1
        "#;

    let record_json_str_en_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –test–test /addstore"
            }
          }
        }"#;

    let record_json_str_en_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test –addstore"
            }
          }
        }"#;

    let record_json_str_em_dash = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —test—test /addstore"
            }
          }
        }"#;

    let record_json_str_em_dash2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test —addstore"
            }
          }
        }"#;

    let record_json_str_horizontal_bar = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―test―test /addstore"
            }
          }
        }"#;

    let record_json_str_horizontal_bar2 = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test ―addstore"
            }
          }
        }"#;

    check_select(rule_str_en_dash, record_json_str_en_dash, true);
    check_select(rule_str_en_dash, record_json_str_en_dash2, false);
    check_select(rule_str_em_dash, record_json_str_em_dash, true);
    check_select(rule_str_em_dash, record_json_str_em_dash2, false);
    check_select(
        rule_str_horizontal_bar,
        record_json_str_horizontal_bar,
        true,
    );
    check_select(
        rule_str_horizontal_bar,
        record_json_str_horizontal_bar2,
        false,
    );
}

#[test]
fn test_exists_true() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_re_caseinsensitive_detect() {
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|i: ABC
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "abc"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_exists_null_true() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_re_multiline_detect() {
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|m: ^ABC$
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_exists_false() {
    let rule_str = r#"
        enabled: true
        detection:
            selection1:
                Dummy|exists: false
            condition: selection1
        "#;

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_re_singleline_detect() {
    let rule_str = r#"
        enabled: true
        detection:
            selection:
                Computer|re|s: A.*F
        details: 'command=%CommandLine%'
        "#;

    let record_json_str = r#"{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_ge() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}

#[test]
fn test_ge_not() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_lt() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}
#[test]
fn test_lt_not() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_gte() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}
#[test]
fn test_gte_not() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}

#[test]
fn test_lte() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lte: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;

    check_select(rule_str, record_json_str, true);
}
#[test]
fn test_lte_not() {
    let rule_str = r"
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        ";

    let record_json_str = r#"
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"#;
    check_select(rule_str, record_json_str, false);
}
