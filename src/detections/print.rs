use crate::detections::configs::{get_lang, Lang};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug)]
pub struct MessageText {
    pub ja: String,
    pub en: String,
}

#[derive(Debug)]
pub struct Message {
    map: HashMap<String, MessageText>,
}

impl Message {
    pub fn new() -> Self {
        let mut messages: HashMap<String, MessageText> = HashMap::new();
        messages.insert(
            "undefined".to_string(),
            MessageText {
                ja: "未設定".to_string(),
                en: "Undefined".to_string(),
            },
        );
        Message { map: messages }
    }

    /// メッセージを設定
    pub fn insert_message(&mut self, error_code: String, message: MessageText) {
        self.map.insert(error_code, message);
    }

    /// メッセージを返す
    pub fn return_message(&self, message_num: &str) -> &MessageText {
        self.map.get(message_num).unwrap_or(self.map.get("undefined").unwrap())
    }
}

/// メッセージテキストを言語設定に合わせて返す
/// println!("{}", <MessageText>) とすると今の言語設定で出力される
impl fmt::Display for MessageText {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match get_lang() {
            Lang::Ja => write!(f, "{}", self.ja),
            Lang::En => write!(f, "{}", self.en),
        }
    }
}

#[test]
fn test_create_and_read_message() {
    let mut error_message = Message::new();

    error_message.insert_message(
        "4103".to_string(),
        MessageText {
            ja: "パイプライン実行をしています".to_string(),
            en: "Execute pipeline".to_string(),
        },
    );

    let display = format!("{}", format_args!("{}", error_message.return_message("4103")));

    assert_eq!(display, "Execute pipeline")
}
