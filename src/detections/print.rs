extern crate lazy_static;
use crate::detections::configs::{singleton, Lang};
use crate::models::rule::MessageText;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Message {
    map: HashMap<String, MessageText>,
}

lazy_static! {
    pub static ref MESSAGES: Mutex<Message> = Mutex::new(Message::new());
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
    pub fn insert(&mut self, error_code: String, message: MessageText) {
        self.map.insert(error_code, message);
    }

    /// メッセージを返す
    pub fn get(&self, message_num: &str) -> &MessageText {
        self.map
            .get(message_num)
            .unwrap_or(self.map.get("undefined").unwrap())
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

/// Argsから言語情報を読み取り Lang を返す
pub fn get_lang() -> Lang {
    let lang: String = singleton().args.value_of("lang").unwrap_or("").to_string();

    match &*lang {
        "Ja" | "ja" => Lang::Ja,
        "En" | "en" => Lang::En,
        _ => Lang::En,
    }
}

#[test]
fn test_create_and_read_message() {
    let mut error_message = Message::new();

    error_message.insert(
        "4103".to_string(),
        MessageText {
            ja: "パイプライン実行をしています".to_string(),
            en: "Execute pipeline".to_string(),
        },
    );

    let display = format!("{}", format_args!("{}", error_message.get("4103")));

    assert_eq!(display, "Execute pipeline")
}
