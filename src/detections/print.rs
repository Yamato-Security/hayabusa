use std::collections::HashMap;

#[derive(Debug)]
pub enum Lang {
    Ja,
    En,
}

#[derive(Debug)]
pub struct MessageText {
    ja: String,
    en: String,
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

    /// メッセージを指定された言語で返す
    pub fn return_error_message(&self, error_num: &str, lang: Lang) -> String {
        let messages = self.map.get(error_num).unwrap_or(self.map.get("undefined").unwrap());
        match lang {
            Lang::Ja => messages.ja.clone(),
            Lang::En => messages.en.clone(),
        }
    }
}

#[test]
fn test_create_error_message() {
    let mut error_message = Message::new();

    error_message.insert_message(
        "4103".to_string(),
        MessageText {
            ja: "パイプライン実行をしています".to_string(),
            en: "Execute pipeline".to_string(),
        },
    );

    let message_ja1 = error_message.return_error_message("4103", Lang::Ja);
    assert_eq!(message_ja1, "パイプライン実行をしています");
    let message_ja2 = error_message.return_error_message("4103", Lang::Ja);
    assert_eq!(message_ja2, "パイプライン実行をしています");

    let message_en1 = error_message.return_error_message("4103", Lang::En);
    assert_eq!(message_en1, "Execute pipeline");
    let message_en2 = error_message.return_error_message("4103", Lang::En);
    assert_eq!(message_en2, "Execute pipeline");

    let undef_ja = error_message.return_error_message("HOGE", Lang::Ja);
    assert_eq!(undef_ja, "未設定");
    let undef_en = error_message.return_error_message("HOGE", Lang::En);
    assert_eq!(undef_en, "Undefined");
}
