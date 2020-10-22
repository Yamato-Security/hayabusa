use std::collections::HashMap;

#[derive(Debug)]
pub enum Lang {
    ja,
    en,
}

#[derive(Debug)]
pub struct MessageLanguages {
    ja: String,
    en: String,
}

#[derive(Debug)]
pub struct ErrorMessage {
    map: HashMap<String, MessageLanguages>,
}

impl ErrorMessage {
    pub fn new() -> Self {
        let mut messages: HashMap<String, MessageLanguages> = HashMap::new();
        messages.insert(
            "undefined".to_string(),
            MessageLanguages {
                ja: "未設定".to_string(),
                en: "Undefined".to_string(),
            },
        );
        ErrorMessage { map: messages }
    }

    /// エラーメッセージを設定
    pub fn insert_rule(&mut self, error_code: String, message: MessageLanguages) {
        self.map.insert(error_code, message);
    }

    /// エラーメッセージを指定された言語で返す
    pub fn return_error_message(&self, error_num: &str, lang: Lang) -> String {
        let messages = if let Some(boxed_message) = self.map.get(error_num) {
            boxed_message
        } else {
            self.map.get("undefined").unwrap()
        };
        match lang {
            Lang::ja => messages.ja.clone(),
            Lang::en => messages.en.clone(),
        }
    }
}

#[test]
fn test_create_error_message() {
    let mut error_message = ErrorMessage::new();

    error_message.insert_rule(
        "4103".to_string(),
        MessageLanguages {
            ja: "パイプライン実行をしています".to_string(),
            en: "Execute pipeline".to_string(),
        },
    );

    let message_ja1 = error_message.return_error_message("4103", Lang::ja);
    assert_eq!(message_ja1, "パイプライン実行をしています");
    let message_ja2 = error_message.return_error_message("4103", Lang::ja);
    assert_eq!(message_ja2, "パイプライン実行をしています");

    let message_en1 = error_message.return_error_message("4103", Lang::en);
    assert_eq!(message_en1, "Execute pipeline");
    let message_en2 = error_message.return_error_message("4103", Lang::en);
    assert_eq!(message_en2, "Execute pipeline");

    let undef_ja = error_message.return_error_message("HOGE", Lang::ja);
    assert_eq!(undef_ja, "未設定");
    let undef_en = error_message.return_error_message("HOGE", Lang::en);
    assert_eq!(undef_en, "Undefined");
}
