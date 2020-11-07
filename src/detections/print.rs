extern crate chrono;
extern crate lazy_static;
use chrono::{DateTime, TimeZone, Utc};
use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Message {
    map: BTreeMap<DateTime<Utc>, Vec<String>>,
}

lazy_static! {
    pub static ref MESSAGES: Mutex<Message> = Mutex::new(Message::new());
}

impl Message {
    pub fn new() -> Self {
        let messages: BTreeMap<DateTime<Utc>, Vec<String>> = BTreeMap::new();
        Message { map: messages }
    }

    /// メッセージを設定
    pub fn insert(&mut self, time: DateTime<Utc>, message: String) {
        match self.map.get_mut(&time) {
            Some(v) => {
                v.push(message.to_string());
            }
            None => {
                let m = vec![message.to_string(); 1];
                self.map.insert(time, m);
            }
        }
    }

    /// メッセージを返す
    pub fn get(&self, time: DateTime<Utc>) -> Vec<String> {
        match self.map.get(&time) {
            Some(v) => (&v).to_vec(),
            None => Vec::new(),
        }
    }

    /// Messageのなかに入っているメッセージすべてを表示する
    pub fn debug(&self) {
        println!("{:?}", self.map);
    }
}

#[test]
fn test_create_and_append_message() {
    let mut message = Message::new();
    let poke = Utc.ymd(1996, 2, 27).and_hms(1, 5, 1);
    let taka = Utc.ymd(2000, 1, 21).and_hms(9, 6, 1);

    message.insert(poke, "TEST".to_string());
    message.insert(poke, "TEST2".to_string());
    message.insert(taka, "TEST3".to_string());

    let display = format!("{}", format_args!("{:?}", message));
    let expect = "Message { map: {1996-02-27T01:05:01Z: [\"TEST\", \"TEST2\"], 2000-01-21T09:06:01Z: [\"TEST3\"]} }";
    assert_eq!(display, expect);
}
