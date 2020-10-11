use std::fs::File;
use std::io::prelude::*;
use std::sync::Once;

#[derive(Clone)]
pub struct SingletonReader {
    pub regex: Vec<Vec<String>>,
    pub whitelist: Vec<Vec<String>>,
}

pub fn get_instance() -> Box<SingletonReader> {
    static mut SINGLETON: Option<Box<SingletonReader>> = Option::None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonReader {
                regex: read_csv("regexes.txt"),
                whitelist: read_csv("whitelist.txt"),
            };

            SINGLETON = Some(Box::new(singleton));
        });

        return SINGLETON.clone().unwrap();
    }
}

fn read_csv(filename: &str) -> Vec<Vec<String>> {
    let mut f = File::open(filename).expect("file not found!!!");
    let mut contents: String = String::new();
    let mut ret = vec![];
    if f.read_to_string(&mut contents).is_err() {
        return ret;
    }

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    return ret;
}
