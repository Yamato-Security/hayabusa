extern crate serde;
extern crate serde_derive;

use std::{fs, path::PathBuf};
use yamato_event_analyzer::afterfact::after_fact;
use yamato_event_analyzer::detections::configs;
use yamato_event_analyzer::detections::detection;
use yamato_event_analyzer::omikuji::Omikuji;

fn main() {
    if let Some(filepath) = configs::singleton().args.value_of("filepath") {
        detect_files(vec![PathBuf::from(filepath)]);
    } else if let Some(directory) = configs::singleton().args.value_of("directory") {
        let evtx_files = collect_evtxfiles(&directory);
        detect_files(evtx_files);
    }

    if configs::singleton().args.is_present("credits") {
        print_credits();
    }

    after_fact();
}

fn collect_evtxfiles(dirpath: &str) -> Vec<PathBuf> {
    let entries = fs::read_dir(dirpath);
    if entries.is_err() {
        eprintln!("{}", entries.unwrap_err());
        return vec![];
    }

    let mut ret = vec![];
    for e in entries.unwrap() {
        if e.is_err() {
            continue;
        }

        let path = e.unwrap().path();
        if path.is_dir() {
            path.to_str().and_then(|path_str| {
                let subdir_ret = collect_evtxfiles(path_str);
                ret.extend(subdir_ret);
                return Option::Some(());
            });
        } else {
            let path_str = path.to_str().unwrap_or("");
            if path_str.ends_with(".evtx") {
                ret.push(path);
            }
        }
    }

    return ret;
}

fn print_credits() {
    match fs::read_to_string("./credits.txt") {
        Ok(contents) => println!("{}", contents),
        Err(err) => println!("{}", err),
    }
}

fn detect_files(evtx_files: Vec<PathBuf>) {
    let mut detection = detection::Detection::new();
    &detection.start(evtx_files);
}

fn _output_with_omikuji(omikuji: Omikuji) {
    let fp = &format!("art/omikuji/{}", omikuji);
    let content = fs::read_to_string(fp).unwrap();
    println!("{}", content);
}

#[cfg(test)]
mod tests {
    use crate::collect_evtxfiles;

    #[test]
    fn test_collect_evtxfiles() {
        let files = collect_evtxfiles("test_files/evtx");
        assert_eq!(3, files.len());

        files.iter().for_each(|file| {
            let is_contains = &vec!["test1.evtx", "test2.evtx", "testtest4.evtx"]
                .into_iter()
                .any(|filepath_str| {
                    return file.file_name().unwrap().to_str().unwrap_or("") == filepath_str;
                });
            assert_eq!(is_contains, &true);
        })
    }
}
