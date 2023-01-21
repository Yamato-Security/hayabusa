use hashbrown::HashMap;
use horrorshow::helper::doctype;
use horrorshow::prelude::*;
use lazy_static::lazy_static;
use nested::Nested;
use pulldown_cmark::{html, Options, Parser};
use std::fs::{create_dir, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::RwLock;

use crate::detections::configs::{Action, Config};

lazy_static! {
    pub static ref HTML_REPORTER: RwLock<HtmlReporter> = RwLock::new(HtmlReporter::new());
}

#[derive(Clone)]
pub struct HtmlReporter {
    pub section_order: Nested<String>,
    pub md_datas: HashMap<String, Nested<String>>,
}

impl HtmlReporter {
    pub fn new() -> HtmlReporter {
        let (init_section_order, init_data) = get_init_md_data_map();
        HtmlReporter {
            section_order: init_section_order,
            md_datas: init_data,
        }
    }

    /// return converted String from md_data(markdown fmt string).
    pub fn create_html(self) -> String {
        let mut options = Options::empty();
        options.insert(Options::ENABLE_TABLES);
        options.insert(Options::ENABLE_HEADING_ATTRIBUTES);
        options.insert(Options::ENABLE_FOOTNOTES);

        let mut md_data = Nested::<String>::new();
        for section_name in self.section_order.iter() {
            if let Some(v) = self.md_datas.get(section_name) {
                md_data.push(format!("## {}\n", &section_name));
                if v.is_empty() {
                    md_data.push("not found data.\n");
                } else {
                    md_data.push(v.iter().collect::<Vec<&str>>().join("\n"));
                }
            }
        }
        let md_str = md_data.iter().collect::<Vec<&str>>().join("\n");
        let parser = Parser::new_ext(&md_str, options);

        let mut ret = String::new();
        html::push_html(&mut ret, parser);
        ret
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_html_flag(config: &Config) -> bool {
    if config.action.as_ref().is_none() {
        return false;
    }
    match &config.action.as_ref().unwrap() {
        Action::CsvTimeline(option) => option.output_options.html_report.is_some(),
        Action::JsonTimeline(option) => option.output_options.html_report.is_some(),
        _ => false,
    }
}

/// get html report section data in HashMap
fn get_init_md_data_map() -> (Nested<String>, HashMap<String, Nested<String>>) {
    let mut ret = HashMap::new();
    let mut section_order = Nested::<String>::new();
    section_order.extend(vec![
        "General Overview {#general_overview}",
        "Results Summary {#results_summary}",
    ]);
    for section in section_order.iter() {
        ret.insert(section.to_owned(), Nested::<String>::new());
    }

    (section_order, ret)
}

pub fn add_md_data(section_name: &str, data: Nested<String>) {
    let mut md_with_section_data = HTML_REPORTER.write().unwrap().md_datas.to_owned();
    for c in data.iter() {
        let entry = md_with_section_data
            .entry(section_name.to_owned())
            .or_insert(Nested::<String>::new());
        entry.push(c);
    }
    HTML_REPORTER.write().unwrap().md_datas = md_with_section_data;
}

/// create html file
pub fn create_html_file(input_html: String, path_str: &str) {
    let path = Path::new(path_str);
    if !path.parent().unwrap().exists() {
        create_dir(path.parent().unwrap()).ok();
    }

    let mut html_writer = BufWriter::new(File::create(path).unwrap());

    let html_data = format!(
        "{}",
        html! {
            : doctype::HTML;
            html {
                head {
                    meta(charset="UTF-8");
                    link(rel="stylesheet", type="text/css", href="./config/html_report/hayabusa_report.css");
                    link(rel="icon", type="image/png", href="./config/html_report/favicon.png");
                }
                body {
                    section {
                        img(id="logo", src = "./config/html_report/logo.png");
                        : Raw(input_html.as_str());
                    }
                }

            }
        }
    );

    writeln!(html_writer, "{}", html_data).ok();
    println!("HTML report: {}", path_str);
}

#[cfg(test)]
mod tests {

    use std::{
        fs::{read_to_string, remove_dir_all},
        path::Path,
    };

    use nested::Nested;

    use crate::{
        detections::configs::{
            Action, Config, CsvOutputOption, InputOption, JSONOutputOption, OutputOption,
            StoredStatic,
        },
        options::htmlreport::{self, HtmlReporter},
    };

    use super::HTML_REPORTER;

    fn create_dummy_stored_static(action: Option<Action>) -> StoredStatic {
        StoredStatic::create_static_data(Some(Config {
            action,
            no_color: false,
            quiet: false,
            debug: false,
        }))
    }

    #[test]
    fn test_create_html() {
        let mut html_reporter = HtmlReporter::default();
        let mut general_data = Nested::<String>::new();
        general_data.extend(vec![
            "- Analyzed event files: 581".to_string(),
            "- Total file size: 148.5 MB".to_string(),
            "- Excluded rules: 12".to_string(),
            "- Noisy rules: 5 (Disabled)".to_string(),
            "- Experimental rules: 1935 (65.97%)".to_string(),
            "- Stable rules: 215 (7.33%)".to_string(),
            "- Test rules: 783 (26.70%)".to_string(),
            "- Hayabusa rules: 138".to_string(),
            "- Sigma rules: 2795".to_string(),
            "- Total enabled detection rules: 2933".to_string(),
            "- Elapsed time: 00:00:29.035".to_string(),
            "".to_string(),
        ]);
        html_reporter.section_order.push("No Exist Section");
        html_reporter.md_datas.insert(
            "General Overview {#general_overview}".to_string(),
            general_data.to_owned(),
        );
        let gen_data = general_data.iter().collect::<Vec<&str>>();
        let general_overview_str = format!(
            "<ul>\n<li>{}</li>\n</ul>",
            gen_data[..general_data.len() - 1]
                .join("</li>\n<li>")
                .replace("- ", "")
        );
        let expect_str = format!(
            "<h2 id=\"general_overview\">General Overview</h2>\n{}\n<h2 id=\"results_summary\">Results Summary</h2>\n<p>not found data.</p>\n",
            general_overview_str
        );

        assert_eq!(html_reporter.create_html(), expect_str);
    }

    #[test]
    fn test_none_config_check_html_flag() {
        let none_action = create_dummy_stored_static(None);
        assert!(!htmlreport::check_html_flag(&none_action.config));
    }

    #[test]
    fn test_with_config_check_html_flag_csvtimeline() {
        let enable_csv_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                profile: None,
                output: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: Some(Path::new("./dummy").to_path_buf()),
                no_summary: false,
            },
        });
        let csv_html_flag_enable = create_dummy_stored_static(Some(enable_csv_action));
        assert!(htmlreport::check_html_flag(&csv_html_flag_enable.config));

        let disable_csv_action = Action::CsvTimeline(CsvOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                profile: None,
                output: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
            },
        });
        let csv_html_flag_disable = create_dummy_stored_static(Some(disable_csv_action));
        assert!(!htmlreport::check_html_flag(&csv_html_flag_disable.config));
    }

    #[test]
    fn test_with_config_check_html_flag_jsontimeline() {
        let enable_json_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                profile: None,
                output: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: Some(Path::new("./dummy").to_path_buf()),
                no_summary: false,
            },
            jsonl_timeline: false,
        });
        let json_html_flag_enable = create_dummy_stored_static(Some(enable_json_action));
        assert!(htmlreport::check_html_flag(&json_html_flag_enable.config));

        let disable_json_action = Action::JsonTimeline(JSONOutputOption {
            output_options: OutputOption {
                input_args: InputOption {
                    directory: None,
                    filepath: None,
                    live_analysis: false,
                    evtx_file_ext: None,
                    thread_number: None,
                    quiet_errors: false,
                    config: Path::new("./rules/config").to_path_buf(),
                    verbose: false,
                },
                profile: None,
                output: None,
                enable_deprecated_rules: false,
                exclude_status: None,
                min_level: "informational".to_string(),
                enable_noisy_rules: false,
                end_timeline: None,
                start_timeline: None,
                eid_filter: false,
                european_time: false,
                iso_8601: false,
                rfc_2822: false,
                rfc_3339: false,
                us_military_time: false,
                us_time: false,
                utc: false,
                visualize_timeline: false,
                rules: Path::new("./rules").to_path_buf(),
                html_report: None,
                no_summary: false,
            },
            jsonl_timeline: false,
        });
        let json_html_flag_disable = create_dummy_stored_static(Some(disable_json_action));
        assert!(!htmlreport::check_html_flag(&json_html_flag_disable.config));
    }

    #[test]
    fn test_create_html_file() {
        let mut html_reporter = HtmlReporter::default();
        let mut general_data = Nested::<String>::new();
        general_data.extend(vec![
            "- Analyzed event files: 581".to_string(),
            "- Total file size: 148.5 MB".to_string(),
            "- Excluded rules: 12".to_string(),
            "- Noisy rules: 5 (Disabled)".to_string(),
            "- Experimental rules: 1935 (65.97%)".to_string(),
            "- Stable rules: 215 (7.33%)".to_string(),
            "- Test rules: 783 (26.70%)".to_string(),
            "- Hayabusa rules: 138".to_string(),
            "- Sigma rules: 2795".to_string(),
            "- Total enabled detection rules: 2933".to_string(),
            "- Elapsed time: 00:00:29.035".to_string(),
            "".to_string(),
        ]);
        html_reporter.section_order.push("No Exist Section");
        html_reporter.md_datas.insert(
            "General Overview {#general_overview}".to_string(),
            general_data.to_owned(),
        );
        let gen_data = general_data.iter().collect::<Vec<&str>>();
        let general_overview_str = format!(
            "<ul>\n<li>{}</li>\n</ul>",
            gen_data[..general_data.len() - 1]
                .join("</li>\n<li>")
                .replace("- ", "")
        );
        let expect_str = format!(
            "<h2 id=\"general_overview\">General Overview</h2>\n{}\n<h2 id=\"results_summary\">Results Summary</h2>\n<p>not found data.</p>\n",
            general_overview_str
        );
        htmlreport::create_html_file(
            html_reporter.create_html(),
            "./test-html/test_create_html_file.html",
        );

        let header = r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><link rel="stylesheet" type="text/css" href="./config/html_report/hayabusa_report.css"><link rel="icon" type="image/png" href="./config/html_report/favicon.png"></head><body><section><img id="logo" src="./config/html_report/logo.png">"#;
        let footer = "</section></body></html>\n";
        let expect = format!("{}{}{}", header, expect_str, footer);
        assert_eq!(
            read_to_string("./test-html/test_create_html_file.html").unwrap(),
            expect
        );
        assert!(remove_dir_all("./test-html").is_ok());
    }

    #[test]
    fn test_add_md_data() {
        let mut html_reporter = HtmlReporter::default();
        let mut general_data = Nested::<String>::new();
        general_data.extend(vec![
            "- Analyzed event files: 581".to_string(),
            "- Total file size: 148.5 MB".to_string(),
            "- Excluded rules: 12".to_string(),
            "- Noisy rules: 5 (Disabled)".to_string(),
            "- Experimental rules: 1935 (65.97%)".to_string(),
            "- Stable rules: 215 (7.33%)".to_string(),
            "- Test rules: 783 (26.70%)".to_string(),
            "- Hayabusa rules: 138".to_string(),
            "- Sigma rules: 2795".to_string(),
            "- Total enabled detection rules: 2933".to_string(),
            "- Elapsed time: 00:00:29.035".to_string(),
            "".to_string(),
        ]);
        html_reporter.section_order.push("No Exist Section");
        let expect_key = "AddTest {#add_test}";
        htmlreport::add_md_data(expect_key, general_data.clone());
        let actual_html_reporter = HTML_REPORTER.read().unwrap().clone();
        let expect_general_data: Vec<&str> = general_data.iter().collect();
        for (k, v) in actual_html_reporter.md_datas.iter() {
            if k == expect_key {
                assert_eq!(v.iter().collect::<Vec<&str>>(), expect_general_data);
            } else {
                assert_eq!(v.len(), 0);
            }
        }
    }
}
