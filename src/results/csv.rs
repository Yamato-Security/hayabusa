use std::io::{self, Write};

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use hashbrown::HashSet;
use itertools::Itertools;

use crate::detections::configs::{Action, StoredStatic};
use crate::detections::message::DetectInfo;
use crate::detections::utils::{get_writable_color, write_color_buffer};
use crate::level::{_get_output_color, create_output_color_map};
use crate::options::profile::Profile;

use super::display::_get_serialized_disp_output;
use super::json::output_json_str;
use super::summary::calc_statistic_info;
use super::{OutputWriter, ResultOutputState, ResultWriter, handle_output_error};

/// Writes one batch of detections and folds it into the summary statistics. This is the
/// streaming output path used in low-memory mode, where results are emitted per batch instead
/// of being collected, sorted, and written all at once by `output_results`. Exits the process
/// if writing fails.
pub fn emit_csv(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    stored_static: &StoredStatic,
    output_writer: &mut OutputWriter,
    result_state: &mut ResultOutputState,
) {
    if detect_infos.is_empty() {
        return;
    }

    let result = emit_csv_inner(
        detect_infos,
        duplicate_indices,
        stored_static,
        output_writer,
        result_state,
    );
    if result.is_err() {
        handle_output_error(Box::new(result.err().unwrap()));
    }

    calc_statistic_info(detect_infos, duplicate_indices, result_state, stored_static);
}
/// Formats a raw multi-author `RuleAuthor` string for multiline/tab CSV output: split on the
/// `,` / `/` / `;` separators used in rule YAML, normalize each author's internal whitespace, and
/// join the authors with `sep` (`\r\n` for multiline, `\t` for tab-separator). Reproduces the CSV
/// file output the former `🛂🛂` marker + `output_remover` round-trip produced. (The terminal
/// display path collapses separators to spaces itself; see `_get_serialized_disp_output`.)
fn format_rule_author(raw: &str, sep: &str) -> String {
    raw.split([',', '/', ';'])
        .map(|a| a.split_whitespace().join(" "))
        .join(sep)
}

pub(crate) fn emit_csv_inner(
    detect_infos: &[DetectInfo],
    duplicate_indices: &HashSet<usize>,
    stored_static: &StoredStatic,
    output_writer: &mut OutputWriter,
    result_state: &mut ResultOutputState,
) -> io::Result<()> {
    // Field values reach here with real `\n`/`\r`/`\t` (kept by utils::remove_sp_char). For
    // single-line output the whole value is whitespace-collapsed and output_remover flattens any
    // remaining control characters to spaces; with the multiline (or tab-separator) option the
    // " ¦ " field separator becomes a line break (or tab) instead. (Multi-valued RuleAuthor values
    // are split and joined per output mode in the write loop below.) Keep the (pattern, replacement)
    // pairs in a single ordered list so the automaton's patterns and the replacement slice line up —
    // `AhoCorasick::replace_all` indexes the replacements by pattern id.
    let multiline_flag = stored_static.multiline_flag;
    let tab_separator_flag = stored_static.tab_separator_flag;
    let mut removed_replaced_pairs: Vec<(&str, &str)> = vec![("\n", " "), ("\r", " "), ("\t", " ")];
    if multiline_flag {
        removed_replaced_pairs.push((" ¦ ", "\r\n"));
    } else if tab_separator_flag {
        removed_replaced_pairs.push((" ¦ ", "\t"));
    }
    let output_remover = AhoCorasickBuilder::new()
        .match_kind(MatchKind::LeftmostLongest)
        .build(removed_replaced_pairs.iter().map(|(pattern, _)| *pattern))
        .unwrap();
    let remover_vals: Vec<&str> = removed_replaced_pairs
        .iter()
        .map(|(_, replacement)| *replacement)
        .collect();

    // Prepare the per-level color map, then determine the output format and whether duplicate
    // field data should be replaced with "DUP" (the remove-duplicate-data option).
    let color_map = create_output_color_map(stored_static.common_options.no_color);
    let (json_output_flag, jsonl_output_flag, remove_duplicate_data) =
        match &stored_static.config.action.as_ref().unwrap() {
            Action::JsonTimeline(option) => (
                true,
                option.jsonl_timeline,
                option.output_options.remove_duplicate_data,
            ),
            Action::CsvTimeline(option) => {
                (false, false, option.output_options.remove_duplicate_data)
            }
            _ => (false, false, false),
        };

    let profile = stored_static.profiles.as_ref().unwrap();
    for (i, detect_info) in detect_infos.iter().enumerate() {
        if duplicate_indices.contains(&i) {
            continue;
        }
        if output_writer.display_flag && !(json_output_flag || jsonl_output_flag) {
            // Terminal display output.
            if !result_state.has_displayed_header {
                // Print the header row only once.
                _get_serialized_disp_output(
                    &output_writer.display_writer,
                    profile,
                    true,
                    (&output_remover, &remover_vals),
                    multiline_flag || tab_separator_flag,
                    stored_static.common_options.no_color,
                    get_writable_color(
                        _get_output_color(&color_map, &detect_info.level),
                        stored_static.common_options.no_color,
                    ),
                );
                result_state.has_displayed_header = true;
            }
            _get_serialized_disp_output(
                &output_writer.display_writer,
                &detect_info.output_fields,
                false,
                (&output_remover, &remover_vals),
                multiline_flag || tab_separator_flag,
                stored_static.common_options.no_color,
                get_writable_color(
                    _get_output_color(&color_map, &detect_info.level),
                    stored_static.common_options.no_color,
                ),
            );
        } else if jsonl_output_flag {
            // JSONL output format
            let result = output_json_str(
                detect_info,
                result_state,
                jsonl_output_flag,
                stored_static.geo_ip_search.is_some(),
                remove_duplicate_data,
            );
            result_state.prev_message = result.1;
            result_state
                .prev_details_convert_map
                .clone_from(&detect_info.details_convert_map);
            if output_writer.display_flag {
                write_color_buffer(
                    &output_writer.display_writer,
                    None,
                    &format!("{{ {} }}", result.0),
                    true,
                )
                .ok();
            } else if let ResultWriter::Json { writer, first } = &mut output_writer.result_writer {
                // Separate records with a newline (the previous csv-writer delimiter), without a
                // leading or trailing one.
                if !*first {
                    writer.write_all(b"\n")?;
                }
                *first = false;
                write!(writer, "{{ {} }}", result.0)?;
            }
        } else if json_output_flag {
            // JSON output
            let result = output_json_str(
                detect_info,
                result_state,
                jsonl_output_flag,
                stored_static.geo_ip_search.is_some(),
                remove_duplicate_data,
            );
            result_state.prev_message = result.1;
            result_state
                .prev_details_convert_map
                .clone_from(&detect_info.details_convert_map);
            if output_writer.display_flag {
                write_color_buffer(
                    &output_writer.display_writer,
                    None,
                    &format!("{{\n{}\n}}", result.0),
                    true,
                )
                .ok();
            } else if let ResultWriter::Json { writer, first } = &mut output_writer.result_writer {
                // The previous csv writer joined the "{", body and "}" fields with its `\n`
                // delimiter; reproduce that layout, with records separated by a newline.
                if !*first {
                    writer.write_all(b"\n")?;
                }
                *first = false;
                write!(writer, "{{\n{}\n}}", result.0)?;
            }
        } else if let ResultWriter::Csv(csv_writer) = &mut output_writer.result_writer {
            // CSV output format
            if !result_state.has_displayed_header {
                csv_writer.write_record(detect_info.output_fields.iter().map(|x| x.0.trim()))?;
                result_state.has_displayed_header = true;
            }
            csv_writer.write_record(detect_info.output_fields.iter().map(|x| {
                match x.1 {
                    Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                        let ret = if remove_duplicate_data
                            && x.1.to_value()
                                == result_state
                                    .prev_message
                                    .get(&x.0)
                                    .unwrap_or(&Profile::Literal("-".into()))
                                    .to_value()
                        {
                            "DUP".to_string()
                        } else {
                            output_remover.replace_all(
                                &x.1.to_value().split_whitespace().join(" "),
                                &remover_vals,
                            )
                        };
                        result_state.prev_message.insert(x.0.clone(), x.1.clone());
                        ret
                    }
                    Profile::RuleAuthor(_) if multiline_flag || tab_separator_flag => {
                        // Put each author on its own line (multiline) or tab (tab-separator).
                        format_rule_author(
                            &x.1.to_value(),
                            if multiline_flag { "\r\n" } else { "\t" },
                        )
                    }
                    _ => output_remover
                        .replace_all(&x.1.to_value().split_whitespace().join(" "), &remover_vals),
                }
            }))?;
        }
    }

    if !output_writer.display_flag {
        match &mut output_writer.result_writer {
            ResultWriter::Csv(csv_writer) => csv_writer.flush()?,
            ResultWriter::Json { writer, .. } => writer.flush()?,
        }
    }
    if json_output_flag && stored_static.output_path.is_none() {
        println!()
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::format_rule_author;

    #[test]
    fn test_format_rule_author() {
        // Mixed `,` / `/` / `;` separators, per-author trim + internal-whitespace collapse.
        assert_eq!(
            format_rule_author("Test, Test2/Test3; Test4 ", "\r\n"),
            "Test\r\nTest2\r\nTest3\r\nTest4"
        );
        assert_eq!(
            format_rule_author("Test, Test2/Test3; Test4 ", "\t"),
            "Test\tTest2\tTest3\tTest4"
        );
        // Internal double-space inside an author name is collapsed to one.
        assert_eq!(format_rule_author("Florian  Roth", "\r\n"), "Florian Roth");
        // A single author (the "-" placeholder or a lone name) is unchanged.
        assert_eq!(format_rule_author("-", "\r\n"), "-");
        assert_eq!(format_rule_author("Zach Mathis", "\t"), "Zach Mathis");
    }
}
