use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use itertools::Itertools;
use nested::Nested;
use termcolor::{BufferWriter, Color};

use ::csv::{QuoteStyle, WriterBuilder};

use crate::detections::utils::{get_writable_color, write_color_buffer};
use crate::options::profile::Profile;

/// Column position within a display cell, which determines where padding spaces are added:
/// First: |<str> |
/// Last: | <str>|
/// Other: | <str> |
enum ColPos {
    First,
    Last,
    Other,
}
/// Writes one record (or, when `header` is true, the column header row) to the terminal in the
/// "·"-separated display format, coloring the timestamp/level/rule-title fields by detection
/// level and the field names/values inside the details sections individually.
pub(crate) fn _get_serialized_disp_output(
    display_writer: &BufferWriter,
    data: &[(CompactString, Profile)],
    header: bool,
    (output_remover, remover_vals): (&AhoCorasick, &[&str]),
    rule_author_multiline: bool,
    no_color: bool,
    level_color: Option<Color>,
) {
    let data_length = data.len();
    let mut ret = Nested::<String>::new();
    if header {
        for (i, entry) in data.iter().enumerate() {
            if i == 0 {
                ret.push(_format_cellpos(&entry.0, ColPos::First))
            } else if i == data_length - 1 {
                ret.push(_format_cellpos(&entry.0, ColPos::Last))
            } else {
                ret.push(_format_cellpos(&entry.0, ColPos::Other))
            }
        }
        let mut disp_serializer = WriterBuilder::new()
            .double_quote(false)
            .quote_style(QuoteStyle::Never)
            .delimiter(b'|')
            .has_headers(false)
            .from_writer(vec![]);

        disp_serializer
            .write_record(ret.iter().collect::<Vec<_>>())
            .ok();

        write_color_buffer(
            display_writer,
            get_writable_color(None, no_color),
            // The serializer above uses '|' as its delimiter; show those separators as '·' and
            // then restore any '🦅' placeholders back to '|'. Historically cell values had
            // literal '|' replaced with '🦅' before serialization so this delimiter
            // substitution would not clobber them; nothing currently inserts that placeholder
            // on this path, so the second replace is defensive/vestigial.
            &String::from_utf8(disp_serializer.into_inner().unwrap_or_default())
                .unwrap_or_default()
                .replace('|', "·")
                .replace('🦅', "|"),
            false,
        )
        .ok();
    } else {
        for (i, entry) in data.iter().enumerate() {
            let col_pos = if i == 0 {
                ColPos::First
            } else if i == data_length - 1 {
                ColPos::Last
            } else {
                ColPos::Other
            };
            // In multiline/tab mode the rule authors were formerly joined with a `🛂🛂` marker that
            // this display path's whitespace collapse reduced to single spaces. Reproduce that by
            // replacing the `,`/`/`/`;` author separators with spaces before the collapse;
            // consecutive separators (e.g. a `//` inside a URL) collapse to one space, as before.
            let value = match entry.1 {
                Profile::RuleAuthor(_) if rule_author_multiline => {
                    entry.1.to_value().replace([',', '/', ';'], " ")
                }
                _ => entry.1.to_value(),
            };
            let display_contents = _format_cellpos(
                &output_remover
                    .replace_all(&value.split_whitespace().join(" "), remover_vals)
                    .split_ascii_whitespace()
                    .join(" "),
                col_pos,
            );
            let output_color_and_contents = match entry.1 {
                Profile::Timestamp(_) | Profile::Level(_) | Profile::RuleTitle(_) => {
                    vec![vec![(
                        display_contents,
                        get_writable_color(level_color, no_color),
                    )]]
                }
                Profile::AllFieldInfo(_) | Profile::Details(_) | Profile::ExtraFieldInfo(_) => {
                    let mut output_str_char_pair = vec![];
                    for segment in display_contents.split('¦') {
                        if let Some((field, val)) = segment.split_once(':') {
                            let mut field_val_col_pair = vec![];
                            field_val_col_pair.push((
                                format!(" {}: ", field.trim()),
                                get_writable_color(Some(Color::Rgb(255, 158, 61)), no_color),
                            ));

                            field_val_col_pair.push((
                                format!(
                                    "{} ",
                                    output_remover
                                        .replace_all(
                                            &val.split_whitespace().join(" "),
                                            remover_vals,
                                        )
                                        .split_ascii_whitespace()
                                        .join(" ")
                                ),
                                get_writable_color(Some(Color::Rgb(0, 255, 255)), no_color),
                            ));
                            output_str_char_pair.push(field_val_col_pair);
                        }
                    }
                    if output_str_char_pair.is_empty() {
                        vec![vec![(display_contents, None)]]
                    } else {
                        output_str_char_pair
                    }
                }
                _ => {
                    vec![vec![(display_contents, None)]]
                }
            };

            let col_cnt = output_color_and_contents.len();
            for (field_idx, col_contents) in output_color_and_contents.iter().enumerate() {
                for (content, color) in col_contents {
                    write_color_buffer(display_writer, *color, content, false).ok();
                }
                if field_idx != col_cnt - 1 {
                    write_color_buffer(display_writer, None, "¦", false).ok();
                }
            }

            if i != data_length - 1 {
                write_color_buffer(
                    display_writer,
                    get_writable_color(Some(Color::Rgb(255, 158, 61)), no_color),
                    "·",
                    false,
                )
                .ok();
            } else {
                // Line break after the last element of one record (plus a blank separator line).
                println!();
                println!();
            }
        }
    }
}
/// Pads a cell value with spaces according to its column position in the display output.
fn _format_cellpos(colval: &str, column: ColPos) -> String {
    match column {
        ColPos::First => format!("{colval} "),
        ColPos::Last => format!(" {colval}"),
        ColPos::Other => format!(" {colval} "),
    }
}
