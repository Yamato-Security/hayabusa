use std::str::FromStr;

use compact_str::CompactString;
use hashbrown::HashMap;
use indexmap::IndexMap;
use serde::ser::{Serialize, SerializeMap, Serializer};

use crate::detections::message::DetectInfo;
use crate::detections::utils;
use crate::options::profile::Profile;

use super::ResultOutputState;

/// Splits the value into its elements for the profile members that are output as JSON arrays or
/// objects: MitreTactics/MitreTags/OtherTags (": "-separated) and Details/AllFieldInfo/
/// ExtraFieldInfo (" ¦ "-separated key-value pairs). Returns an empty Vec for everything else,
/// and also for a details value that is a single element with no "key: value" structure.
fn _get_json_vec(profile: &Profile, target_data: &String) -> Vec<String> {
    match profile {
        Profile::MitreTactics(_) | Profile::MitreTags(_) | Profile::OtherTags(_) => {
            target_data.split(": ").map(|x| x.to_string()).collect()
        }
        Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
            let ret: Vec<String> = target_data.split(" ¦ ").map(|x| x.to_string()).collect();
            if target_data == &ret[0] && !utils::contains_str(target_data, ": ") {
                vec![]
            } else {
                ret
            }
        }
        _ => vec![],
    }
}
/// An ordered JSON value used to assemble one timeline record. Objects preserve key
/// insertion order (via `IndexMap`) so the output keeps the rule/field order — unlike
/// `serde_json::Map`, which sorts keys. Leaves are plain `serde_json::Value`s (scalars or
/// arrays), so `serde_json` performs all escaping and number/bool serialization.
enum JsonNode {
    Leaf(serde_json::Value),
    Object(IndexMap<String, JsonNode>),
}
impl Serialize for JsonNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JsonNode::Leaf(value) => value.serialize(serializer),
            // Serialize entries in insertion order (IndexMap iteration order), instead of the
            // key-sorted order a `serde_json::Map` would produce.
            JsonNode::Object(map) => {
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}
/// Converts a field-value string to a JSON scalar, reproducing the previous type-guessing:
/// an i64-parseable value becomes a JSON number, `true`/`false` becomes a boolean, and
/// anything else becomes a string. Any real `\n`/`\r`/`\t` in the value are escaped by
/// `serde_json` (as of #1849; previously they were `🛂n`/`🛂r`/`🛂t` placeholders rendered as the
/// visible text `\\n`/`\\r`/`\\t`).
pub(crate) fn json_scalar(value: &str) -> serde_json::Value {
    if let Ok(i) = i64::from_str(value) {
        serde_json::Value::from(i)
    } else if let Ok(b) = bool::from_str(value) {
        serde_json::Value::from(b)
    } else {
        serde_json::Value::String(close_unterminated_quote(value))
    }
}
/// A JSON string leaf (no type-guessing) — used for array elements, which are always emitted
/// as strings.
pub(crate) fn json_string(value: &str) -> serde_json::Value {
    serde_json::Value::String(close_unterminated_quote(value))
}
/// Reproduces the previous `_convert_valid_json_str` quirk where a value starting with a double
/// quote but not ending with one had a closing quote appended (kept for byte-identical JSON data).
pub(crate) fn close_unterminated_quote(value: &str) -> String {
    let mut out = value.to_string();
    if value.starts_with('"') && !value.ends_with('"') {
        out.push('"');
    }
    out
}
/// Splits each "key: value" detail entry (on the first colon), trims both sides, and groups
/// the values by key preserving first-seen key order. A key that appears more than once
/// (e.g. Data[1]/Data[2]) collects multiple values, later emitted as a JSON array.
fn group_details_raw(stock: &[CompactString]) -> IndexMap<String, Vec<String>> {
    let mut map: IndexMap<String, Vec<String>> = IndexMap::new();
    for contents in stock {
        let (key, value) = contents.split_once(':').unwrap_or_default();
        map.entry(key.trim().to_string())
            .or_default()
            .push(value.trim().to_string());
    }
    map
}
/// Serializes one record and returns the body *without* the surrounding object braces, so the
/// caller's wrapping (`{\n...\n}` for JSON, `{ ... }` for JSONL) reproduces the full object.
/// JSON uses a 4-space pretty formatter; JSONL is compact.
fn serialize_record_body(record: IndexMap<String, JsonNode>, jsonl: bool) -> String {
    if record.is_empty() {
        return String::new();
    }
    let node = JsonNode::Object(record);
    // Serializing this in-memory JsonNode (string keys, serde_json::Value leaves) to a String /
    // Vec<u8> cannot fail; `expect` surfaces a would-be bug loudly instead of silently emitting
    // empty/malformed JSON.
    if jsonl {
        let full = serde_json::to_string(&node).expect("JsonNode serialization is infallible");
        full.strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(&full)
            .to_string()
    } else {
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        node.serialize(&mut ser)
            .expect("JsonNode serialization is infallible");
        let full = String::from_utf8(buf).expect("serde_json output is valid UTF-8");
        full.strip_prefix("{\n")
            .and_then(|s| s.strip_suffix("\n}"))
            .unwrap_or(&full)
            .to_string()
    }
}
/// Builds the JSON object body for one detection. Returns the body string (without the
/// surrounding braces, which the caller adds) together with the updated previous-record field
/// map used for duplicate-data suppression on the next record.
pub fn output_json_str(
    detect_info: &DetectInfo,
    result_state: &mut ResultOutputState,
    jsonl_output_flag: bool,
    is_included_geo_ip: bool,
    remove_duplicate_flag: bool,
) -> (String, HashMap<CompactString, Profile>) {
    let mut record: IndexMap<String, JsonNode> = IndexMap::new();
    let mut target_ext_field = Vec::new();
    let ext_field_map: HashMap<CompactString, Profile> =
        HashMap::from_iter(detect_info.output_fields.to_owned());
    let mut next_prev_message = result_state.prev_message.clone();
    if remove_duplicate_flag {
        for (field_name, profile) in detect_info.output_fields.iter() {
            match profile {
                Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                    let details_key = match profile {
                        Profile::Details(_) => "Details",
                        Profile::AllFieldInfo(_) => "AllFieldInfo",
                        Profile::ExtraFieldInfo(_) => "ExtraFieldInfo",
                        _ => "",
                    };

                    let empty = vec![];
                    let now = detect_info
                        .details_convert_map
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let prev = result_state
                        .prev_details_convert_map
                        .get(format!("#{details_key}").as_str())
                        .unwrap_or(&empty);
                    let dup_flag = (!profile.to_value().is_empty()
                        && result_state
                            .prev_message
                            .get(field_name)
                            .unwrap_or(&Profile::Literal("".into()))
                            .to_value()
                            == profile.to_value())
                        || (!&now.is_empty() && !&prev.is_empty() && now == prev);
                    if dup_flag {
                        // Duplicate of the previous record: output the plain string "DUP"
                        // instead of the value (Profile::Literal emits it as-is). The previous
                        // message is intentionally NOT updated, so consecutive duplicates keep
                        // being compared against the last non-duplicate value.
                        target_ext_field.push((field_name.clone(), Profile::Literal("DUP".into())));
                    } else {
                        // Not a duplicate: remember this value for comparison with the next
                        // record.
                        next_prev_message.insert(field_name.clone(), profile.clone());
                        target_ext_field.push((field_name.clone(), profile.clone()));
                    }
                }
                _ => {
                    target_ext_field.push((field_name.clone(), profile.clone()));
                }
            }
        }
    } else {
        target_ext_field.clone_from(&detect_info.output_fields);
    }
    // GeoIP enrichment fields that are folded into the Details (and AllFieldInfo) objects of
    // the JSON output instead of being emitted as top-level keys.
    let key_add_to_details = [
        "SrcASN",
        "SrcCountry",
        "SrcCity",
        "TgtASN",
        "TgtCountry",
        "TgtCity",
    ];

    let valid_key_add_to_details: Vec<&str> = key_add_to_details
        .iter()
        .filter(|target_key| {
            let target = ext_field_map.get(&CompactString::from(**target_key));
            target.is_some() && target.unwrap().to_value() != "-"
        })
        .copied()
        .collect();
    for (key, profile) in target_ext_field.iter() {
        let val = profile.to_value();
        if !matches!(
            profile,
            Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_)
        ) && val.is_empty()
        {
            continue;
        }
        let vec_data = _get_json_vec(profile, &val.to_string());
        if (!key_add_to_details.contains(&key.as_str())
            && !matches!(
                profile,
                Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_)
            ))
            && vec_data.is_empty()
        {
            // A `Details` value of "-" is emitted as an empty object.
            if matches!(profile, Profile::Details(_)) && val == "-" {
                record.insert(key.to_string(), JsonNode::Object(IndexMap::new()));
                continue;
            }
            // Plain scalar field. `_convert_valid_json_str` used to drop everything before the
            // first ": " for multi-segment values (keeping `input[1..]`); reproduce that here.
            let tmp_val: Vec<&str> = val.split(": ").collect();
            let joined = if tmp_val.len() == 1 {
                val.to_string()
            } else {
                tmp_val[1..].join(": ")
            };
            record.insert(key.to_string(), JsonNode::Leaf(json_scalar(joined.trim())));
        } else {
            match profile {
                // GeoIP profile fields are skipped here because they are emitted inside the
                // Details/AllFieldInfo sections instead (see the key_add_to_details handling
                // below).
                Profile::SrcASN(_)
                | Profile::SrcCountry(_)
                | Profile::SrcCity(_)
                | Profile::TgtASN(_)
                | Profile::TgtCountry(_)
                | Profile::TgtCity(_) => continue,
                Profile::RecoveredRecord(data) => {
                    record.insert(
                        "RecoveredRecord".to_string(),
                        JsonNode::Leaf(json_scalar(data)),
                    );
                }
                Profile::Details(_) | Profile::AllFieldInfo(_) | Profile::ExtraFieldInfo(_) => {
                    let details_key = match profile {
                        Profile::Details(_) => "Details",
                        Profile::AllFieldInfo(_) => "AllFieldInfo",
                        Profile::ExtraFieldInfo(_) => "ExtraFieldInfo",
                        _ => "",
                    };
                    let details_target_stocks = detect_info
                        .details_convert_map
                        .get(&CompactString::from(format!("#{details_key}")));
                    if details_target_stocks.is_none() {
                        continue;
                    }
                    let details_target_stock = details_target_stocks.unwrap();
                    // Group the "key: value" detail entries into ordered (key -> values).
                    let grouped = if detect_info.agg_result.is_some() {
                        if details_target_stock.is_empty() || details_target_stock[0] == "-" {
                            record.insert(key.to_string(), JsonNode::Object(IndexMap::new()));
                            continue;
                        }
                        let split_agg_details: Vec<CompactString> = details_target_stock[0]
                            .split(" ¦ ")
                            .map(|x| x.into())
                            .collect();
                        group_details_raw(&split_agg_details)
                    } else if details_target_stock.is_empty() {
                        record.insert(key.to_string(), JsonNode::Object(IndexMap::new()));
                        continue;
                    } else {
                        group_details_raw(details_target_stock)
                    };
                    let mut details_obj: IndexMap<String, JsonNode> = IndexMap::new();
                    for (c_key, c_vals) in grouped {
                        let node = if c_vals.len() == 1 {
                            JsonNode::Leaf(json_scalar(&c_vals[0]))
                        } else {
                            // A field that repeats becomes an array of string values.
                            JsonNode::Leaf(serde_json::Value::Array(
                                c_vals.iter().map(|v| json_string(v)).collect(),
                            ))
                        };
                        details_obj.insert(c_key, node);
                    }
                    // Fold GeoIP enrichment fields into Details/AllFieldInfo (not ExtraFieldInfo).
                    if is_included_geo_ip && !matches!(profile, Profile::ExtraFieldInfo(_)) {
                        for target_key in valid_key_add_to_details.iter() {
                            let geo_val = ext_field_map
                                .get(&CompactString::from(*target_key))
                                .unwrap()
                                .to_value();
                            details_obj.insert(
                                target_key.to_string(),
                                JsonNode::Leaf(json_scalar(&geo_val)),
                            );
                        }
                    }
                    record.insert(key.to_string(), JsonNode::Object(details_obj));
                }
                Profile::MitreTags(_) | Profile::MitreTactics(_) | Profile::OtherTags(_) => {
                    let values: Vec<&str> = val.split(": ").filter(|x| x.trim() != "").collect();
                    if values.is_empty() {
                        continue;
                    }
                    // Each "value" may itself hold several `¦`-separated tags; flatten them all
                    // into one array of trimmed strings.
                    let mut elems: Vec<serde_json::Value> = vec![];
                    for tag_val in values {
                        for part in tag_val.split('¦') {
                            elems.push(json_string(part.trim()));
                        }
                    }
                    record.insert(
                        key.to_string(),
                        JsonNode::Leaf(serde_json::Value::Array(elems)),
                    );
                }
                _ => {}
            }
        }
    }
    (
        serialize_record_body(record, jsonl_output_flag),
        next_prev_message,
    )
}
