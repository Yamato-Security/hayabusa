use itertools::Itertools;
use nested::Nested;

use crate::detections::message::{COMPUTER_MITRE_ATTCK_MAP, COMPUTER_MITRE_ATTCK_UNIQUE_KEYS};

use super::html_escape_value;

/// Appends to `html_output_stock` a Markdown table of computer names and the MITRE ATT&CK
/// tactics detected on them (with unique and total counts), for the HTML report.
pub(crate) fn _output_html_computer_by_mitre_attck(html_output_stock: &mut Nested<String>) {
    html_output_stock.push("### MITRE ATT&CK Tactics:{#computers_with_mitre_attck_detections}");
    if COMPUTER_MITRE_ATTCK_MAP.is_empty() {
        html_output_stock.push("- No computers were detected with MITRE ATT&CK Tactics.<br>Make sure you run Hayabusa with a profile that includes %MitreTactics% in order to get this info.<br>");
    }
    for (idx, sorted_output_map) in COMPUTER_MITRE_ATTCK_MAP
        .iter()
        .sorted_by(|a, b| {
            Ord::cmp(
                &format!("{}-{}", &b.value()[b.value().len() - 1].0, b.key()),
                &format!("{}-{}", &a.value()[a.value().len() - 1].0, a.key()),
            )
        })
        .enumerate()
    {
        if idx == 0 {
            html_output_stock.push("|Computer| MITRE ATT&CK Tactics|");
            html_output_stock.push("|---|---|");
        }
        html_output_stock.push(format!(
            "|{}|{}|",
            html_escape_value(sorted_output_map.key()),
            sorted_output_map
                .value()
                .iter()
                .map(|(tactic, unique, total)| format!("{} ({} &#124; {})", tactic, unique, total))
                .join("<br>")
        ));
    }
    // Scope the accumulated counts to this single report: clear both accumulators after the table is
    // emitted so a subsequent report generated in the same process (e.g. across tests) starts clean
    // instead of leaking keys and undercounting `unique`.
    COMPUTER_MITRE_ATTCK_MAP.clear();
    COMPUTER_MITRE_ATTCK_UNIQUE_KEYS.clear();
}
