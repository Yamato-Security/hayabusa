//! The `cidr` modifier.

use std::net::IpAddr;
use std::str::FromStr;

use cidr_utils::cidr::IpCidr;
use cidr_utils::cidr::errors::NetworkParseError;

/// `|cidr`: true when the event value parses as an IP address inside the rule's CIDR range.
pub(super) fn is_match(
    ip_result: &Result<IpCidr, NetworkParseError>,
    event_value: Option<&String>,
) -> bool {
    match ip_result {
        Ok(matcher_ip) => {
            let val = String::default();
            let event_value_str = event_value.unwrap_or(&val);
            match IpAddr::from_str(event_value_str) {
                Ok(target_ip) => matcher_ip.contains(&target_ip),
                Err(_) => false, // The event value is not an IP address.
            }
        }
        Err(_) => false, // The rule's cidr value is not a valid CIDR range.
    }
}
