use cidr_utils::cidr::IpCidr;
use compact_str::CompactString;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use maxminddb::{MaxMindDbError, Reader, geoip2};
use std::io::Error;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::{net::IpAddr, str::FromStr};

lazy_static! {
    pub static ref IP_MAP: Mutex<HashMap<IpAddr, CompactString>> = Mutex::new(HashMap::new());
}
pub struct GeoIPSearch {
    pub asn_reader: Reader<Vec<u8>>,
    pub country_reader: Reader<Vec<u8>>,
    pub city_reader: Reader<Vec<u8>>,
}

impl GeoIPSearch {
    pub fn new(path: &Path, asn_country_city_filename: Vec<&str>) -> GeoIPSearch {
        GeoIPSearch {
            asn_reader: maxminddb::Reader::open_readfile(path.join(asn_country_city_filename[0]))
                .unwrap(),
            country_reader: maxminddb::Reader::open_readfile(
                path.join(asn_country_city_filename[1]),
            )
            .unwrap(),
            city_reader: maxminddb::Reader::open_readfile(path.join(asn_country_city_filename[2]))
                .unwrap(),
        }
    }

    /// check existence files in specified path by GeoIP option.
    pub fn check_exist_geo_ip_files(
        geo_ip_dir_path: &Option<PathBuf>,
        check_files: Vec<&str>,
    ) -> Result<Option<PathBuf>, String> {
        if let Some(path) = geo_ip_dir_path {
            let mut combined_err = vec![];
            for file_name in check_files {
                let mmdb_path = path.join(file_name);
                if !mmdb_path.exists() {
                    combined_err.push(format!(
                        "Cannot find the appropriate MaxMind GeoIP .mmdb database files. filepath: {mmdb_path:?}"
                    ));
                }
            }
            if combined_err.is_empty() {
                Ok(geo_ip_dir_path.to_owned())
            } else {
                Err(combined_err.join("\n"))
            }
        } else {
            Ok(None)
        }
    }

    /// check target_ip in private IP range.
    fn check_in_private_ip_range(&self, target_ip: &IpAddr) -> bool {
        let private_cidr = if target_ip.is_ipv4() {
            vec![
                IpCidr::from_str("10/8").unwrap(),
                IpCidr::from_str("172.16/12").unwrap(),
                IpCidr::from_str("192.168/16").unwrap(),
            ]
        } else {
            vec![
                IpCidr::from_str("::/128").unwrap(),    // IPv6 Unspecified
                IpCidr::from_str("2000::/3").unwrap(),  // IPv6 Global Unicast
                IpCidr::from_str("FE80::/10").unwrap(), // IPv6 Link Local Unicast
                IpCidr::from_str("FC00::/7").unwrap(),  // IPv6 Unique Local Address
                IpCidr::from_str("FD00::/8").unwrap(),  // IPv6 Unique Local Address
                IpCidr::from_str("FF00::/8").unwrap(),  // IPv6 Multicast Address
            ]
        };
        for cidr in private_cidr {
            if cidr.contains(target_ip) {
                return true;
            }
        }
        false
    }

    /// convert IP address string to geo data
    pub fn convert_ip_to_geo(&self, target_ip: &str) -> Result<String, MaxMindDbError> {
        if target_ip == "ローカル" || target_ip == "LOCAL" {
            return Ok("Local🦅-🦅-".to_string());
        }
        let target = if target_ip.starts_with("::ffff:") {
            target_ip.replace("::ffff:", "")
        } else {
            target_ip.to_string()
        };
        let addr;
        if let Ok(conv) = IpAddr::from_str(&target) {
            addr = conv;
        } else {
            let msg = format!("Failed Convert IP Address. input: {target_ip}");
            return Err(MaxMindDbError::Io(Error::new(
                std::io::ErrorKind::Other,
                msg,
            )));
        };

        if addr.is_loopback() || target_ip == "0.0.0.0" {
            return Ok("Local🦅-🦅-".to_string());
        }

        if self.check_in_private_ip_range(&addr) {
            return Ok("Private🦅-🦅-".to_string());
        }

        // If the IP address is the same, the result obtained is the same, so the lookup process is omitted by obtaining the result of a hit from the cache.
        if let Some(cached_data) = IP_MAP.lock().unwrap().get(&addr) {
            return Ok(cached_data.to_string());
        }
        let asn_search: Result<Option<geoip2::Asn>, MaxMindDbError> = self.asn_reader.lookup(addr);
        let country_search: Result<Option<geoip2::Country>, MaxMindDbError> =
            self.country_reader.lookup(addr);
        let city_search: Result<Option<geoip2::City>, MaxMindDbError> =
            self.city_reader.lookup(addr);

        let output_asn = if let Ok(Some(asn)) = asn_search {
            asn.autonomous_system_organization.unwrap_or("-")
        } else {
            "-"
        };

        let output_country = if let Ok(Some(country)) = country_search {
            let mut ret = "-";
            if let Some(country) = country.country {
                if let Some(name_tree) = country.names {
                    ret = name_tree.get("en").unwrap_or(&"-")
                }
            }
            ret
        } else {
            "-"
        };

        let output_city = if let Ok(Some(city)) = city_search {
            let mut ret = "n/-";
            if let Some(city) = city.city {
                if let Some(name_tree) = city.names {
                    ret = name_tree.get("en").unwrap_or(&"-")
                }
            }
            ret
        } else {
            "-"
        };

        let geo_data = format!("{output_asn}🦅{output_country}🦅{output_city}");
        IP_MAP
            .lock()
            .unwrap()
            .insert(addr, CompactString::from(&geo_data));
        Ok(geo_data)
    }
}

#[cfg(test)]
mod tests {
    use super::GeoIPSearch;
    use crate::options::geoip_search::IP_MAP;
    use compact_str::CompactString;
    use std::{net::IpAddr, path::Path, str::FromStr};

    #[test]
    fn test_no_specified_geo_ip_option() {
        // Test files from https://github.com/maxmind/MaxMind-DB/tree/a8ae5b4ac0aa730e2783f708cdaa208aca20e9ec/test-data
        assert!(
            GeoIPSearch::check_exist_geo_ip_files(
                &None,
                vec![
                    "GeoLite2-ASN-Test.mmdb",
                    "GeoLite2-Country-Test.mmdb",
                    "GeoLite2-City-Test.mmdb",
                ]
            )
            .unwrap()
            .is_none()
        )
    }

    #[test]
    fn test_not_exist_files() {
        let target_files = vec![
            "GeoLite2-NoExist1.mmdb",
            "GeoLite2-NoExist2.mmdb",
            "GeoLite2-NoExist3.mmdb",
        ];
        let test_path = Path::new("test_files/mmdb").to_path_buf();
        let mut expect_err_msg = vec![];
        for file_path in &target_files {
            expect_err_msg.push(format!(
                "Cannot find the appropriate MaxMind GeoIP .mmdb database files. filepath: {:?}",
                test_path.join(file_path)
            ));
        }
        assert_eq!(
            GeoIPSearch::check_exist_geo_ip_files(&Some(test_path), target_files),
            Err(expect_err_msg.join("\n"))
        )
    }

    #[test]
    fn test_convert_ip_to_geo() {
        let test_path = Path::new("test_files/mmdb").to_path_buf();

        // Test files from https://github.com/maxmind/MaxMind-DB/tree/a8ae5b4ac0aa730e2783f708cdaa208aca20e9ec/test-data
        let target_files = vec![
            "GeoLite2-ASN.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        assert_eq!(
            GeoIPSearch::check_exist_geo_ip_files(&Some(test_path.clone()), target_files.clone()),
            Ok(Some(test_path.clone()))
        );
        IP_MAP.lock().unwrap().clear();
        let geo_ip = GeoIPSearch::new(&test_path, target_files);
        let expect = "-🦅United Kingdom🦅Boxford";
        let actual = geo_ip.convert_ip_to_geo("2.125.160.216");
        assert!(actual.is_ok());
        assert_eq!(expect, actual.unwrap());
    }

    #[test]
    fn test_already_convert_ip_to_geo() {
        let test_path = Path::new("test_files/mmdb").to_path_buf();

        // Test files from https://github.com/maxmind/MaxMind-DB/tree/a8ae5b4ac0aa730e2783f708cdaa208aca20e9ec/test-data
        // GeoLite2-ASN.mmdb -> GeoLite2.ASN-Test.mmdb
        // GeoLite2-Country.mmdb -> GeoLite2.Country-Test.mmdb
        // GeoLite2-City.mmdb -> GeoLite2.City-Test.mmdb
        let target_files = vec![
            "GeoLite2-ASN.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        assert_eq!(
            GeoIPSearch::check_exist_geo_ip_files(&Some(test_path.clone()), target_files.clone()),
            Ok(Some(test_path.clone()))
        );
        let geo_ip = GeoIPSearch::new(&test_path, target_files);
        IP_MAP.lock().unwrap().insert(
            IpAddr::from_str("2.125.160.216").unwrap(),
            "this is dummy".into(),
        );
        let actual = geo_ip.convert_ip_to_geo("2.125.160.216");
        assert!(actual.is_ok());
        assert_eq!(CompactString::from("this is dummy"), actual.unwrap());
    }

    #[test]
    fn test_check_in_private_range_v4() {
        let test_path = Path::new("test_files/mmdb").to_path_buf();

        // Test files from https://github.com/maxmind/MaxMind-DB/tree/a8ae5b4ac0aa730e2783f708cdaa208aca20e9ec/test-data
        let target_files = vec![
            "GeoLite2-ASN.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        assert_eq!(
            GeoIPSearch::check_exist_geo_ip_files(&Some(test_path.clone()), target_files.clone()),
            Ok(Some(test_path.clone()))
        );
        IP_MAP.lock().unwrap().clear();
        let geo_ip = GeoIPSearch::new(&test_path, target_files);
        let loopback = geo_ip.convert_ip_to_geo("127.0.0.1");
        assert!(loopback.is_ok());
        assert_eq!("Local🦅-🦅-", loopback.unwrap());
        let actual_class_a = geo_ip.convert_ip_to_geo("10.1.1.128");
        assert!(actual_class_a.is_ok());
        assert_eq!("Private🦅-🦅-", actual_class_a.unwrap());
        let actual_class_b = geo_ip.convert_ip_to_geo("172.19.128.128");
        assert!(actual_class_b.is_ok());
        assert_eq!("Private🦅-🦅-", actual_class_b.unwrap());
        let actual_class_c = geo_ip.convert_ip_to_geo("192.168.128.128");
        assert!(actual_class_c.is_ok());
        assert_eq!("Private🦅-🦅-", actual_class_c.unwrap());
    }

    #[test]
    fn test_check_in_private_range_v6() {
        let test_path = Path::new("test_files/mmdb").to_path_buf();

        // Test files from https://github.com/maxmind/MaxMind-DB/tree/a8ae5b4ac0aa730e2783f708cdaa208aca20e9ec/test-data
        let target_files = vec![
            "GeoLite2-ASN.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        assert_eq!(
            GeoIPSearch::check_exist_geo_ip_files(&Some(test_path.clone()), target_files.clone()),
            Ok(Some(test_path.clone()))
        );
        IP_MAP.lock().unwrap().clear();
        let geo_ip = GeoIPSearch::new(&test_path, target_files);
        let loopback = geo_ip.convert_ip_to_geo("::1");
        assert!(loopback.is_ok());
        assert_eq!("Local🦅-🦅-", loopback.unwrap());
        let link_local = geo_ip.convert_ip_to_geo("fe80::123:33ef:fe11:1");
        assert!(link_local.is_ok());
        assert_eq!("Private🦅-🦅-", link_local.unwrap());
        let global_unicast = geo_ip.convert_ip_to_geo("2001:1234:abcd:1234::1");
        assert!(global_unicast.is_ok());
        assert_eq!("Private🦅-🦅-", global_unicast.unwrap());
    }
}
