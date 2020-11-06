extern crate serde;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub severity: Option<String>,
    pub name: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Toml {
    pub rule: Rule,
}
