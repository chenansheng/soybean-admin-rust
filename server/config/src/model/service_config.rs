use std::collections::HashMap;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct ServiceConfig {
    pub service_map: HashMap<String, Box<T>>,
}