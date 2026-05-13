use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, RANGE, USER_AGENT};
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Serialize)]
struct ProbeResult {
    path: String,
    url: String,
    status: u16,
    bytes: u64,
}

#[derive(Serialize)]
struct Output {
    base_url: String,
    base_status: u16,
    headers: BTreeMap<String, String>,
    probes: Vec<ProbeResult>,
}

fn join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

fn headers_to_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers.iter() {
        let val = value.to_str().unwrap_or("").to_string();
        out.insert(name.as_str().to_string(), val);
    }
    out
}

fn probe_path(client: Arc<Client>, base_url: String, path: String) -> ProbeResult {
    let url = join_url(&base_url, &path);
    let mut status = 0u16;
    let mut bytes = 0u64;

    let head_request = client
        .head(&url)
        .header(USER_AGENT, HeaderValue::from_static("grudarin-probe/0.1"));

    if let Ok(response) = head_request.send() {
        status = response.status().as_u16();
        bytes = response.content_length().unwrap_or(0);
    }

    if status == 0 || status == 400 || status == 405 {
        let get_request = client
            .get(&url)
            .header(USER_AGENT, HeaderValue::from_static("grudarin-probe/0.1"))
            .header(RANGE, HeaderValue::from_static("bytes=0-0"));

        if let Ok(response) = get_request.send() {
            status = response.status().as_u16();
            bytes = response.content_length().unwrap_or(bytes);
        }
    }

    ProbeResult {
        path,
        url,
        status,
        bytes,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut base_url = String::new();
    let mut paths_csv = String::new();
    let mut timeout_ms = 6500u64;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base" => {
                base_url = args.next().unwrap_or_default();
            }
            "--paths" => {
                paths_csv = args.next().unwrap_or_default();
            }
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(6500);
            }
            _ => {}
        }
    }

    if base_url.is_empty() {
        return Err("missing --base".into());
    }

    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut base_status = 0u16;
    let mut headers = BTreeMap::new();
    if let Ok(response) = client
        .get(&base_url)
        .header(USER_AGENT, HeaderValue::from_static("grudarin-probe/0.1"))
        .send()
    {
        base_status = response.status().as_u16();
        headers = headers_to_map(response.headers());
    }

    let paths: Vec<String> = paths_csv
        .split(',')
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect();

    let shared_client = Arc::new(client);
    let mut handles = Vec::new();
    for path in paths {
        let client = Arc::clone(&shared_client);
        let base = base_url.clone();
        handles.push(thread::spawn(move || probe_path(client, base, path)));
    }

    let mut probes = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.join() {
            probes.push(result);
        }
    }

    let output = Output {
        base_url,
        base_status,
        headers,
        probes,
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
