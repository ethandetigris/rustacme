use chrono::{TimeZone, Utc};
use encoding_rs::GBK;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use log::{error, info, warn};
use md5::{Digest, Md5};
use rand::rngs::OsRng;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA512};
use reqwest::Client as HttpClient;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use x509_parser::pem::parse_x509_pem;

const ACCT: &str = "/certs/account.json";
const DEFAULT_ACME: &str = "https://acme-v02.api.letsencrypt.org/directory";
const API: &str = "https://api.west.cn/API/v2/domain/dns/";
const DEFAULT_DNS_WAIT: u64 = 90;
const TIMEOUT: Duration = Duration::from_secs(30);
const CERT_KEY_BITS: usize = 4096;
const CERT_CSR_SIGNATURE: &str = "RSA-4096/PKCS#1-SHA512";

/// Two-level TLD suffixes that require 3-part base domain extraction.
const TWO_LVL: &[&[&str]] = &[
    &["com", "cn"], &["net", "cn"], &["org", "cn"], &["gov", "cn"], &["edu", "cn"], &["ac", "cn"],
    &["com", "hk"], &["net", "hk"], &["org", "hk"], &["gov", "hk"], &["edu", "hk"],
];

/// Returns (zone, hostname_prefix) for a DNS-01 challenge.
///
/// zone:      registered domain for West.cn DNS API
/// prefix:    subdomain part to prepend to "_acme-challenge" (empty for apex)
///
/// Examples:
///   "mail.tigrisla.com"  → ("tigrisla.com", "mail")
///   "tigrisla.com"       → ("tigrisla.com", "")
///   "*.tigrisla.com"     → ("tigrisla.com", "")
///   "cdma.tigrisla.cn"   → ("tigrisla.cn", "cdma")
///   "tigrisla.com.cn"    → ("tigrisla.com.cn", "")
fn zone_info(fqdn: &str) -> (String, String) {
    let fqdn = fqdn.strip_prefix("*.").unwrap_or(fqdn);
    let parts: Vec<&str> = fqdn.split('.').collect();
    let n = parts.len();
    if n < 2 {
        return (fqdn.to_string(), String::new());
    }
    let is_2 = n >= 3 && TWO_LVL.iter().any(|t| parts[n - 2] == t[0] && parts[n - 1] == t[1]);
    let base_count = if is_2 { 3 } else { 2 };
    if n <= base_count {
        (fqdn.to_string(), String::new())
    } else {
        let zone = parts[n - base_count..].join(".");
        let sub = parts[..n - base_count].join(".");
        (zone, sub)
    }
}

struct Cert {
    domains: Vec<String>,
    apikey: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct TxtRecord {
    zone: String,
    hostname: String,
    value: String,
}

impl Cert {
    fn load(i: usize) -> Option<Self> {
        let domains: Vec<String> = env::var(format!("CERT_{}_DOMAINS", i))
            .ok()?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if domains.is_empty() {
            return None;
        }
        let key = env::var(format!("CERT_{}_KEY", i)).ok()?;
        Some(Cert { apikey: md5_gbk(&key), domains })
    }

    fn cert_dir(&self) -> String {
        let name = self.domains[0].strip_prefix("*.").unwrap_or(&self.domains[0]);
        format!("/certs/{}", name)
    }
}

fn md5_gbk(s: &str) -> String {
    let (b, _, _) = GBK.encode(s);
    format!("{:x}", Md5::digest(&b))
}

fn secure(path: &str, data: &str) -> std::io::Result<()> {
    let tmp = format!("{}.tmp", path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    let mut p = file.metadata()?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(&tmp, p)?;
    fs::rename(tmp, path)
}

fn valid(d: &str) -> bool {
    let d = d.strip_prefix("*.").unwrap_or(d);
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn needs_renewal(
    path: &str,
    thresh: i64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if !Path::new(path).exists() {
        return Ok(true);
    }
    let pem = fs::read_to_string(path)?;
    let (_, obj) = parse_x509_pem(pem.as_bytes())?;
    let x509 = obj.parse_x509()?;
    let dt = Utc
        .timestamp_opt(x509.tbs_certificate.validity.not_after.timestamp(), 0)
        .single()
        .ok_or("invalid not_after")?;
    Ok((dt - Utc::now()).num_days() <= thresh)
}

macro_rules! dns {
    ($act:expr, $zone:expr $(, $k:expr => $v:expr)*) => {{
        let mut m = HashMap::<&str, &str>::with_capacity(6);
        m.insert("act", $act);
        m.insert("domain", $zone);
        $( m.insert($k, $v); )*
        m
    }};
}

async fn api(
    cli: &HttpClient,
    key: &str,
    p: HashMap<&str, &str>,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let resp = cli
        .post(API)
        .timeout(TIMEOUT)
        .query(&[("apidomainkey", key)])
        .form(&p)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let (text, _, _) = GBK.decode(&resp);
    let json: Value = serde_json::from_str(&text)?;
    ensure_api_success(&json)?;
    Ok(json)
}

fn ensure_api_success(json: &Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for key in ["code", "status", "result"] {
        if let Some(value) = json.get(key) {
            if success_value(value) {
                return Ok(());
            }
            return Err(format!("west.cn API returned failure: {}", compact_json(json)).into());
        }
    }

    if let Some(value) = json.get("success") {
        return if value.as_bool() == Some(true) {
            Ok(())
        } else {
            Err(format!("west.cn API returned failure: {}", compact_json(json)).into())
        };
    }

    if json.get("error").is_some() || json.get("errors").is_some() {
        return Err(format!("west.cn API returned error: {}", compact_json(json)).into());
    }

    Ok(())
}

fn success_value(value: &Value) -> bool {
    match value {
        Value::Bool(v) => *v,
        Value::Number(v) => v
            .as_i64()
            .map(|n| matches!(n, 0 | 1 | 200))
            .unwrap_or(false),
        Value::String(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "1" | "ok" | "true" | "success" | "successful" | "200"
        ),
        _ => false,
    }
}

fn compact_json(json: &Value) -> String {
    let mut text = json.to_string();
    if text.len() > 600 {
        text.truncate(600);
        text.push_str("...");
    }
    text
}

async fn add_txt(
    cli: &HttpClient,
    key: &str,
    zone: &str,
    hostname: &str,
    val: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    api(
        cli,
        key,
        dns!(
            "dnsrec.add", zone,
            "record_type" => "TXT",
            "hostname" => hostname,
            "record_value" => val,
            "record_ttl" => "600"
        ),
    )
    .await?;
    info!("TXT added zone={} host={}", zone, hostname);
    Ok(())
}

async fn cleanup(
    cli: &HttpClient,
    key: &str,
    record: &TxtRecord,
) {
    let json = match api(cli, key, dns!("dnsrec.list", &record.zone, "limit" => "100")).await {
        Ok(j) => j,
        Err(e) => {
            warn!("list {}: {}", record.zone, e);
            return;
        }
    };
    for item in json["body"]["items"].as_array().iter().flat_map(|a| a.iter()) {
        if item["hostname"].as_str() != Some(record.hostname.as_str()) {
            continue;
        }
        if item["record_type"].as_str() != Some("TXT") {
            continue;
        }
        if !record_value_matches(item, &record.value) {
            continue;
        }
        let id = item["record_id"]
            .as_i64()
            .map(|n| n.to_string())
            .or_else(|| item["record_id"].as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if id.is_empty() {
            continue;
        }
        match api(
            cli,
            key,
            dns!("dnsrec.remove", &record.zone, "record_id" => &id),
        )
        .await
        {
            Ok(_) => info!("TXT removed {} {}", record.zone, id),
            Err(e) => warn!("remove {} {}: {}", record.zone, id, e),
        }
    }
}

fn record_value(item: &Value) -> Option<&str> {
    ["record_value", "value", "record"]
        .iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
}

fn record_value_matches(item: &Value, expected: &str) -> bool {
    record_value(item)
        .map(|value| value == expected || value.trim_matches('"') == expected)
        .unwrap_or(false)
}

fn acme_http_client() -> Box<dyn instant_acme::HttpClient> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    Box::new(hyper::Client::builder().build(https))
}

fn certificate_request(
    domains: &[String],
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error + Send + Sync>> {
    let common_name = domains.first().ok_or("certificate must contain at least one domain")?;
    let private_key = RsaPrivateKey::new(&mut OsRng, CERT_KEY_BITS)?;
    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let key_pair = KeyPair::from_pem_and_sign_algo(&private_key_pem, &PKCS_RSA_SHA512)?;

    let mut params = CertificateParams::new(domains.to_vec());
    params.alg = &PKCS_RSA_SHA512;
    params.key_pair = Some(key_pair);
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name.clone());
        dn
    };

    let certificate = Certificate::from_params(params)?;
    Ok((certificate.serialize_request_der()?, private_key_pem))
}

async fn account(
    email: &str,
    acme_directory: &str,
) -> Result<Account, Box<dyn std::error::Error + Send + Sync>> {
    if Path::new(ACCT).exists() {
        let c: AccountCredentials = serde_json::from_str(&fs::read_to_string(ACCT)?)?;
        Ok(Account::from_credentials_and_http(c, acme_http_client()).await?)
    } else {
        let contact = format!("mailto:{}", email);
        let refs = [contact.as_str()];
        let (acct, creds) = Account::create_with_http(
            &NewAccount {
                contact: &refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme_directory,
            None,
            acme_http_client(),
        )
        .await?;
        secure(ACCT, &serde_json::to_string(&creds)?)?;
        info!("ACME account created");
        Ok(acct)
    }
}

async fn issue(
    cli: &HttpClient,
    cert: &Cert,
    email: &str,
    acme_directory: &str,
    dns_wait: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("[{}] ACME: {} domains", cert.cert_dir(), cert.domains.len());
    let dir = cert.cert_dir();
    fs::create_dir_all(&dir)?;
    let chain = format!("{}/fullchain.pem", dir);
    let key = format!("{}/privkey.pem", dir);

    let mut created: Vec<TxtRecord> = Vec::new();
    let result = issue_with_cleanup(cli, cert, email, acme_directory, dns_wait, &mut created).await;

    for record in &created {
        cleanup(cli, &cert.apikey, record).await;
    }

    if result.is_ok() {
        info!("[{}] saved", cert.cert_dir());
    }

    result?;
    secure_file_mode(&chain)?;
    secure_file_mode(&key)?;
    Ok(())
}

async fn issue_with_cleanup(
    cli: &HttpClient,
    cert: &Cert,
    email: &str,
    acme_directory: &str,
    dns_wait: u64,
    created: &mut Vec<TxtRecord>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = cert.cert_dir();
    let chain = format!("{}/fullchain.pem", dir);
    let key = format!("{}/privkey.pem", dir);

    let acct = account(email, acme_directory).await?;
    let ids: Vec<Identifier> = cert
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = acct.new_order(&NewOrder { identifiers: &ids }).await?;
    let auths = order.authorizations().await?;

    for auth in &auths {
        let domain = match &auth.identifier {
            Identifier::Dns(d) => d.as_str(),
        };
        let (zone, prefix) = zone_info(domain);
        let hostname = if prefix.is_empty() {
            "_acme-challenge".to_string()
        } else {
            format!("_acme-challenge.{}", prefix)
        };
        let chal = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or("no DNS-01")?;
        add_txt(
            cli,
            &cert.apikey,
            &zone,
            &hostname,
            &order.key_authorization(chal).dns_value(),
        )
        .await?;
        created.push(TxtRecord {
            zone,
            hostname,
            value: order.key_authorization(chal).dns_value(),
        });
    }

    let unique_created: HashSet<TxtRecord> = created.iter().cloned().collect();
    created.clear();
    created.extend(unique_created);

    info!("[{}] DNS wait {}s", cert.cert_dir(), dns_wait);
    tokio::time::sleep(Duration::from_secs(dns_wait)).await;

    for auth in &auths {
        if let Some(c) = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
        {
            order.set_challenge_ready(&c.url).await?;
        }
    }

    for _ in 0..60 {
        order.refresh().await?;
        match order.state().status {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid => return Err("order invalid".into()),
            _ => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }

    let (csr_der, privkey) = certificate_request(&cert.domains)?;
    info!("[{}] CSR uses {}", cert.cert_dir(), CERT_CSR_SIGNATURE);
    order.finalize(&csr_der).await?;

    let pem = loop {
        if let Some(c) = order.certificate().await? {
            break c;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    };

    secure(&chain, &pem)?;
    secure(&key, &privkey)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    fs::create_dir_all("/certs")?;
    fs::set_permissions("/certs", fs::Permissions::from_mode(0o700))?;

    let mut certs: Vec<Cert> = Vec::new();
    for i in 1..100 {
        match Cert::load(i) {
            Some(c) => {
                for d in &c.domains {
                    if !valid(d) {
                        return Err(format!("invalid domain: {}", d).into());
                    }
                }
                certs.push(c);
            }
            None => break,
        }
    }
    if certs.is_empty() {
        return Err("no CERT_1_DOMAINS in environment".into());
    }

    let email = env::var("ACME_EMAIL")
        .map_err(|_| "ACME_EMAIL is required and must be registered with Let's Encrypt")?;
    if !email.contains('@') {
        return Err("ACME_EMAIL must be a valid email address".into());
    }
    let thresh: i64 = env::var("RENEW_BEFORE_DAYS")
        .unwrap_or_default()
        .parse()
        .unwrap_or(30);
    let interval: u64 = env::var("CHECK_INTERVAL_SECS")
        .unwrap_or_default()
        .parse()
        .unwrap_or(43200);
    let dns_wait: u64 = env::var("DNS_WAIT_SECS")
        .unwrap_or_default()
        .parse()
        .unwrap_or(DEFAULT_DNS_WAIT);
    let acme_directory = env::var("ACME_DIRECTORY_URL").unwrap_or_else(|_| DEFAULT_ACME.to_string());

    info!("{} cert(s), check every {}s", certs.len(), interval);
    let cli = HttpClient::builder()
        .timeout(TIMEOUT)
        .https_only(true)
        .build()
        .unwrap();

    loop {
        for cert in &certs {
            let dir = cert.cert_dir();
            let chain = format!("{}/fullchain.pem", dir);
            info!("=== [{}] ===", dir);
            match needs_renewal(&chain, thresh) {
                Ok(true) => {
                    if let Err(e) = issue(&cli, cert, &email, &acme_directory, dns_wait).await {
                        error!("[{}] {}", dir, e);
                    }
                }
                Ok(false) => info!("[{}] cert ok", dir),
                Err(e) => error!("[{}] {}", dir, e),
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

fn secure_file_mode(path: &str) -> std::io::Result<()> {
    let mut p = fs::metadata(path)?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(path, p)
}
