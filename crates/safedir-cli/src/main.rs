//! `safedir` — resolve German justice ERV recipients by SAFE-ID.
//!
//! Exit codes: `0` ok · `2` usage/config/parse · `3` not found · `4`
//! directory, extract, or network issues.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use safedir::dienststellen::DienststellenId;
use safedir::entry::SafeEntry;
use safedir::error::Error;
use safedir::resolver::SafeDirectory;
use safedir::roles::RoleValue;
use safedir::safe_id::SafeId;

/// A reference to a directory entry: either a SAFE-ID or
/// `dienststellen:<ID>`.
#[derive(Debug, Clone)]
enum Ref {
    SafeId(SafeId),
    Dienststellen(DienststellenId),
}

fn parse_ref(s: &str) -> Result<Ref, Error> {
    if let Some(rest) = s
        .strip_prefix("dienststellen:")
        .or_else(|| s.strip_prefix("Dienststellen-ID:"))
    {
        Ok(Ref::Dienststellen(rest.parse()?))
    } else {
        Ok(Ref::SafeId(s.parse()?))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "safedir",
    version,
    about = "Resolve German justice ERV recipients by SAFE-ID or Dienststellen-ID",
    after_help = "Configuration comes from flags and SAFEDIR_FILE only: no config files, no state."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate a SAFE-ID (fully offline).
    Check {
        /// The SAFE-ID.
        id: String,
    },
    /// Resolve an entry from an extract file or the VAS.
    Lookup {
        /// SAFE-ID or `dienststellen:<ID>`.
        r#ref: String,
        /// Extract file (default: $SAFEDIR_FILE or safe.json).
        #[arg(long, short = 'f')]
        file: Option<PathBuf>,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// VAS endpoint URL (SPML over SOAP); overrides extract mode.
        /// Requires a build with the `vas` feature (the default).
        #[arg(long)]
        vas_url: Option<String>,
        /// Mutual-TLS client identity PEM for the VAS.
        #[arg(long, requires = "vas_url")]
        vas_identity: Option<PathBuf>,
        /// Additional CA PEM for the VAS endpoint.
        #[arg(long, requires = "vas_url")]
        vas_ca: Option<PathBuf>,
    },
    /// Validate an extract file (schema, checksums, duplicates, certs).
    Validate {
        /// Extract file to check.
        file: PathBuf,
        /// Output JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Advisory check: may a sender role address this entry?
    Addressable {
        /// Sender role value, e.g. `egvp_beA`.
        sender_role: String,
        /// SAFE-ID or `dienststellen:<ID>`.
        r#ref: String,
        /// Extract file (default: $SAFEDIR_FILE or safe.json).
        #[arg(long, short = 'f')]
        file: Option<PathBuf>,
    },
}

/// Print a line, exiting quietly when the reader closed the pipe
/// (`… | head` must not panic).
fn out(line: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if lock
        .write_all(line.as_bytes())
        .and_then(|_| lock.write_all(b"\n"))
        .is_err()
    {
        std::process::exit(0);
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Check { id } => cmd_check(&id),
        Command::Lookup {
            r#ref,
            file,
            json,
            vas_url,
            vas_identity,
            vas_ca,
        } => cmd_lookup(&r#ref, file, json, vas_url, vas_identity, vas_ca),
        Command::Validate { file, json } => cmd_validate(&file, json),
        Command::Addressable {
            sender_role,
            r#ref,
            file,
        } => cmd_addressable(&sender_role, &r#ref, file),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("safedir: {e}");
            ExitCode::from(e.exit_code().clamp(2, 5) as u8)
        }
    }
}

fn cmd_check(id: &str) -> Result<ExitCode, Error> {
    let parsed: SafeId = id.parse()?;
    match parsed.kind() {
        safedir::safe_id::IdKind::Modern { domain, .. } => {
            out(&format!(
                "OK  {}  (modern, domain {}, directory {}, checksum valid)",
                parsed,
                domain,
                parsed
                    .directory()
                    .map_or("unknown".to_owned(), |d| d.token().to_owned())
            ));
        }
        safedir::safe_id::IdKind::Legacy { prefix } => {
            out(&format!(
                "OK  {parsed}  (legacy format, prefix {prefix}, no check digits)"
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn open_extract(
    file: Option<&std::path::Path>,
) -> Result<safedir::backends::ExtractResolver, Error> {
    let path = file
        .map(std::path::Path::to_owned)
        .or_else(|| std::env::var_os("SAFEDIR_FILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("safe.json"));
    safedir::backends::ExtractResolver::from_path(&path)
}

fn cmd_lookup(
    r#ref: &str,
    file: Option<PathBuf>,
    json: bool,
    vas_url: Option<String>,
    vas_identity: Option<PathBuf>,
    vas_ca: Option<PathBuf>,
) -> Result<ExitCode, Error> {
    let r = parse_ref(r#ref)?;

    let entries: Vec<SafeEntry> = if let Some(url) = vas_url {
        let dir = vas_resolver(url, vas_identity, vas_ca)?;
        resolve(dir.as_ref(), &r)?
    } else {
        let dir = open_extract(file.as_deref())?;
        resolve(&dir, &r)?
    };

    if entries.is_empty() {
        eprintln!("safedir: no entry for {ref}");
        return Ok(ExitCode::from(3));
    }
    if json {
        let json_out =
            serde_json::to_string_pretty(&entries).map_err(|e| Error::Extract(e.to_string()))?;
        out(&json_out);
    } else {
        for entry in &entries {
            print_entry(entry);
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "vas")]
fn vas_resolver(
    url: String,
    identity: Option<PathBuf>,
    ca: Option<PathBuf>,
) -> Result<Box<dyn SafeDirectory>, Error> {
    let mut config = safedir::vas::SpmlConfig::new(url);
    if let Some(path) = identity {
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        config = config.with_client_identity(pem);
    }
    if let Some(path) = ca {
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        config = config.with_ca(pem);
    }
    Ok(Box::new(safedir::vas::SpmlResolver::new(config)?))
}

#[cfg(not(feature = "vas"))]
fn vas_resolver(
    _url: String,
    _identity: Option<PathBuf>,
    _ca: Option<PathBuf>,
) -> Result<Box<dyn SafeDirectory>, Error> {
    Err(Error::Unsupported(
        "--vas-url requires a build with the `vas` feature".to_owned(),
    ))
}

fn resolve(dir: &dyn SafeDirectory, r: &Ref) -> Result<Vec<SafeEntry>, Error> {
    match r {
        Ref::SafeId(id) => Ok(dir.lookup_safe_id(id)?.into_iter().collect()),
        Ref::Dienststellen(ds) => dir.lookup_dienststellen(ds),
    }
}

fn print_entry(e: &SafeEntry) {
    out(&format!("SAFE-ID      {}", e.safe_id));
    out(&format!("directory    {}", e.directory.token()));
    out(&format!("name         {}", e.name));
    if let Some(v) = &e.vorname {
        out(&format!("vorname      {v}"));
    }
    for (label, value) in [
        ("beruf", &e.beruf),
        ("kanzlei", &e.kanzlei),
        ("abteilung", &e.abteilung),
        ("strasse", &e.strasse),
        ("hausnummer", &e.hausnummer),
        ("plz", &e.plz),
        ("ort", &e.ort),
        ("bundesland", &e.bundesland),
        ("land", &e.land),
        ("telefon", &e.telefon),
        ("mobil", &e.mobil),
    ] {
        if let Some(v) = value {
            out(&format!("{label:<12} {v}"));
        }
    }
    for ds in &e.dienststellen_ids {
        out(&format!("dienststelle {ds}"));
    }
    let roles: Vec<String> = e.roles.iter().map(|r| r.token().to_string()).collect();
    out(&format!("roles        {}", roles.join(", ")));
    out(&format!("intermediary {}", e.osci.intermediary_url));
    if let Some(fp) = &e.osci.intermediary_cipher.fingerprint {
        out(&format!("int.-cert    sha256:{fp}"));
    }
    out(&format!(
        "certs        recipient={} reader={}",
        e.osci.recipient_cipher.len(),
        e.osci.reader_cipher.len()
    ));
    out(&format!("state        {:?}", e.state(now_unix())));
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn cmd_validate(file: &std::path::Path, json: bool) -> Result<ExitCode, Error> {
    let extract = safedir::extract::ExtractFile::from_path(file)?;
    let issues = extract.validate();
    if json {
        let payload: Vec<serde_json::Value> = issues
            .iter()
            .map(|i| {
                serde_json::json!({
                    "entry": i.entry,
                    "field": i.field,
                    "message": i.message,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "entries": extract.entries.len(),
            "issues": payload,
        }))
        .map_err(|e| Error::Extract(e.to_string()))?;
        out(&json);
    } else {
        out(&format!("{} entries", extract.entries.len()));
        if issues.is_empty() {
            out("no issues");
        }
        for i in &issues {
            match i.entry {
                Some(n) => out(&format!("entry {n}: {}: {}", i.field, i.message)),
                None => out(&format!("{}: {}", i.field, i.message)),
            }
        }
    }
    if issues.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(4))
    }
}

fn cmd_addressable(
    sender_role: &str,
    r#ref: &str,
    file: Option<PathBuf>,
) -> Result<ExitCode, Error> {
    let sender: RoleValue = sender_role.parse()?;
    let r = parse_ref(r#ref)?;
    let dir = open_extract(file.as_deref())?;
    let entries = resolve(&dir, &r)?;
    if entries.is_empty() {
        eprintln!("safedir: no entry for {ref}");
        return Ok(ExitCode::from(3));
    }
    let mut all_ok = true;
    for e in &entries {
        let verdict =
            safedir::addressability::addressability(std::slice::from_ref(&sender), e, now_unix());
        match verdict {
            safedir::addressability::Addressability::Addressable => {
                out(&format!(
                    "ADDRESSABLE     {} → {}",
                    sender.token(),
                    e.safe_id
                ));
            }
            safedir::addressability::Addressability::Conditional(c) => {
                all_ok = false;
                out(&format!(
                    "CONDITIONAL     {} → {}: {c:?}",
                    sender.token(),
                    e.safe_id
                ));
            }
            safedir::addressability::Addressability::NotAddressable(reason) => {
                all_ok = false;
                out(&format!(
                    "NOT ADDRESSABLE {} → {}: {reason}",
                    sender.token(),
                    e.safe_id
                ));
            }
            _ => {
                all_ok = false;
                out(&format!("UNKNOWN VERDICT for {}", e.safe_id));
            }
        }
    }
    if all_ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(4))
    }
}
