use log::info;
use rbxlx_to_rojo::{filesystem::FileSystem, process_instructions};
use std::{
    borrow::Cow,
    fmt, fs,
    io::{self, BufReader, Read, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
};
use regex::Regex;

#[derive(Debug)]
enum Problem {
    BinaryDecodeError(rbx_binary::DecodeError),
    InvalidFile,
    IoError(&'static str, io::Error),
    NFDCancel,
    NFDError(String),
    XMLDecodeError(rbx_xml::DecodeError),
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Problem::BinaryDecodeError(error) => write!(
                formatter,
                "While attempting to decode the place file, at {} rbx_binary didn't know what to do",
                error,
            ),

            Problem::InvalidFile => {
                write!(formatter, "The file provided does not have a recognized file extension")
            }

            Problem::IoError(doing_what, error) => {
                write!(formatter, "While attempting to {}, {}", doing_what, error)
            }

            Problem::NFDCancel => write!(formatter, "Didn't choose a file."),

            Problem::NFDError(error) => write!(
                formatter,
                "Something went wrong when choosing a file: {}",
                error,
            ),

            Problem::XMLDecodeError(error) => write!(
                formatter,
                "While attempting to decode the place file, at {} rbx_xml didn't know what to do",
                error,
            ),
        }
    }
}

struct WrappedLogger {
    log: env_logger::Logger,
    log_file: Arc<RwLock<Option<fs::File>>>,
}

impl log::Log for WrappedLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.log.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.log.log(record);

            if let Some(ref mut log_file) = &mut *self.log_file.write().unwrap() {
                log_file
                    .write(format!("{}\r\n", record.args()).as_bytes())
                    .ok();
            }
        }
    }

    fn flush(&self) {}
}

fn is_valid_xml_codepoint(code: u32) -> bool {
    match code {
        0x9 | 0xA | 0xD => true,
        0x20..=0xD7FF => true,
        0xE000..=0xFFFD => true,
        0x10000..=0x10FFFF => true,
        _ => false,
    }
}

fn sanitize_xml(text: &mut String) -> bool {
    if text.chars().all(|c| is_valid_xml_codepoint(c as u32)) {
        return false;
    }

    let mut cleaned = String::with_capacity(text.len());
    for ch in text.chars() {
        if is_valid_xml_codepoint(ch as u32) {
            cleaned.push(ch);
        }
    }

    *text = cleaned;
    true
}

fn strip_invalid_numeric_char_refs(text: &mut String) -> bool {
    // Matches both decimal and hex numeric character references.
    lazy_static::lazy_static! {
        static ref NUMERIC_CHAR_REF_RE: Regex = Regex::new(r"&#(x[0-9A-Fa-f]+|[0-9]+);").unwrap();
    }

    let mut changed = false;
    let replaced = NUMERIC_CHAR_REF_RE.replace_all(text, |caps: &regex::Captures| {
        let raw = &caps[1];
        let value = if raw.starts_with('x') || raw.starts_with('X') {
            u32::from_str_radix(&raw[1..], 16).ok()
        } else {
            raw.parse::<u32>().ok()
        };

        match value {
            Some(code) if is_valid_xml_codepoint(code) => caps[0].to_string(),
            _ => {
                changed = true;
                String::new()
            }
        }
    });

    if changed {
        *text = replaced.into_owned();
    }

    changed
}

fn replace_invalid_float_literals(text: &mut String) -> bool {
    lazy_static::lazy_static! {
        static ref INVALID_FLOAT_TOKEN_RE: Regex = Regex::new(
            r"(?i)(-?nan(?:\\([^)]*\\))?|1\\.\\#(?:inf|ind|qnan|nan)|-?inf)"
        )
        .unwrap();
        static ref FLOAT_FIELD_RE: Regex = Regex::new(
            r"(>\\s*)(-?[0-9]+(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[^<\\s]+)(\\s*<)"
        )
        .unwrap();
        static ref NUMBER_SEQUENCE_RE: Regex = Regex::new(
            r"(<NumberSequence[^>]*>)([^<]+)(</NumberSequence>)"
        )
        .unwrap();
        static ref NUMBER_RANGE_RE: Regex = Regex::new(
            r"(<NumberRange[^>]*>)([^<]+)(</NumberRange>)"
        )
        .unwrap();
    }

    let mut changed = false;

    // Replace obvious tokens first.
    if INVALID_FLOAT_TOKEN_RE.is_match(text) {
        let replaced = INVALID_FLOAT_TOKEN_RE.replace_all(text, "0");
        *text = replaced.into_owned();
        changed = true;
    }

    // Normalize any non-parsable tokens inside NumberSequence/NumberRange elements to 0.
    let normalize_list = |list: &str| -> String {
        list.split_whitespace()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<f64>().ok().map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let replaced_ns = NUMBER_SEQUENCE_RE.replace_all(text, |caps: &regex::Captures| {
        changed = true;
        format!("{}{}{}", &caps[1], normalize_list(&caps[2]), &caps[3])
    });
    *text = replaced_ns.into_owned();

    let replaced_nr = NUMBER_RANGE_RE.replace_all(text, |caps: &regex::Captures| {
        changed = true;
        format!("{}{}{}", &caps[1], normalize_list(&caps[2]), &caps[3])
    });
    *text = replaced_nr.into_owned();

    changed
}

fn protect_shared_sections(text: &str) -> (String, Vec<String>) {
    lazy_static::lazy_static! {
        static ref PROTECTED_RE: Regex =
            Regex::new(r"(?is)<(?:SharedString|BinaryString)[^>]*>.*?</(?:SharedString|BinaryString)>")
                .unwrap();
    }

    let mut protected: Vec<String> = Vec::new();
    let mut result = String::with_capacity(text.len());
    let mut last = 0;
    for (idx, mat) in PROTECTED_RE.find_iter(text).enumerate() {
        result.push_str(&text[last..mat.start()]);
        let placeholder = format!("__RBX_PROTECTED_CHUNK_{}__", idx);
        protected.push(text[mat.start()..mat.end()].to_string());
        result.push_str(&placeholder);
        last = mat.end();
    }
    result.push_str(&text[last..]);

    (result, protected)
}

fn restore_shared_sections(text: &mut String, protected: Vec<String>) {
    lazy_static::lazy_static! {
        static ref PLACEHOLDER_RE: Regex =
            Regex::new(r"__RBX_PROTECTED_CHUNK_(\d+)__").unwrap();
    }

    let replaced = PLACEHOLDER_RE.replace_all(text, |caps: &regex::Captures| {
        let idx: usize = caps[1].parse().unwrap_or(usize::MAX);
        protected.get(idx).cloned().unwrap_or_default()
    });
    *text = replaced.into_owned();
}

fn routine() -> Result<(), Problem> {
    let env_logger = env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .build();

    let log_file = Arc::new(RwLock::new(None));
    let logger = WrappedLogger {
        log: env_logger,
        log_file: Arc::clone(&log_file),
    };

    log::set_boxed_logger(Box::new(logger)).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    info!("rbxlx-to-rojo {}", env!("CARGO_PKG_VERSION"));

    info!("Select a place file.");
    let file_path = PathBuf::from(match std::env::args().nth(1) {
        Some(text) => text,
        None => match nfd::open_file_dialog(Some("rbxl,rbxm,rbxlx,rbxmx"), None)
            .map_err(|error| Problem::NFDError(error.to_string()))?
        {
            nfd::Response::Okay(path) => path,
            nfd::Response::Cancel => Err(Problem::NFDCancel)?,
            _ => unreachable!(),
        },
    });

    info!("Opening place file");
    let file_source = BufReader::new(
        fs::File::open(&file_path)
            .map_err(|error| Problem::IoError("read the place file", error))?,
    );
    info!("Decoding place file, this is the longest part...");

    let tree = match file_path
        .extension()
        .map(|extension| extension.to_string_lossy())
    {
        Some(Cow::Borrowed("rbxmx")) | Some(Cow::Borrowed("rbxlx")) => {
            let mut reader = file_source;
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|error| Problem::IoError("read the place file", error))?;

            let contents = String::from_utf8_lossy(&bytes).into_owned();
            if contents.len() != bytes.len() {
                log::warn!("Replaced invalid UTF-8 bytes while reading XML; content was lossily decoded.");
            }

            let (mut safe_contents, protected) = protect_shared_sections(&contents);

            if replace_invalid_float_literals(&mut safe_contents) {
                log::warn!("Replaced invalid float literals before decoding.");
            }

            if strip_invalid_numeric_char_refs(&mut safe_contents) {
                log::warn!("Stripped invalid numeric character references before decoding.");
            }

            if sanitize_xml(&mut safe_contents) {
                log::warn!("Stripped invalid XML characters before decoding.");
            }

            restore_shared_sections(&mut safe_contents, protected);

            rbx_xml::from_str_default(&safe_contents).map_err(Problem::XMLDecodeError)
        }
        Some(Cow::Borrowed("rbxm")) | Some(Cow::Borrowed("rbxl")) => {
            rbx_binary::from_reader(file_source).map_err(Problem::BinaryDecodeError)
        }
        _ => Err(Problem::InvalidFile),
    }?;

    info!("Select the path to put your Rojo project in.");
    let root = PathBuf::from(match std::env::args().nth(2) {
        Some(text) => text,
        None => match nfd::open_pick_folder(Some(&file_path.parent().unwrap().to_string_lossy()))
            .map_err(|error| Problem::NFDError(error.to_string()))?
        {
            nfd::Response::Okay(path) => path,
            nfd::Response::Cancel => Err(Problem::NFDCancel)?,
            _ => unreachable!(),
        },
    });

    let mut filesystem = FileSystem::from_root(root.join(file_path.file_stem().unwrap()).into());

    log_file.write().unwrap().replace(
        fs::File::create(root.join("rbxlx-to-rojo.log"))
            .map_err(|error| Problem::IoError("couldn't create log file", error))?,
    );

    info!("Starting processing, please wait a bit...");
    process_instructions(&tree, &mut filesystem);
    info!("Done! Check rbxlx-to-rojo.log for a full log.");
    Ok(())
}

fn main() {
    if let Err(error) = routine() {
        eprintln!("An error occurred while using rbxlx-to-rojo.");
        eprintln!("{}", error);
    }
}
