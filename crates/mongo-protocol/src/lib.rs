use flate2::read::ZlibDecoder;
use snap::raw::Decoder as SnappyDecoder;
use std::io::Read;
use thiserror::Error;

pub const OP_REPLY: i32 = 1;
pub const OP_QUERY: i32 = 2004;
pub const OP_COMPRESSED: i32 = 2012;
pub const OP_MSG: i32 = 2013;
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 48 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct DecoderConfig {
    pub max_message_bytes: usize,
    pub max_buffer_bytes: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_buffer_bytes: DEFAULT_MAX_MESSAGE_BYTES * 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MongoCommand {
    pub name: String,
    pub database: Option<String>,
    pub collection: Option<String>,
    pub auth_mechanism: Option<String>,
    pub principal: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResponseStatus {
    pub ok: Option<bool>,
    pub code: Option<i32>,
    pub code_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedMessage {
    pub request_id: i32,
    pub response_to: i32,
    pub wire_bytes: u32,
    pub flags: u32,
    pub more_to_come: bool,
    pub compressed: bool,
    pub command: Option<MongoCommand>,
    pub status: Option<ResponseStatus>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("MongoDB frame length {0} is invalid")]
    InvalidFrameLength(i32),
    #[error("MongoDB frame exceeds configured limit")]
    FrameTooLarge,
    #[error("MongoDB stream buffer exceeds configured limit")]
    BufferTooLarge,
    #[error("truncated MongoDB message")]
    Truncated,
    #[error("unsupported MongoDB opcode {0}")]
    UnsupportedOpcode(i32),
    #[error("unsupported OP_MSG section kind {0}")]
    UnsupportedSection(u8),
    #[error("invalid BSON document")]
    InvalidBson,
    #[error("invalid OP_COMPRESSED payload")]
    InvalidCompressed,
    #[error("unsupported MongoDB compressor {0}")]
    UnsupportedCompressor(u8),
    #[error("MongoDB decompression failed: {0}")]
    Decompression(String),
}

pub struct StreamDecoder {
    config: DecoderConfig,
    buffer: Vec<u8>,
}

impl StreamDecoder {
    pub fn new(config: DecoderConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<DecodedMessage>, DecodeError> {
        if self.buffer.len().saturating_add(bytes.len()) > self.config.max_buffer_bytes {
            self.buffer.clear();
            return Err(DecodeError::BufferTooLarge);
        }
        self.buffer.extend_from_slice(bytes);

        let mut decoded = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let length = i32::from_le_bytes(self.buffer[0..4].try_into().unwrap());
            if length < 16 {
                self.buffer.clear();
                return Err(DecodeError::InvalidFrameLength(length));
            }
            let length = length as usize;
            if length > self.config.max_message_bytes {
                self.buffer.clear();
                return Err(DecodeError::FrameTooLarge);
            }
            if self.buffer.len() < length {
                break;
            }
            let frame = self.buffer[..length].to_vec();
            self.buffer.drain(..length);
            decoded.push(decode_frame(&frame, self.config.max_message_bytes)?);
        }
        Ok(decoded)
    }

    /// Decodes a large uncompressed frame from only its first `prefix_limit`
    /// bytes. This bounds retained stream data even when an application emits
    /// one frame through many individually short syscalls.
    pub fn push_bounded_prefix(
        &mut self,
        bytes: &[u8],
        prefix_limit: usize,
    ) -> Result<Vec<DecodedMessage>, DecodeError> {
        if prefix_limit < 16 || prefix_limit > self.config.max_buffer_bytes {
            self.buffer.clear();
            return Err(DecodeError::BufferTooLarge);
        }

        let Some(frame_length) = self.next_frame_length(bytes)? else {
            return self.push(bytes);
        };
        if frame_length <= prefix_limit
            || self.buffer.len().saturating_add(bytes.len()) < prefix_limit
        {
            return self.push(bytes);
        }

        let needed = prefix_limit.saturating_sub(self.buffer.len());
        let message = self.push_truncated(&bytes[..needed.min(bytes.len())])?;
        Ok(vec![message])
    }

    fn next_frame_length(&self, bytes: &[u8]) -> Result<Option<usize>, DecodeError> {
        let mut header = [0u8; 4];
        let buffered = self.buffer.len().min(4);
        header[..buffered].copy_from_slice(&self.buffer[..buffered]);
        let needed = 4 - buffered;
        if bytes.len() < needed {
            return Ok(None);
        }
        header[buffered..].copy_from_slice(&bytes[..needed]);
        let length = i32::from_le_bytes(header);
        if length < 16 {
            return Err(DecodeError::InvalidFrameLength(length));
        }
        let length = length as usize;
        if length > self.config.max_message_bytes {
            return Err(DecodeError::FrameTooLarge);
        }
        Ok(Some(length))
    }

    /// Finishes a stream prefix when the sensor copied only the beginning of
    /// the current syscall buffer. Bytes accumulated from earlier short reads
    /// are included, then the stream is reset because the omitted tail cannot
    /// be reconstructed.
    pub fn push_truncated(&mut self, bytes: &[u8]) -> Result<DecodedMessage, DecodeError> {
        if self.buffer.len().saturating_add(bytes.len()) > self.config.max_buffer_bytes {
            self.buffer.clear();
            return Err(DecodeError::BufferTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        let result = decode_frame_prefix(&self.buffer, self.config.max_message_bytes);
        self.buffer.clear();
        result
    }
}

pub fn decode_frame(frame: &[u8], max_message_bytes: usize) -> Result<DecodedMessage, DecodeError> {
    if frame.len() < 16 {
        return Err(DecodeError::Truncated);
    }
    let declared = read_i32(frame, 0)?;
    if declared < 16 || declared as usize != frame.len() {
        return Err(DecodeError::InvalidFrameLength(declared));
    }
    if frame.len() > max_message_bytes {
        return Err(DecodeError::FrameTooLarge);
    }
    let request_id = read_i32(frame, 4)?;
    let response_to = read_i32(frame, 8)?;
    let opcode = read_i32(frame, 12)?;
    let payload = &frame[16..];

    match opcode {
        OP_MSG => decode_op_msg(request_id, response_to, frame.len(), payload, false),
        OP_QUERY => decode_op_query(request_id, response_to, frame.len(), payload, false),
        OP_REPLY => decode_op_reply(request_id, response_to, frame.len(), payload, false),
        OP_COMPRESSED => decode_compressed(
            request_id,
            response_to,
            frame.len(),
            payload,
            max_message_bytes,
        ),
        other => Err(DecodeError::UnsupportedOpcode(other)),
    }
}

/// Decodes only the bounded prefix copied by the sensor. This intentionally
/// extracts command metadata without requiring the rest of a potentially
/// sensitive BSON body to leave kernel memory. Compressed messages still need
/// a complete frame because their BSON prefix cannot be recovered safely from
/// a truncated compressed stream.
pub fn decode_frame_prefix(
    prefix: &[u8],
    max_message_bytes: usize,
) -> Result<DecodedMessage, DecodeError> {
    if prefix.len() < 16 {
        return Err(DecodeError::Truncated);
    }
    let declared = read_i32(prefix, 0)?;
    if declared < 16 {
        return Err(DecodeError::InvalidFrameLength(declared));
    }
    let declared = declared as usize;
    if declared > max_message_bytes {
        return Err(DecodeError::FrameTooLarge);
    }
    if prefix.len() >= declared {
        return decode_frame(&prefix[..declared], max_message_bytes);
    }

    let request_id = read_i32(prefix, 4)?;
    let response_to = read_i32(prefix, 8)?;
    let opcode = read_i32(prefix, 12)?;
    if opcode == OP_COMPRESSED {
        return Err(DecodeError::Truncated);
    }
    match opcode {
        OP_MSG => decode_op_msg_prefix(request_id, response_to, declared, &prefix[16..]),
        OP_QUERY => decode_op_query_prefix(request_id, response_to, declared, &prefix[16..]),
        OP_REPLY => decode_op_reply_prefix(request_id, response_to, declared, &prefix[16..]),
        other => Err(DecodeError::UnsupportedOpcode(other)),
    }
}

fn decode_op_msg_prefix(
    request_id: i32,
    response_to: i32,
    declared: usize,
    payload: &[u8],
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 6 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    if payload[4] != 0 {
        return Err(DecodeError::UnsupportedSection(payload[4]));
    }
    let document = &payload[5..];
    let summary = summarize_bson_prefix(document)?;
    let command = if response_to == 0 {
        command_from_summary(&summary)
    } else {
        None
    };
    let status = if response_to != 0 {
        Some(ResponseStatus {
            ok: summary.ok,
            code: summary.code,
            code_name: summary.code_name,
        })
    } else {
        None
    };
    Ok(DecodedMessage {
        request_id,
        response_to,
        wire_bytes: u32::try_from(declared).unwrap_or(u32::MAX),
        flags,
        more_to_come: flags & 2 != 0,
        compressed: false,
        command,
        status,
    })
}

fn decode_compressed(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
    max_message_bytes: usize,
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 9 {
        return Err(DecodeError::InvalidCompressed);
    }
    let original_opcode = read_i32(payload, 0)?;
    let uncompressed_size = read_i32(payload, 4)?;
    if uncompressed_size < 0 || uncompressed_size as usize > max_message_bytes.saturating_sub(16) {
        return Err(DecodeError::FrameTooLarge);
    }
    let compressor = payload[8];
    let compressed = &payload[9..];
    let uncompressed = match compressor {
        0 => compressed.to_vec(),
        1 => {
            let decoded_size = snap::raw::decompress_len(compressed)
                .map_err(|error| DecodeError::Decompression(error.to_string()))?;
            if decoded_size != uncompressed_size as usize {
                return Err(DecodeError::InvalidCompressed);
            }
            SnappyDecoder::new()
                .decompress_vec(compressed)
                .map_err(|error| DecodeError::Decompression(error.to_string()))?
        }
        2 => {
            let decoder = ZlibDecoder::new(compressed);
            let mut output = Vec::with_capacity(uncompressed_size as usize);
            decoder
                .take(uncompressed_size as u64 + 1)
                .read_to_end(&mut output)
                .map_err(|error| DecodeError::Decompression(error.to_string()))?;
            output
        }
        3 => {
            let decoder = zstd::stream::read::Decoder::new(compressed)
                .map_err(|error| DecodeError::Decompression(error.to_string()))?;
            let mut output = Vec::with_capacity(uncompressed_size as usize);
            decoder
                .take(uncompressed_size as u64 + 1)
                .read_to_end(&mut output)
                .map_err(|error| DecodeError::Decompression(error.to_string()))?;
            output
        }
        other => return Err(DecodeError::UnsupportedCompressor(other)),
    };
    if uncompressed.len() != uncompressed_size as usize {
        return Err(DecodeError::InvalidCompressed);
    }
    match original_opcode {
        OP_MSG => decode_op_msg(request_id, response_to, wire_bytes, &uncompressed, true),
        OP_QUERY => decode_op_query(request_id, response_to, wire_bytes, &uncompressed, true),
        OP_REPLY => decode_op_reply(request_id, response_to, wire_bytes, &uncompressed, true),
        other => Err(DecodeError::UnsupportedOpcode(other)),
    }
}

fn decode_op_query(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
    compressed: bool,
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 13 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    let (namespace, after_namespace) = read_cstring(payload, 4)?;
    let document_offset = after_namespace
        .checked_add(8)
        .ok_or(DecodeError::InvalidBson)?;
    let document_length = read_i32(payload, document_offset)?;
    if document_length < 5 {
        return Err(DecodeError::InvalidBson);
    }
    let document_end = document_offset
        .checked_add(document_length as usize)
        .ok_or(DecodeError::InvalidBson)?;
    if document_end > payload.len() {
        return Err(DecodeError::InvalidBson);
    }
    let summary = summarize_bson(&payload[document_offset..document_end])?;
    Ok(decoded_op_query(
        request_id,
        response_to,
        wire_bytes,
        flags,
        namespace,
        summary,
        compressed,
    ))
}

fn decode_op_query_prefix(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 13 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    let (namespace, after_namespace) = read_cstring(payload, 4)?;
    let document_offset = after_namespace
        .checked_add(8)
        .ok_or(DecodeError::InvalidBson)?;
    let summary = summarize_bson_prefix(
        payload
            .get(document_offset..)
            .ok_or(DecodeError::Truncated)?,
    )?;
    Ok(decoded_op_query(
        request_id,
        response_to,
        wire_bytes,
        flags,
        namespace,
        summary,
        false,
    ))
}

fn decoded_op_query(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    flags: u32,
    namespace: &str,
    summary: BsonSummary,
    compressed: bool,
) -> DecodedMessage {
    let (database, namespace_collection, is_command) = split_legacy_namespace(namespace);
    let command = if response_to != 0 {
        None
    } else if is_command {
        command_from_summary(&summary).map(|mut command| {
            if command.database.is_none() {
                command.database = database;
            }
            command
        })
    } else {
        Some(MongoCommand {
            name: "find".into(),
            database,
            collection: namespace_collection,
            auth_mechanism: None,
            principal: None,
        })
    };
    DecodedMessage {
        request_id,
        response_to,
        wire_bytes: u32::try_from(wire_bytes).unwrap_or(u32::MAX),
        flags,
        more_to_come: false,
        compressed,
        command,
        status: None,
    }
}

fn decode_op_reply(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
    compressed: bool,
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 20 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    let returned = read_i32(payload, 16)?;
    let summary = if returned > 0 && payload.len() > 20 {
        let document_length = read_i32(payload, 20)?;
        if document_length < 5 {
            return Err(DecodeError::InvalidBson);
        }
        let document_end = 20usize
            .checked_add(document_length as usize)
            .ok_or(DecodeError::InvalidBson)?;
        if document_end > payload.len() {
            return Err(DecodeError::InvalidBson);
        }
        Some(summarize_bson(&payload[20..document_end])?)
    } else {
        None
    };
    Ok(decoded_op_reply(
        request_id,
        response_to,
        wire_bytes,
        flags,
        summary,
        compressed,
    ))
}

fn decode_op_reply_prefix(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 20 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    let returned = read_i32(payload, 16)?;
    let summary = if returned > 0 && payload.len() > 20 {
        Some(summarize_bson_prefix(&payload[20..])?)
    } else {
        None
    };
    Ok(decoded_op_reply(
        request_id,
        response_to,
        wire_bytes,
        flags,
        summary,
        false,
    ))
}

fn decoded_op_reply(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    flags: u32,
    summary: Option<BsonSummary>,
    compressed: bool,
) -> DecodedMessage {
    let failed = flags & 0x03 != 0;
    let status = Some(ResponseStatus {
        ok: summary
            .as_ref()
            .and_then(|value| value.ok)
            .or(Some(!failed)),
        code: summary.as_ref().and_then(|value| value.code),
        code_name: summary.and_then(|value| value.code_name),
    });
    DecodedMessage {
        request_id,
        response_to,
        wire_bytes: u32::try_from(wire_bytes).unwrap_or(u32::MAX),
        flags,
        more_to_come: false,
        compressed,
        command: None,
        status,
    }
}

fn split_legacy_namespace(namespace: &str) -> (Option<String>, Option<String>, bool) {
    let Some((database, collection)) = namespace.split_once('.') else {
        return (None, None, false);
    };
    if collection == "$cmd" || collection.starts_with("$cmd.") {
        (Some(database.to_string()), None, true)
    } else {
        (
            Some(database.to_string()),
            Some(collection.to_string()),
            false,
        )
    }
}

fn decode_op_msg(
    request_id: i32,
    response_to: i32,
    wire_bytes: usize,
    payload: &[u8],
    compressed: bool,
) -> Result<DecodedMessage, DecodeError> {
    if payload.len() < 5 {
        return Err(DecodeError::Truncated);
    }
    let flags = read_u32(payload, 0)?;
    let checksum_bytes = if flags & 1 != 0 { 4 } else { 0 };
    if payload.len() < 4 + checksum_bytes {
        return Err(DecodeError::Truncated);
    }
    let end = payload.len() - checksum_bytes;
    let mut offset = 4;
    let mut summary = None;

    while offset < end {
        let kind = payload[offset];
        offset += 1;
        match kind {
            0 => {
                let document_length = read_i32(payload, offset)?;
                if document_length < 5 {
                    return Err(DecodeError::InvalidBson);
                }
                let document_end = offset
                    .checked_add(document_length as usize)
                    .ok_or(DecodeError::InvalidBson)?;
                if document_end > end {
                    return Err(DecodeError::InvalidBson);
                }
                if summary.is_none() {
                    summary = Some(summarize_bson(&payload[offset..document_end])?);
                }
                offset = document_end;
            }
            1 => {
                let section_size = read_i32(payload, offset)?;
                if section_size < 5 {
                    return Err(DecodeError::InvalidBson);
                }
                let section_end = offset
                    .checked_add(section_size as usize)
                    .ok_or(DecodeError::InvalidBson)?;
                if section_end > end {
                    return Err(DecodeError::InvalidBson);
                }
                offset = section_end;
            }
            other => return Err(DecodeError::UnsupportedSection(other)),
        }
    }

    let summary = summary.ok_or(DecodeError::InvalidBson)?;
    let command = if response_to == 0 {
        command_from_summary(&summary)
    } else {
        None
    };
    let status = if response_to != 0 {
        Some(ResponseStatus {
            ok: summary.ok,
            code: summary.code,
            code_name: summary.code_name,
        })
    } else {
        None
    };

    Ok(DecodedMessage {
        request_id,
        response_to,
        wire_bytes: u32::try_from(wire_bytes).unwrap_or(u32::MAX),
        flags,
        more_to_come: flags & 2 != 0,
        compressed,
        command,
        status,
    })
}

#[derive(Default)]
struct BsonSummary {
    first_key: Option<String>,
    first_string: Option<String>,
    database: Option<String>,
    collection: Option<String>,
    ok: Option<bool>,
    code: Option<i32>,
    code_name: Option<String>,
    auth_mechanism: Option<String>,
    principal: Option<String>,
}

fn command_from_summary(summary: &BsonSummary) -> Option<MongoCommand> {
    let name = summary.first_key.clone()?;
    let normalized = name.to_ascii_lowercase();
    let collection = if command_has_collection_argument(&normalized) {
        summary
            .first_string
            .clone()
            .or_else(|| summary.collection.clone())
    } else {
        None
    };
    let principal = summary.principal.clone().or_else(|| {
        command_has_principal_argument(&normalized)
            .then_some(summary.first_string.clone())
            .flatten()
    });
    Some(MongoCommand {
        name,
        database: summary.database.clone(),
        collection,
        auth_mechanism: summary.auth_mechanism.clone(),
        principal,
    })
}

/// BSON's first value is command-specific. Keep this list deny-by-default so
/// identifiers such as usernames can never be mislabeled and exported as a
/// collection merely because they are strings.
fn command_has_collection_argument(command: &str) -> bool {
    matches!(
        command,
        "aggregate"
            | "clonecollectionascapped"
            | "collmod"
            | "compact"
            | "converttocapped"
            | "count"
            | "create"
            | "createindexes"
            | "delete"
            | "distinct"
            | "drop"
            | "dropindexes"
            | "emptycapped"
            | "find"
            | "findandmodify"
            | "geosearch"
            | "getmore"
            | "insert"
            | "killcursors"
            | "listindexes"
            | "mapreduce"
            | "parallelcollectionscan"
            | "renamecollection"
            | "update"
            | "validate"
    )
}

fn command_has_principal_argument(command: &str) -> bool {
    matches!(
        command,
        "createuser"
            | "dropuser"
            | "grantrolestouser"
            | "revokerolesfromuser"
            | "updateuser"
            | "usersinfo"
    )
}

fn summarize_bson(document: &[u8]) -> Result<BsonSummary, DecodeError> {
    if document.len() < 5
        || read_i32(document, 0)? as usize != document.len()
        || document.last() != Some(&0)
    {
        return Err(DecodeError::InvalidBson);
    }
    let mut summary = BsonSummary::default();
    let mut offset = 4;
    let mut ordinal = 0usize;
    while offset < document.len() - 1 {
        let element_type = document[offset];
        offset += 1;
        let (key, after_key) = read_cstring(document, offset)?;
        offset = after_key;
        let value_start = offset;
        offset = skip_value(document, offset, element_type)?;
        if offset > document.len() - 1 {
            return Err(DecodeError::InvalidBson);
        }

        if ordinal == 0 {
            summary.first_key = Some(key.to_string());
            if element_type == 0x02 {
                summary.first_string = read_bson_string(document, value_start).ok();
            }
        }
        match key {
            "$db" if element_type == 0x02 => {
                summary.database = read_bson_string(document, value_start).ok();
            }
            "collection" if element_type == 0x02 => {
                summary.collection = read_bson_string(document, value_start).ok();
            }
            "ok" => summary.ok = read_boolish(document, value_start, element_type),
            "code" => summary.code = read_i32ish(document, value_start, element_type),
            "codeName" if element_type == 0x02 => {
                summary.code_name = read_bson_string(document, value_start).ok();
            }
            "mechanism" if element_type == 0x02 => {
                summary.auth_mechanism = read_bson_string(document, value_start).ok();
            }
            "user" if element_type == 0x02 => {
                summary.principal = read_bson_string(document, value_start).ok();
            }
            "payload" if element_type == 0x05 => {
                summary.principal = read_bson_binary(document, value_start)
                    .ok()
                    .and_then(parse_scram_principal)
                    .or(summary.principal);
            }
            _ => {}
        }
        ordinal += 1;
    }
    Ok(summary)
}

fn summarize_bson_prefix(document: &[u8]) -> Result<BsonSummary, DecodeError> {
    if document.len() < 5 {
        return Err(DecodeError::Truncated);
    }
    let declared = read_i32(document, 0)?;
    if declared < 5 {
        return Err(DecodeError::InvalidBson);
    }
    let declared = declared as usize;
    let available_end = document.len().min(declared.saturating_sub(1));
    let mut summary = BsonSummary::default();
    let mut offset = 4;
    let mut ordinal = 0usize;
    while offset < available_end {
        let Some(element_type) = document.get(offset).copied() else {
            break;
        };
        offset += 1;
        let Ok((key, after_key)) = read_cstring(document, offset) else {
            break;
        };
        offset = after_key;
        let value_start = offset;
        let next = skip_value(document, offset, element_type);

        if ordinal == 0 {
            summary.first_key = Some(key.to_string());
            if element_type == 0x02 {
                summary.first_string = read_bson_string(document, value_start).ok();
            }
        }
        match key {
            "$db" if element_type == 0x02 => {
                summary.database = read_bson_string(document, value_start).ok();
            }
            "collection" if element_type == 0x02 => {
                summary.collection = read_bson_string(document, value_start).ok();
            }
            "ok" => summary.ok = read_boolish(document, value_start, element_type),
            "code" => summary.code = read_i32ish(document, value_start, element_type),
            "codeName" if element_type == 0x02 => {
                summary.code_name = read_bson_string(document, value_start).ok();
            }
            "mechanism" if element_type == 0x02 => {
                summary.auth_mechanism = read_bson_string(document, value_start).ok();
            }
            "user" if element_type == 0x02 => {
                summary.principal = read_bson_string(document, value_start).ok();
            }
            "payload" if element_type == 0x05 => {
                summary.principal = read_bson_binary(document, value_start)
                    .ok()
                    .and_then(parse_scram_principal)
                    .or(summary.principal);
            }
            _ => {}
        }
        ordinal += 1;
        match next {
            Ok(next) if next > offset && next <= available_end => offset = next,
            Ok(next) if next == declared.saturating_sub(1) => break,
            _ => break,
        }
    }
    if summary.first_key.is_none() {
        return Err(DecodeError::Truncated);
    }
    Ok(summary)
}

fn skip_value(bytes: &[u8], offset: usize, element_type: u8) -> Result<usize, DecodeError> {
    let fixed = match element_type {
        0x01 | 0x09 | 0x11 | 0x12 => Some(8),
        0x07 => Some(12),
        0x08 => Some(1),
        0x0A | 0x06 | 0x7f | 0xff => Some(0),
        0x10 => Some(4),
        0x13 => Some(16),
        _ => None,
    };
    if let Some(length) = fixed {
        return offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(DecodeError::InvalidBson);
    }

    match element_type {
        0x02 | 0x0d | 0x0e => {
            let length = read_i32(bytes, offset)?;
            if length < 1 {
                return Err(DecodeError::InvalidBson);
            }
            offset
                .checked_add(4 + length as usize)
                .filter(|end| *end <= bytes.len())
                .ok_or(DecodeError::InvalidBson)
        }
        0x03 | 0x04 | 0x0f => {
            let length = read_i32(bytes, offset)?;
            if length < 5 {
                return Err(DecodeError::InvalidBson);
            }
            offset
                .checked_add(length as usize)
                .filter(|end| *end <= bytes.len())
                .ok_or(DecodeError::InvalidBson)
        }
        0x05 => {
            let length = read_i32(bytes, offset)?;
            if length < 0 {
                return Err(DecodeError::InvalidBson);
            }
            offset
                .checked_add(5 + length as usize)
                .filter(|end| *end <= bytes.len())
                .ok_or(DecodeError::InvalidBson)
        }
        0x0b => {
            let (_, after_pattern) = read_cstring(bytes, offset)?;
            let (_, after_options) = read_cstring(bytes, after_pattern)?;
            Ok(after_options)
        }
        0x0c => {
            let length = read_i32(bytes, offset)?;
            if length < 1 {
                return Err(DecodeError::InvalidBson);
            }
            offset
                .checked_add(4 + length as usize + 12)
                .filter(|end| *end <= bytes.len())
                .ok_or(DecodeError::InvalidBson)
        }
        other => {
            let _ = other;
            Err(DecodeError::InvalidBson)
        }
    }
}

fn read_bson_string(bytes: &[u8], offset: usize) -> Result<String, DecodeError> {
    let length = read_i32(bytes, offset)?;
    if length < 1 {
        return Err(DecodeError::InvalidBson);
    }
    let start = offset + 4;
    let end = start
        .checked_add(length as usize)
        .ok_or(DecodeError::InvalidBson)?;
    if end > bytes.len() || bytes[end - 1] != 0 {
        return Err(DecodeError::InvalidBson);
    }
    std::str::from_utf8(&bytes[start..end - 1])
        .map(str::to_string)
        .map_err(|_| DecodeError::InvalidBson)
}

fn read_bson_binary(bytes: &[u8], offset: usize) -> Result<&[u8], DecodeError> {
    let length = read_i32(bytes, offset)?;
    if length < 0 {
        return Err(DecodeError::InvalidBson);
    }
    let start = offset.checked_add(5).ok_or(DecodeError::InvalidBson)?;
    let end = start
        .checked_add(length as usize)
        .ok_or(DecodeError::InvalidBson)?;
    bytes.get(start..end).ok_or(DecodeError::InvalidBson)
}

fn parse_scram_principal(payload: &[u8]) -> Option<String> {
    let payload = std::str::from_utf8(payload).ok()?;
    let encoded = payload
        .split(',')
        .find_map(|field| field.strip_prefix("n=").filter(|value| !value.is_empty()))?;
    if encoded.len() > 768 {
        return None;
    }
    let decoded = encoded.replace("=2C", ",").replace("=3D", "=");
    (!decoded.is_empty() && decoded.len() <= 256 && !decoded.chars().any(char::is_control))
        .then_some(decoded)
}

fn read_boolish(bytes: &[u8], offset: usize, element_type: u8) -> Option<bool> {
    match element_type {
        0x01 => {
            let value = f64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
            Some(value != 0.0)
        }
        0x08 => Some(*bytes.get(offset)? != 0),
        0x10 => Some(read_i32(bytes, offset).ok()? != 0),
        0x12 => Some(i64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?) != 0),
        _ => None,
    }
}

fn read_i32ish(bytes: &[u8], offset: usize, element_type: u8) -> Option<i32> {
    match element_type {
        0x10 => read_i32(bytes, offset).ok(),
        0x12 => i32::try_from(i64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
        .ok(),
        0x01 => {
            let value = f64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
            if value >= i32::MIN as f64 && value <= i32::MAX as f64 {
                Some(value as i32)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn read_cstring(bytes: &[u8], offset: usize) -> Result<(&str, usize), DecodeError> {
    let relative_end = bytes
        .get(offset..)
        .ok_or(DecodeError::InvalidBson)?
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DecodeError::InvalidBson)?;
    let end = offset + relative_end;
    let value = std::str::from_utf8(&bytes[offset..end]).map_err(|_| DecodeError::InvalidBson)?;
    Ok((value, end + 1))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, DecodeError> {
    bytes
        .get(offset..offset + 4)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .map(i32::from_le_bytes)
        .map_err(|_| DecodeError::Truncated)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    bytes
        .get(offset..offset + 4)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| DecodeError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn string_element(key: &str, value: &str) -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&((value.len() + 1) as i32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        bytes
    }

    fn double_element(key: &str, value: f64) -> Vec<u8> {
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    fn int_element(key: &str, value: i32) -> Vec<u8> {
        let mut bytes = vec![0x10];
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    fn binary_element(key: &str, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x05];
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(value.len() as i32).to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(value);
        bytes
    }

    fn document(elements: Vec<Vec<u8>>) -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0];
        for element in elements {
            bytes.extend_from_slice(&element);
        }
        bytes.push(0);
        let length = bytes.len() as i32;
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    fn op_msg(request_id: i32, response_to: i32, flags: u32, bson: Vec<u8>) -> Vec<u8> {
        let mut payload = flags.to_le_bytes().to_vec();
        payload.push(0);
        payload.extend_from_slice(&bson);
        let mut frame = ((16 + payload.len()) as i32).to_le_bytes().to_vec();
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&response_to.to_le_bytes());
        frame.extend_from_slice(&OP_MSG.to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn op_query(request_id: i32, namespace: &str, bson: Vec<u8>) -> Vec<u8> {
        let mut payload = 0u32.to_le_bytes().to_vec();
        payload.extend_from_slice(namespace.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&(-1i32).to_le_bytes());
        payload.extend_from_slice(&bson);
        let mut frame = ((16 + payload.len()) as i32).to_le_bytes().to_vec();
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&0i32.to_le_bytes());
        frame.extend_from_slice(&OP_QUERY.to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn op_reply(request_id: i32, response_to: i32, flags: u32, bson: Vec<u8>) -> Vec<u8> {
        let mut payload = flags.to_le_bytes().to_vec();
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&bson);
        let mut frame = ((16 + payload.len()) as i32).to_le_bytes().to_vec();
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&response_to.to_le_bytes());
        frame.extend_from_slice(&OP_REPLY.to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn decodes_fragmented_find_without_query_values() {
        let bson = document(vec![
            string_element("find", "orders"),
            string_element("$db", "sales"),
        ]);
        let frame = op_msg(41, 0, 0, bson);
        let split = frame.len() / 2;
        let mut decoder = StreamDecoder::new(DecoderConfig::default());
        assert!(decoder.push(&frame[..split]).unwrap().is_empty());
        let messages = decoder.push(&frame[split..]).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].command,
            Some(MongoCommand {
                name: "find".into(),
                database: Some("sales".into()),
                collection: Some("orders".into()),
                auth_mechanism: None,
                principal: None,
            })
        );
    }

    #[test]
    fn treats_user_management_argument_as_principal_not_collection() {
        let bson = document(vec![
            string_element("createUser", "alice@example.com"),
            string_element("$db", "admin"),
        ]);
        let frame = op_msg(43, 0, 0, bson);
        let command = decode_frame(&frame, DEFAULT_MAX_MESSAGE_BYTES)
            .unwrap()
            .command
            .unwrap();

        assert_eq!(command.name, "createUser");
        assert_eq!(command.database.as_deref(), Some("admin"));
        assert_eq!(command.collection, None);
        assert_eq!(command.principal.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn extracts_scram_principal_without_retaining_the_auth_payload() {
        let bson = document(vec![
            int_element("saslStart", 1),
            string_element("mechanism", "SCRAM-SHA-256"),
            binary_element("payload", b"n,,n=alice=2Cops,r=client-nonce"),
            string_element("$db", "admin"),
        ]);
        let frame = op_msg(45, 0, 0, bson);
        let command = decode_frame(&frame, DEFAULT_MAX_MESSAGE_BYTES)
            .unwrap()
            .command
            .unwrap();

        assert_eq!(command.name, "saslStart");
        assert_eq!(command.auth_mechanism.as_deref(), Some("SCRAM-SHA-256"));
        assert_eq!(command.principal.as_deref(), Some("alice,ops"));
    }

    #[test]
    fn decodes_legacy_op_query_and_reply_metadata() {
        let query = op_query(
            51,
            "sales.$cmd",
            document(vec![
                string_element("find", "orders"),
                string_element("$db", "sales"),
            ]),
        );
        let command = decode_frame(&query, DEFAULT_MAX_MESSAGE_BYTES)
            .unwrap()
            .command
            .unwrap();
        assert_eq!(command.name, "find");
        assert_eq!(command.database.as_deref(), Some("sales"));
        assert_eq!(command.collection.as_deref(), Some("orders"));

        let reply = op_reply(52, 51, 0, document(vec![double_element("ok", 1.0)]));
        let response = decode_frame(&reply, DEFAULT_MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(response.response_to, 51);
        assert_eq!(response.status.unwrap().ok, Some(true));
    }

    #[test]
    fn maps_legacy_collection_queries_to_find_without_filter_values() {
        let query = op_query(
            53,
            "sales.orders",
            document(vec![string_element("secret", "must-not-be-exported")]),
        );
        let command = decode_frame(&query, DEFAULT_MAX_MESSAGE_BYTES)
            .unwrap()
            .command
            .unwrap();
        assert_eq!(command.name, "find");
        assert_eq!(command.database.as_deref(), Some("sales"));
        assert_eq!(command.collection.as_deref(), Some("orders"));
        assert_eq!(command.principal, None);
    }

    #[test]
    fn never_exports_an_unknown_command_string_as_a_collection() {
        let bson = document(vec![
            string_element("futureCommand", "possibly-sensitive-value"),
            string_element("$db", "admin"),
        ]);
        let frame = op_msg(44, 0, 0, bson);
        let command = decode_frame(&frame, DEFAULT_MAX_MESSAGE_BYTES)
            .unwrap()
            .command
            .unwrap();

        assert_eq!(command.collection, None);
        assert_eq!(command.principal, None);
    }

    #[test]
    fn decodes_metadata_from_a_truncated_large_message_prefix() {
        let bson = document(vec![
            string_element("find", "orders"),
            string_element("$db", "sales"),
            string_element("comment", &"sensitive".repeat(256)),
        ]);
        let frame = op_msg(77, 0, 0, bson);
        let prefix = &frame[..96];
        let message = decode_frame_prefix(prefix, DEFAULT_MAX_MESSAGE_BYTES).unwrap();
        let command = message.command.unwrap();
        assert_eq!(command.name, "find");
        assert_eq!(command.collection.as_deref(), Some("orders"));
        assert_eq!(command.database.as_deref(), Some("sales"));
        assert_eq!(message.wire_bytes as usize, frame.len());
    }

    #[test]
    fn truncated_chunk_includes_a_header_from_an_earlier_short_read() {
        let bson = document(vec![
            string_element("find", "orders"),
            string_element("$db", "sales"),
            string_element("padding", &"x".repeat(2_000)),
        ]);
        let frame = op_msg(42, 0, 0, bson);
        let mut decoder = StreamDecoder::new(DecoderConfig::default());
        assert!(decoder.push(&frame[..16]).unwrap().is_empty());
        let message = decoder.push_truncated(&frame[16..528]).unwrap();

        assert_eq!(message.request_id, 42);
        assert_eq!(message.wire_bytes as usize, frame.len());
        assert_eq!(message.command.unwrap().name, "find");
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn bounds_a_large_frame_split_across_short_reads_to_its_prefix() {
        let bson = document(vec![
            string_element("find", "orders"),
            string_element("$db", "sales"),
            string_element("filter", &"private-value".repeat(256)),
        ]);
        let frame = op_msg(91, 0, 0, bson);
        let mut decoder = StreamDecoder::new(DecoderConfig {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_buffer_bytes: 2_048,
        });

        assert!(decoder
            .push_bounded_prefix(&frame[..512], 1_024)
            .unwrap()
            .is_empty());
        let messages = decoder
            .push_bounded_prefix(&frame[512..1_024], 1_024)
            .unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].command.as_ref().unwrap().name, "find");
        assert_eq!(
            messages[0].command.as_ref().unwrap().database.as_deref(),
            Some("sales")
        );
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn decodes_response_status() {
        let bson = document(vec![
            double_element("ok", 0.0),
            int_element("code", 13),
            string_element("codeName", "Unauthorized"),
        ]);
        let frame = op_msg(42, 41, 0, bson);
        let message = decode_frame(&frame, DEFAULT_MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(
            message.status,
            Some(ResponseStatus {
                ok: Some(false),
                code: Some(13),
                code_name: Some("Unauthorized".into()),
            })
        );
    }

    #[test]
    fn decodes_zlib_compressed_op_msg() {
        let bson = document(vec![
            string_element("aggregate", "orders"),
            string_element("$db", "sales"),
        ]);
        let inner = op_msg(9, 0, 0, bson);
        let inner_payload = &inner[16..];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(inner_payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut payload = OP_MSG.to_le_bytes().to_vec();
        payload.extend_from_slice(&(inner_payload.len() as i32).to_le_bytes());
        payload.push(2);
        payload.extend_from_slice(&compressed);
        let mut frame = ((16 + payload.len()) as i32).to_le_bytes().to_vec();
        frame.extend_from_slice(&9i32.to_le_bytes());
        frame.extend_from_slice(&0i32.to_le_bytes());
        frame.extend_from_slice(&OP_COMPRESSED.to_le_bytes());
        frame.extend_from_slice(&payload);

        let message = decode_frame(&frame, DEFAULT_MAX_MESSAGE_BYTES).unwrap();
        assert!(message.compressed);
        assert_eq!(message.command.unwrap().name, "aggregate");
    }

    #[test]
    fn rejects_oversized_frame_before_buffering_body() {
        let mut decoder = StreamDecoder::new(DecoderConfig {
            max_message_bytes: 32,
            max_buffer_bytes: 64,
        });
        assert_eq!(
            decoder.push(&100i32.to_le_bytes()),
            Err(DecodeError::FrameTooLarge)
        );
    }
}
