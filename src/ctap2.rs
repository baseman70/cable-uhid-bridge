use ciborium::value::Value;

pub const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
pub const CTAP_CMD_GET_INFO: u8 = 0x04;

pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;

#[derive(Debug, Clone)]
pub struct AssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub user_presence: bool,
    pub user_verification: bool,
    pub allow_list_len: usize,
    pub allow_list: Vec<Vec<u8>>,
}

/// Parses a raw GetAssertion CBOR request to extract the relying party ID,
/// clientDataHash, options (user presence, user verification), and allowList.
pub fn parse_assertion_request(raw_cbor: &[u8]) -> AssertionRequest {
    let mut req = AssertionRequest {
        rp_id: "Passkey Authentication".to_string(),
        client_data_hash: Vec::new(),
        user_presence: true, // In CTAP2, user presence defaults to true if omitted
        user_verification: false,
        allow_list_len: 0,
        allow_list: Vec::new(),
    };

    if raw_cbor.len() > 1 {
        // Skip the first byte (CTAP_CMD_GET_ASSERTION = 0x02)
        if let Ok(Value::Map(entries)) = ciborium::from_reader(&raw_cbor[1..]) {
            for (k, v) in entries {
                if let Value::Integer(int) = k {
                    // Key 1: rpId (String)
                    if int == 1.into() {
                        if let Value::Text(s) = v {
                            req.rp_id = s;
                        }
                    }
                    // Key 2: clientDataHash (Byte string, 32 bytes)
                    else if int == 2.into() {
                        if let Value::Bytes(b) = v {
                            req.client_data_hash = b;
                        }
                    }
                    // Key 3: allowList (Array of PublicKeyCredentialDescriptor)
                    else if int == 3.into() {
                        if let Value::Array(list) = v {
                            req.allow_list_len = list.len();
                            for item in list {
                                if let Value::Map(desc) = item {
                                    for (dk, dv) in desc {
                                        if let Value::Text(ref k_str) = dk {
                                            if k_str == "id" {
                                                if let Value::Bytes(id_bytes) = dv {
                                                    req.allow_list.push(id_bytes);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Key 5: options (Map: {"up": bool, "uv": bool})
                    else if int == 5.into() {
                        if let Value::Map(options) = v {
                            for (ok, ov) in options {
                                if let Value::Text(ref key) = ok {
                                    if key == "up" {
                                        if let Value::Bool(b) = ov {
                                            req.user_presence = b;
                                        }
                                    } else if key == "uv" {
                                        if let Value::Bool(b) = ov {
                                            req.user_verification = b;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    req
}

/// Extracts the relying party ID (e.g. "github.com") from a raw GetAssertion CBOR request.
#[allow(dead_code)]
pub fn extract_assertion_rp_id(raw_cbor: &[u8]) -> String {
    parse_assertion_request(raw_cbor).rp_id
}

/// Extracts the first credential descriptor from a raw GetAssertion CBOR request.
pub fn extract_first_allow_list_credential(raw_cbor: &[u8]) -> Option<(Value, Vec<u8>)> {
    if raw_cbor.len() <= 1 {
        return None;
    }
    if let Ok(Value::Map(entries)) = ciborium::from_reader(&raw_cbor[1..]) {
        for (k, v) in entries {
            if let Value::Integer(int) = k {
                // Key 3: allowList
                if int == 3.into() {
                    if let Value::Array(list) = v {
                        for item in list {
                            if let Value::Map(desc) = item {
                                for (dk, dv) in &desc {
                                    if let Value::Text(ref k_str) = dk {
                                        if k_str == "id" {
                                            if let Value::Bytes(ref id_bytes) = dv {
                                                let mut cred_map = vec![
                                                    (Value::Text("id".into()), Value::Bytes(id_bytes.clone())),
                                                    (Value::Text("type".into()), Value::Text("public-key".into())),
                                                ];
                                                sort_cbor_map(&mut cred_map);
                                                return Some((Value::Map(cred_map), id_bytes.clone()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extracts the credential ID from a CTAP2 GetAssertion response (CBOR map key 1: credential -> "id").
pub fn extract_assertion_credential_id(raw_cbor: &[u8]) -> Option<Vec<u8>> {
    let cbor_slice = if !raw_cbor.is_empty() && raw_cbor[0] == CTAP2_OK {
        &raw_cbor[1..]
    } else {
        raw_cbor
    };

    if let Ok(Value::Map(entries)) = ciborium::from_reader(cbor_slice) {
        for (k, v) in entries {
            if let Value::Integer(int) = k {
                // Key 1: credential (PublicKeyCredentialDescriptor)
                if int == 1.into() {
                    if let Value::Map(desc) = v {
                        for (dk, dv) in desc {
                            if let Value::Text(ref k_str) = dk {
                                if k_str == "id" {
                                    if let Value::Bytes(id_bytes) = dv {
                                        return Some(id_bytes);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Builds a silent GetAssertion pre-flight response for matching allowList credentials.
///
/// When a browser sends a silent probe (options: { "up": false }) to check if this security key
/// holds a credential from allowList, this function returns a synthetic CTAP 2.0 response
/// containing the matched credential descriptor.
/// This satisfies the browser's silent probe instantly without user interaction or caBLE prompts,
/// allowing the browser to immediately issue the single real, interactive GetAssertion request.
pub fn build_silent_assertion_response(rp_id: &str, cred_descriptor: Value) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let rp_id_hash = hasher.finalize();

    // 37-byte authData: 32 bytes rpIdHash + 1 byte flags (0x00) + 4 bytes counter (0)
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x00); // flags: UP=0, UV=0
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // counter

    // Dummy 64-byte signature
    let dummy_sig = vec![0u8; 64];

    let mut map = vec![
        (Value::Integer(1.into()), cred_descriptor),
        (Value::Integer(2.into()), Value::Bytes(auth_data)),
        (Value::Integer(3.into()), Value::Bytes(dummy_sig)),
    ];
    sort_cbor_map(&mut map);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).expect("Failed to serialize silent assertion");
    out
}

/// Sorts a CBOR map's key-value pairs according to RFC 7049 / RFC 8949 canonical CBOR order:
/// 1. Shorter encoded byte length sorts before longer encoded byte length.
/// 2. If encoded byte lengths are equal, lexicographical byte comparison determines order.
pub fn sort_cbor_map(entries: &mut [(Value, Value)]) {
    entries.sort_by(|(k1, _), (k2, _)| {
        let mut b1 = Vec::new();
        let mut b2 = Vec::new();
        let _ = ciborium::ser::into_writer(k1, &mut b1);
        let _ = ciborium::ser::into_writer(k2, &mut b2);
        b1.len().cmp(&b2.len()).then_with(|| b1.cmp(&b2))
    });
}

/// Extracts the relying party ID from a raw MakeCredential CBOR request.
pub fn extract_make_credential_rp_id(raw_cbor: &[u8]) -> String {
    if raw_cbor.len() > 1 {
        // Skip the first byte (CTAP_CMD_MAKE_CREDENTIAL = 0x01)
        if let Ok(Value::Map(entries)) = ciborium::from_reader(&raw_cbor[1..]) {
            for (k, v) in entries {
                if let Value::Integer(int) = k {
                    // Key 2: rp (Map with "id", "name", etc.)
                    if int == 2.into() {
                        if let Value::Map(rp_entries) = v {
                            let mut found_id = None;
                            let mut found_name = None;
                            for (rk, rv) in rp_entries {
                                if let Value::Text(ref key_str) = rk {
                                    if key_str == "id" {
                                        if let Value::Text(id) = rv {
                                            if !id.is_empty() {
                                                found_id = Some(id);
                                            }
                                        }
                                    } else if key_str == "name" {
                                        if let Value::Text(name) = rv {
                                            if !name.is_empty() {
                                                found_name = Some(name);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(id) = found_id {
                                return id;
                            }
                            if let Some(name) = found_name {
                                return name;
                            }
                        }
                    }
                }
            }
        }
    }
    "Passkey Registration".to_string()
}

/// Extracts the created credential ID from a CTAP2 MakeCredential response.
///
/// In CTAP2, the authenticatorMakeCredential response is a CBOR map containing:
/// - Key 1: fmt (Text)
/// - Key 2: authData (Bytes)
/// - Key 3: attStmt (Map)
///
/// The authData structure contains:
/// - Bytes 0..32: rpIdHash (32 bytes)
/// - Byte 32: flags (1 byte, bit 6 is AT - Attested Credential Data present)
/// - Bytes 33..37: signCount (4 bytes, big-endian)
/// - Bytes 37..53: aaguid (16 bytes)
/// - Bytes 53..55: credentialIdLength (2 bytes, big-endian u16)
/// - Bytes 55..55+L: credentialId (L bytes)
pub fn extract_make_credential_id(raw_cbor: &[u8]) -> Option<Vec<u8>> {
    let cbor_slice = if !raw_cbor.is_empty() && raw_cbor[0] == CTAP2_OK {
        &raw_cbor[1..]
    } else {
        raw_cbor
    };

    if let Ok(Value::Map(entries)) = ciborium::from_reader(cbor_slice) {
        for (k, v) in entries {
            if let Value::Integer(int) = k {
                // Key 2: authData (Bytes)
                if int == 2.into() {
                    if let Value::Bytes(auth_data) = v {
                        if auth_data.len() >= 55 {
                            let flags = auth_data[32];
                            // Check bit 6 (0x40): Attested credential data present (AT flag)
                            if (flags & 0x40) != 0 {
                                let cred_len =
                                    u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
                                if cred_len > 0 && auth_data.len() >= 55 + cred_len {
                                    return Some(auth_data[55..55 + cred_len].to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Builds a standard CTAP 2.0 / 2.1 GetInfo response indicating support for
/// passkeys with resident keys (rk), user presence (up), and user verification (uv),
/// along with batching limits so browsers do not chunk allowList into size-1 batches.
pub fn build_get_info_response() -> Vec<u8> {
    let mut map = Vec::new();

    // 0x01: versions: ["FIDO_2_0"]
    map.push((
        Value::Integer(1.into()),
        Value::Array(vec![
            Value::Text("FIDO_2_0".into()),
        ]),
    ));

    // 0x03: aaguid (16 bytes) - Apple Passkey AAGUID
    map.push((
        Value::Integer(3.into()),
        Value::Bytes(vec![
            0xf2, 0x4a, 0x8e, 0x70, 0xd0, 0xd3, 0xf8, 0x2c,
            0x29, 0x37, 0x32, 0x52, 0x3c, 0xc4, 0xde, 0x5a,
        ]),
    ));

    // 0x04: options: { "rk": true, "up": true, "uv": true }
    let mut opts = vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(true)),
    ];
    sort_cbor_map(&mut opts);
    map.push((
        Value::Integer(4.into()),
        Value::Map(opts),
    ));

    // 0x05: maxMsgSize: 1200 bytes
    map.push((
        Value::Integer(5.into()),
        Value::Integer(1200.into()),
    ));

    // 0x07: maxCredentialCountInList: 32
    // Informs the browser that the authenticator can process up to 32 credentials in allowList.
    // This prevents Chromium/Firefox from chunking allowList into size-1 batches and sending
    // silent pre-flight probes (up=false) that cause authentication failure and dummy touch fallback.
    map.push((
        Value::Integer(7.into()),
        Value::Integer(32.into()),
    ));

    // 0x08: maxCredentialIdLength: 256
    // Required alongside maxCredentialCountInList for Chromium/Firefox to enable list batching.
    map.push((
        Value::Integer(8.into()),
        Value::Integer(256.into()),
    ));

    // 0x09: transports: ["usb", "hybrid"]
    map.push((
        Value::Integer(9.into()),
        Value::Array(vec![
            Value::Text("usb".into()),
            Value::Text("hybrid".into()),
        ]),
    ));

    // 0x0A: algorithms: [{ "alg": -7, "type": "public-key" }]
    let mut alg_param = vec![
        (Value::Text("alg".into()), Value::Integer((-7).into())),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ];
    sort_cbor_map(&mut alg_param);
    map.push((
        Value::Integer(10.into()),
        Value::Array(vec![Value::Map(alg_param)]),
    ));

    sort_cbor_map(&mut map);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).expect("Failed to serialize GetInfo");
    out
}

/// Sanitizes a single PublicKeyCredentialDescriptor map for caBLE v2 transmission.
///
/// Retains only the essential fields ("id" and "type") and explicitly strips
/// transport hints (e.g. `transports: ["usb"]`).
/// When a desktop browser communicates with our virtual USB device, it generates
/// descriptors tagged with `transports: ["usb"]`. If forwarded untouched over caBLE,
/// the iOS authenticator rejects the credential as incompatible with the hybrid transport,
/// causing the phone to report "No passkeys found".
pub fn sanitize_credential_descriptor(desc: &Value) -> Option<Value> {
    if let Value::Map(entries) = desc {
        let mut id_val = None;
        let mut type_val = None;

        for (k, v) in entries {
            if let Value::Text(ref k_str) = k {
                match k_str.as_str() {
                    "id" => id_val = Some(v.clone()),
                    "type" => type_val = Some(v.clone()),
                    _ => {} // Drop transports and any non-standard/hint fields
                }
            }
        }

        if let Some(id) = id_val {
            let cred_type = type_val.unwrap_or_else(|| Value::Text("public-key".into()));
            let mut sanitized = vec![
                (Value::Text("id".into()), id),
                (Value::Text("type".into()), cred_type),
            ];
            sort_cbor_map(&mut sanitized);
            Some(Value::Map(sanitized))
        } else {
            None
        }
    } else {
        None
    }
}

/// Prepares and sanitizes a MakeCredential request for transmission over a caBLE v2 tunnel.
///
/// Ensures compliance with strict CTAP 2.0 authenticators (such as Apple Passkeys on iOS):
/// 1. Drops extensions (key 6) entirely, as caBLE authenticators do not advertise or support
///    extensions and abort validation if unexpected extensions (e.g. "hmac-secret: false") are provided.
/// 2. Ensures pubKeyCredParams (key 4) offers ES256 (alg: -7, COSE P-256), the only algorithm
///    supported by Apple Passkeys on iOS Secure Enclave.
/// 3. Normalizes rp (key 2) to ensure both "id" and "name" exist, avoiding missing name failures on iOS.
/// 4. Normalizes user (key 3) to ensure "id", "name", and "displayName" exist, ensuring the iOS passkey
///    sheet has the required account metadata to display.
/// 5. Ensures options (key 7) contains {"rk": true, "uv": true} without "up" or non-standard options.
/// 6. Orders all maps using RFC 7049 canonical CBOR rules (length-first then lexicographical byte order).
pub fn prepare_make_credential_for_cable(raw_cbor: &[u8]) -> (Vec<u8>, String) {
    if raw_cbor.len() <= 1 {
        return (raw_cbor.to_vec(), "Empty or truncated".to_string());
    }

    let cmd_byte = raw_cbor[0];
    let payload = &raw_cbor[1..];

    let mut summary = String::new();

    let val: Result<Value, _> = ciborium::from_reader(payload);
    let mut entries = match val {
        Ok(Value::Map(m)) => m,
        Ok(other) => {
            return (
                raw_cbor.to_vec(),
                format!("Unexpected top-level CBOR type: {:?}", other),
            );
        }
        Err(e) => {
            return (
                raw_cbor.to_vec(),
                format!("Failed to parse CBOR payload: {:?}", e),
            );
        }
    };

    let mut new_entries = Vec::new();
    let mut options_found = false;

    for (k, v) in entries.drain(..) {
        if let Value::Integer(ref int) = k {
            let key_num: i128 = (*int).into();
            match key_num {
                1 => {
                    // Key 1: clientDataHash (32 bytes)
                    if let Value::Bytes(ref b) = v {
                        summary.push_str(&format!("clientDataHash({}B) ", b.len()));
                    }
                    new_entries.push((k, v));
                }
                2 => {
                    // Key 2: rp (PublicKeyCredentialRpEntity)
                    let mut rp_map = match v {
                        Value::Map(m) => m,
                        _ => Vec::new(),
                    };

                    let mut id_val = None;
                    let mut name_val = None;
                    let mut other_rp = Vec::new();

                    for (rk, rv) in rp_map.drain(..) {
                        if let Value::Text(ref k_str) = rk {
                            match k_str.as_str() {
                                "id" => id_val = Some(rv),
                                "name" => name_val = Some(rv),
                                _ => other_rp.push((rk, rv)),
                            }
                        } else {
                            other_rp.push((rk, rv));
                        }
                    }

                    let id_str = match id_val {
                        Some(Value::Text(s)) if !s.is_empty() => s,
                        _ => match &name_val {
                            Some(Value::Text(s)) if !s.is_empty() => s.clone(),
                            _ => "webauthn".to_string(),
                        },
                    };

                    let name_str = match name_val {
                        Some(Value::Text(s)) if !s.is_empty() => s,
                        _ => id_str.clone(),
                    };

                    summary.push_str(&format!("rpId='{}' rpName='{}' ", id_str, name_str));

                    let mut clean_rp = vec![
                        (Value::Text("id".into()), Value::Text(id_str)),
                        (Value::Text("name".into()), Value::Text(name_str)),
                    ];
                    clean_rp.extend(other_rp);
                    sort_cbor_map(&mut clean_rp);

                    new_entries.push((k, Value::Map(clean_rp)));
                }
                3 => {
                    // Key 3: user (PublicKeyCredentialUserEntity)
                    let mut user_map = match v {
                        Value::Map(m) => m,
                        _ => Vec::new(),
                    };

                    let mut id_val = None;
                    let mut name_val = None;
                    let mut display_name_val = None;
                    let mut other_user = Vec::new();

                    for (uk, uv) in user_map.drain(..) {
                        if let Value::Text(ref k_str) = uk {
                            match k_str.as_str() {
                                "id" => id_val = Some(uv),
                                "name" => name_val = Some(uv),
                                "displayName" => display_name_val = Some(uv),
                                _ => other_user.push((uk, uv)),
                            }
                        } else {
                            other_user.push((uk, uv));
                        }
                    }

                    let final_name = match name_val {
                        Some(Value::Text(s)) if !s.is_empty() => s,
                        _ => match &display_name_val {
                            Some(Value::Text(s)) if !s.is_empty() => s.clone(),
                            _ => "user".to_string(),
                        },
                    };

                    let final_display_name = match display_name_val {
                        Some(Value::Text(s)) if !s.is_empty() => s,
                        _ => final_name.clone(),
                    };

                    let final_id = id_val.unwrap_or_else(|| Value::Bytes(final_name.as_bytes().to_vec()));

                    summary.push_str(&format!("user='{}' displayName='{}' ", final_name, final_display_name));

                    let mut clean_user = vec![
                        (Value::Text("id".into()), final_id),
                        (Value::Text("name".into()), Value::Text(final_name)),
                        (Value::Text("displayName".into()), Value::Text(final_display_name)),
                    ];
                    clean_user.extend(other_user);
                    sort_cbor_map(&mut clean_user);

                    new_entries.push((k, Value::Map(clean_user)));
                }
                4 => {
                    // Key 4: pubKeyCredParams (PublicKeyCredentialParameters[])
                    // Apple iOS Secure Enclave exclusively supports ES256 (alg: -7, COSE P-256).
                    // If the RP offered ES256 (-7), prioritize it and filter down to ES256.
                    // If ES256 is not offered, preserve the RP's requested parameters.
                    let mut has_es256 = false;
                    if let Value::Array(ref params) = v {
                        for p in params {
                            if let Value::Map(ref fields) = p {
                                for (fk, fv) in fields {
                                    if let Value::Text(ref key) = fk {
                                        if key == "alg" {
                                            if let Value::Integer(int) = fv {
                                                if *int == (-7).into() {
                                                    has_es256 = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if has_es256 {
                        let mut es256_param = vec![
                            (Value::Text("alg".into()), Value::Integer((-7).into())),
                            (Value::Text("type".into()), Value::Text("public-key".into())),
                        ];
                        sort_cbor_map(&mut es256_param);
                        summary.push_str("credParams=[ES256] ");
                        new_entries.push((k, Value::Array(vec![Value::Map(es256_param)])));
                    } else {
                        summary.push_str("credParams=[original] ");
                        new_entries.push((k, v));
                    }
                }
                5 => {
                    // Key 5: excludeList (PublicKeyCredentialDescriptor[])
                    // Sanitize descriptors to strip transport hints (e.g. transports: ["usb"])
                    if let Value::Array(list) = v {
                        let mut sanitized_list = Vec::new();
                        for item in list {
                            if let Some(sanitized_desc) = sanitize_credential_descriptor(&item) {
                                sanitized_list.push(sanitized_desc);
                            }
                        }
                        if !sanitized_list.is_empty() {
                            summary.push_str(&format!("excludeList({} items, transports stripped) ", sanitized_list.len()));
                            new_entries.push((k, Value::Array(sanitized_list)));
                        }
                    }
                }
                6 => {
                    // Key 6: extensions (Map)
                    // MUST be dropped for caBLE: phone GetInfo has no extensions, and strict parsers fail on unknown/unexpected extensions.
                    summary.push_str("extensions(dropped) ");
                }
                7 => {
                    // Key 7: options (Map: {"rk": bool, "uv": bool})
                    options_found = true;
                    summary.push_str("options={rk:true, uv:true} ");
                    let mut opts = vec![
                        (Value::Text("rk".into()), Value::Bool(true)),
                        (Value::Text("uv".into()), Value::Bool(true)),
                    ];
                    sort_cbor_map(&mut opts);
                    new_entries.push((k, Value::Map(opts)));
                }
                _ => {
                    // Non-standard keys (pinAuth etc.) dropped for caBLE tunnel
                }
            }
        }
    }

    if !options_found {
        summary.push_str("options={rk:true, uv:true} (injected) ");
        let mut opts = vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(true)),
        ];
        sort_cbor_map(&mut opts);
        new_entries.push((Value::Integer(7.into()), Value::Map(opts)));
    }

    sort_cbor_map(&mut new_entries);

    let mut sanitized_payload = vec![cmd_byte];
    if let Err(e) = ciborium::ser::into_writer(&Value::Map(new_entries), &mut sanitized_payload) {
        return (
            raw_cbor.to_vec(),
            format!("Serialization error: {:?}; using original", e),
        );
    }

    (sanitized_payload, summary)
}

/// Prepares and sanitizes a GetAssertion request for transmission over a caBLE v2 tunnel.
///
/// Ensures compliance with strict CTAP 2.0 authenticators:
/// 1. Drops extensions (key 4) entirely, as caBLE authenticators do not support extensions.
/// 2. Ensures options (key 5) contains {"up": true, "uv": bool}.
/// 3. Orders all maps using canonical CBOR rules.
pub fn prepare_get_assertion_for_cable(raw_cbor: &[u8]) -> (Vec<u8>, String) {
    if raw_cbor.len() <= 1 {
        return (raw_cbor.to_vec(), "Empty or truncated".to_string());
    }

    let cmd_byte = raw_cbor[0];
    let payload = &raw_cbor[1..];

    let mut summary = String::new();

    let val: Result<Value, _> = ciborium::from_reader(payload);
    let mut entries = match val {
        Ok(Value::Map(m)) => m,
        Ok(other) => {
            return (
                raw_cbor.to_vec(),
                format!("Unexpected top-level CBOR type: {:?}", other),
            );
        }
        Err(e) => {
            return (
                raw_cbor.to_vec(),
                format!("Failed to parse CBOR payload: {:?}", e),
            );
        }
    };

    let mut new_entries = Vec::new();
    let mut uv_requested = true;

    for (k, v) in entries.drain(..) {
        if let Value::Integer(ref int) = k {
            let key_num: i128 = (*int).into();
            match key_num {
                1 => {
                    // Key 1: rpId (String)
                    if let Value::Text(ref s) = v {
                        summary.push_str(&format!("rpId='{}' ", s));
                    }
                    new_entries.push((k, v));
                }
                2 => {
                    // Key 2: clientDataHash (Bytes)
                    if let Value::Bytes(ref b) = v {
                        summary.push_str(&format!("clientDataHash({}B) ", b.len()));
                    }
                    new_entries.push((k, v));
                }
                3 => {
                    // Key 3: allowList (Array of PublicKeyCredentialDescriptor)
                    // Sanitize descriptors to strip transport hints (e.g. transports: ["usb"])
                    if let Value::Array(list) = v {
                        let mut sanitized_list = Vec::new();
                        for item in list {
                            if let Some(sanitized_desc) = sanitize_credential_descriptor(&item) {
                                sanitized_list.push(sanitized_desc);
                            }
                        }
                        if !sanitized_list.is_empty() {
                            summary.push_str(&format!("allowList({} items, transports stripped) ", sanitized_list.len()));
                            new_entries.push((k, Value::Array(sanitized_list)));
                        }
                    }
                }
                4 => {
                    // Key 4: extensions (Map) - dropped for caBLE
                    summary.push_str("extensions(dropped) ");
                }
                5 => {
                    // Key 5: options (Map: {"up": bool, "uv": bool})
                    if let Value::Map(ref opts) = v {
                        for (ok, ov) in opts {
                            if let (Value::Text(k_str), Value::Bool(b)) = (ok, ov) {
                                if k_str == "uv" {
                                    uv_requested = *b;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut opts = vec![
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(uv_requested)),
    ];
    sort_cbor_map(&mut opts);
    summary.push_str(&format!("options={{up:true, uv:{}}} ", uv_requested));
    new_entries.push((Value::Integer(5.into()), Value::Map(opts)));

    sort_cbor_map(&mut new_entries);

    let mut sanitized_payload = vec![cmd_byte];
    if let Err(e) = ciborium::ser::into_writer(&Value::Map(new_entries), &mut sanitized_payload) {
        return (
            raw_cbor.to_vec(),
            format!("Serialization error: {:?}; using original", e),
        );
    }

    (sanitized_payload, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_assertion_rp_id() {
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("github.com".into())));
        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let rp_id = extract_assertion_rp_id(&cbor);
        assert_eq!(rp_id, "github.com");

        assert_eq!(extract_assertion_rp_id(&[]), "Passkey Authentication");
        assert_eq!(extract_assertion_rp_id(&[0x02, 0xff]), "Passkey Authentication");
    }

    #[test]
    fn test_extract_make_credential_rp_id() {
        let mut rp_map = Vec::new();
        rp_map.push((Value::Text("id".into()), Value::Text("webauthn.io".into())));
        let mut map = Vec::new();
        map.push((Value::Integer(2.into()), Value::Map(rp_map)));

        let mut cbor = vec![CTAP_CMD_MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let rp_id = extract_make_credential_rp_id(&cbor);
        assert_eq!(rp_id, "webauthn.io");

        assert_eq!(extract_make_credential_rp_id(&[]), "Passkey Registration");
    }

    #[test]
    fn test_get_info_response() {
        let resp = build_get_info_response();
        assert!(!resp.is_empty());
        let val: Value = ciborium::from_reader(&resp[..]).expect("Valid CBOR");
        if let Value::Map(entries) = val {
            assert!(entries.len() >= 4);
        } else {
            panic!("Expected CBOR Map in GetInfo");
        }
    }

    #[test]
    fn test_parse_assertion_request_up_false() {
        let mut opt_map = Vec::new();
        opt_map.push((Value::Text("up".into()), Value::Bool(false)));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(5.into()), Value::Map(opt_map)));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let req = parse_assertion_request(&cbor);
        assert_eq!(req.rp_id, "webauthn.io");
        assert!(!req.user_presence);
        assert_eq!(req.allow_list_len, 0);
    }

    #[test]
    fn test_parse_assertion_request_default_up_true() {
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("github.com".into())));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let req = parse_assertion_request(&cbor);
        assert_eq!(req.rp_id, "github.com");
        assert!(req.user_presence);
    }

    #[test]
    fn test_prepare_make_credential_for_cable() {
        // Construct a request matching the exact wire payload from Firefox on webauthn.io:
        // - Key 1: clientDataHash (32 bytes)
        // - Key 2: rp { "id": "webauthn.io" } (missing name!)
        // - Key 3: user { "id": b"webauthnio-test", "name": "test" } (missing displayName!)
        // - Key 4: pubKeyCredParams [ {alg: -8, type: "public-key"}, {alg: -7, type: "public-key"}, {alg: -257, type: "public-key"} ]
        // - Key 6: extensions { "hmac-secret": false }
        // - Key 7: options { "rk": true, "up": true, "plat": false }
        let mut rp_map = Vec::new();
        rp_map.push((Value::Text("id".into()), Value::Text("webauthn.io".into())));

        let mut user_map = Vec::new();
        user_map.push((Value::Text("id".into()), Value::Bytes(b"webauthnio-test".to_vec())));
        user_map.push((Value::Text("name".into()), Value::Text("test".into())));

        let params = vec![
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-8).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
            Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-257).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]),
        ];

        let mut ext_map = Vec::new();
        ext_map.push((Value::Text("hmac-secret".into()), Value::Bool(false)));

        let mut opt_map = Vec::new();
        opt_map.push((Value::Text("rk".into()), Value::Bool(true)));
        opt_map.push((Value::Text("up".into()), Value::Bool(true)));
        opt_map.push((Value::Text("plat".into()), Value::Bool(false)));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Bytes(vec![0xAA; 32])));
        map.push((Value::Integer(2.into()), Value::Map(rp_map)));
        map.push((Value::Integer(3.into()), Value::Map(user_map)));
        map.push((Value::Integer(4.into()), Value::Array(params)));
        map.push((Value::Integer(6.into()), Value::Map(ext_map)));
        map.push((Value::Integer(7.into()), Value::Map(opt_map)));

        let mut cbor = vec![CTAP_CMD_MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let (sanitized, summary) = prepare_make_credential_for_cable(&cbor);
        assert_eq!(sanitized[0], CTAP_CMD_MAKE_CREDENTIAL);
        assert!(summary.contains("rpId='webauthn.io'"));
        assert!(summary.contains("rpName='webauthn.io'"));
        assert!(summary.contains("user='test'"));
        assert!(summary.contains("displayName='test'"));
        assert!(summary.contains("credParams=[ES256]"));
        assert!(summary.contains("extensions(dropped)"));
        assert!(summary.contains("options={rk:true, uv:true}"));

        // Verify the sanitized CBOR structure
        let val: Value = ciborium::from_reader(&sanitized[1..]).unwrap();
        if let Value::Map(entries) = val {
            // Key 6 (extensions) MUST be dropped completely
            assert!(!entries.iter().any(|(k, _)| *k == Value::Integer(6.into())));

            // Key 2 (rp) must contain both id and name
            let rp_entry = entries.iter().find(|(k, _)| *k == Value::Integer(2.into())).unwrap();
            if let Value::Map(ref rp) = rp_entry.1 {
                assert!(rp.iter().any(|(k, v)| *k == Value::Text("id".into()) && *v == Value::Text("webauthn.io".into())));
                assert!(rp.iter().any(|(k, v)| *k == Value::Text("name".into()) && *v == Value::Text("webauthn.io".into())));
            } else {
                panic!("Expected rp Map");
            }

            // Key 3 (user) must contain id, name, and displayName
            let user_entry = entries.iter().find(|(k, _)| *k == Value::Integer(3.into())).unwrap();
            if let Value::Map(ref user) = user_entry.1 {
                assert!(user.iter().any(|(k, v)| *k == Value::Text("name".into()) && *v == Value::Text("test".into())));
                assert!(user.iter().any(|(k, v)| *k == Value::Text("displayName".into()) && *v == Value::Text("test".into())));
                assert!(user.iter().any(|(k, v)| *k == Value::Text("id".into()) && *v == Value::Bytes(b"webauthnio-test".to_vec())));
            } else {
                panic!("Expected user Map");
            }

            // Key 4 (pubKeyCredParams) must contain exclusively ES256 (-7)
            let params_entry = entries.iter().find(|(k, _)| *k == Value::Integer(4.into())).unwrap();
            if let Value::Array(ref params) = params_entry.1 {
                assert_eq!(params.len(), 1);
                if let Value::Map(ref p) = params[0] {
                    assert!(p.iter().any(|(k, v)| *k == Value::Text("alg".into()) && *v == Value::Integer((-7).into())));
                    assert!(p.iter().any(|(k, v)| *k == Value::Text("type".into()) && *v == Value::Text("public-key".into())));
                } else {
                    panic!("Expected param Map");
                }
            } else {
                panic!("Expected params Array");
            }

            // Key 7 (options) must ONLY contain "rk" and "uv"
            let options_entry = entries.iter().find(|(k, _)| *k == Value::Integer(7.into())).unwrap();
            if let Value::Map(ref opts) = options_entry.1 {
                assert_eq!(opts.len(), 2);
                assert!(opts.iter().any(|(k, v)| *k == Value::Text("rk".into()) && *v == Value::Bool(true)));
                assert!(opts.iter().any(|(k, v)| *k == Value::Text("uv".into()) && *v == Value::Bool(true)));
                assert!(!opts.iter().any(|(k, _)| *k == Value::Text("up".into())));
                assert!(!opts.iter().any(|(k, _)| *k == Value::Text("plat".into())));
            } else {
                panic!("Expected options Map");
            }

            // Verify canonical key ordering: 1, 2, 3, 4, 7
            let key_nums: Vec<i128> = entries.iter().map(|(k, _)| {
                if let Value::Integer(i) = k {
                    (*i).into()
                } else {
                    -1
                }
            }).collect();
            assert_eq!(key_nums, vec![1, 2, 3, 4, 7]);
        } else {
            panic!("Expected CBOR map");
        }
    }

    #[test]
    fn test_prepare_get_assertion_for_cable() {
        let mut ext_map = Vec::new();
        ext_map.push((Value::Text("hmac-secret".into()), Value::Bool(false)));

        let mut opt_map = Vec::new();
        opt_map.push((Value::Text("up".into()), Value::Bool(true)));
        opt_map.push((Value::Text("uv".into()), Value::Bool(true)));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(2.into()), Value::Bytes(vec![0xBB; 32])));
        map.push((Value::Integer(4.into()), Value::Map(ext_map)));
        map.push((Value::Integer(5.into()), Value::Map(opt_map)));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let (sanitized, summary) = prepare_get_assertion_for_cable(&cbor);
        assert_eq!(sanitized[0], CTAP_CMD_GET_ASSERTION);
        assert!(summary.contains("rpId='webauthn.io'"));
        assert!(summary.contains("extensions(dropped)"));

        let val: Value = ciborium::from_reader(&sanitized[1..]).unwrap();
        if let Value::Map(entries) = val {
            assert!(!entries.iter().any(|(k, _)| *k == Value::Integer(4.into())));
            let key_nums: Vec<i128> = entries.iter().map(|(k, _)| {
                if let Value::Integer(i) = k {
                    (*i).into()
                } else {
                    -1
                }
            }).collect();
            assert_eq!(key_nums, vec![1, 2, 5]);
        } else {
            panic!("Expected CBOR Map");
        }
    }

    #[test]
    fn test_extract_first_allow_list_credential() {
        let cred_id = vec![0x11, 0x22, 0x33, 0x44];
        let mut desc = Vec::new();
        desc.push((Value::Text("id".into()), Value::Bytes(cred_id.clone())));
        desc.push((Value::Text("type".into()), Value::Text("public-key".into())));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(3.into()), Value::Array(vec![Value::Map(desc)])));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let extracted = extract_first_allow_list_credential(&cbor);
        assert!(extracted.is_some());
        let (desc_val, extracted_id) = extracted.unwrap();
        assert_eq!(extracted_id, cred_id);
        if let Value::Map(entries) = desc_val {
            assert!(entries.iter().any(|(k, v)| *k == Value::Text("id".into()) && *v == Value::Bytes(cred_id.clone())));
        } else {
            panic!("Expected Map in credential descriptor");
        }
    }

    #[test]
    fn test_build_silent_assertion_response() {
        let cred_desc = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);
        let resp = build_silent_assertion_response("webauthn.io", cred_desc);
        assert!(!resp.is_empty());
        let val: Value = ciborium::from_reader(&resp[..]).expect("Valid CBOR");
        if let Value::Map(entries) = val {
            assert_eq!(entries.len(), 3);
            assert!(entries.iter().any(|(k, _)| *k == Value::Integer(1.into())));
            assert!(entries.iter().any(|(k, _)| *k == Value::Integer(2.into())));
            assert!(entries.iter().any(|(k, _)| *k == Value::Integer(3.into())));
        } else {
            panic!("Expected CBOR Map");
        }
    }

    #[test]
    fn test_extract_assertion_credential_id() {
        let cred_id = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut desc = Vec::new();
        desc.push((Value::Text("id".into()), Value::Bytes(cred_id.clone())));
        desc.push((Value::Text("type".into()), Value::Text("public-key".into())));

        let mut resp_map = Vec::new();
        resp_map.push((Value::Integer(1.into()), Value::Map(desc)));
        resp_map.push((Value::Integer(2.into()), Value::Bytes(vec![0xAA; 37]))); // authData
        resp_map.push((Value::Integer(3.into()), Value::Bytes(vec![0xBB; 64]))); // signature

        let mut cbor = vec![CTAP2_OK]; // Prepend 0x00 status byte
        ciborium::ser::into_writer(&Value::Map(resp_map), &mut cbor).unwrap();

        let extracted = extract_assertion_credential_id(&cbor);
        assert_eq!(extracted, Some(cred_id));

        // Test without status byte
        let extracted_no_status = extract_assertion_credential_id(&cbor[1..]);
        assert_eq!(extracted_no_status, extracted);
    }

    #[test]
    fn test_parse_assertion_request_allow_list() {
        let cred1 = vec![1, 2, 3];
        let cred2 = vec![4, 5, 6];
        let desc1 = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(cred1.clone())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);
        let desc2 = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(cred2.clone())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(3.into()), Value::Array(vec![desc1, desc2])));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let req = parse_assertion_request(&cbor);
        assert_eq!(req.rp_id, "webauthn.io");
        assert_eq!(req.allow_list_len, 2);
        assert_eq!(req.allow_list, vec![cred1, cred2]);
    }

    #[test]
    fn test_sanitize_credential_descriptor() {
        let mut desc_map = Vec::new();
        desc_map.push((Value::Text("id".into()), Value::Bytes(vec![1, 2, 3, 4])));
        desc_map.push((Value::Text("type".into()), Value::Text("public-key".into())));
        desc_map.push((Value::Text("transports".into()), Value::Array(vec![
            Value::Text("usb".into()),
            Value::Text("ble".into()),
        ])));

        let sanitized = sanitize_credential_descriptor(&Value::Map(desc_map)).expect("Sanitized descriptor");
        if let Value::Map(entries) = sanitized {
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().any(|(k, v)| *k == Value::Text("id".into()) && *v == Value::Bytes(vec![1, 2, 3, 4])));
            assert!(entries.iter().any(|(k, v)| *k == Value::Text("type".into()) && *v == Value::Text("public-key".into())));
            assert!(!entries.iter().any(|(k, _)| *k == Value::Text("transports".into())));
        } else {
            panic!("Expected CBOR Map");
        }
    }

    #[test]
    fn test_prepare_get_assertion_strips_transports_from_allow_list() {
        let cred_id = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut desc = Vec::new();
        desc.push((Value::Text("id".into()), Value::Bytes(cred_id.clone())));
        desc.push((Value::Text("type".into()), Value::Text("public-key".into())));
        desc.push((Value::Text("transports".into()), Value::Array(vec![Value::Text("usb".into())])));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(2.into()), Value::Bytes(vec![0x11; 32])));
        map.push((Value::Integer(3.into()), Value::Array(vec![Value::Map(desc)])));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let (sanitized, summary) = prepare_get_assertion_for_cable(&cbor);
        assert!(summary.contains("allowList(1 items, transports stripped)"));

        let val: Value = ciborium::from_reader(&sanitized[1..]).unwrap();
        if let Value::Map(entries) = val {
            let allow_list_entry = entries.iter().find(|(k, _)| *k == Value::Integer(3.into())).unwrap();
            if let Value::Array(ref list) = allow_list_entry.1 {
                assert_eq!(list.len(), 1);
                if let Value::Map(ref d) = list[0] {
                    assert_eq!(d.len(), 2);
                    assert!(d.iter().any(|(k, v)| *k == Value::Text("id".into()) && *v == Value::Bytes(cred_id.clone())));
                    assert!(d.iter().any(|(k, v)| *k == Value::Text("type".into()) && *v == Value::Text("public-key".into())));
                    assert!(!d.iter().any(|(k, _)| *k == Value::Text("transports".into())));
                } else {
                    panic!("Expected descriptor map");
                }
            } else {
                panic!("Expected allowList array");
            }
        } else {
            panic!("Expected CBOR map");
        }
    }

    #[test]
    fn test_prepare_make_credential_strips_transports_from_exclude_list() {
        let cred_id = vec![0x12, 0x34, 0x56];
        let mut desc = Vec::new();
        desc.push((Value::Text("id".into()), Value::Bytes(cred_id.clone())));
        desc.push((Value::Text("type".into()), Value::Text("public-key".into())));
        desc.push((Value::Text("transports".into()), Value::Array(vec![Value::Text("usb".into())])));

        let mut rp_map = Vec::new();
        rp_map.push((Value::Text("id".into()), Value::Text("webauthn.io".into())));

        let mut user_map = Vec::new();
        user_map.push((Value::Text("id".into()), Value::Bytes(b"user1".to_vec())));

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Bytes(vec![0xAA; 32])));
        map.push((Value::Integer(2.into()), Value::Map(rp_map)));
        map.push((Value::Integer(3.into()), Value::Map(user_map)));
        map.push((Value::Integer(5.into()), Value::Array(vec![Value::Map(desc)])));

        let mut cbor = vec![CTAP_CMD_MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let (sanitized, summary) = prepare_make_credential_for_cable(&cbor);
        assert!(summary.contains("excludeList(1 items, transports stripped)"));

        let val: Value = ciborium::from_reader(&sanitized[1..]).unwrap();
        if let Value::Map(entries) = val {
            let exclude_entry = entries.iter().find(|(k, _)| *k == Value::Integer(5.into())).unwrap();
            if let Value::Array(ref list) = exclude_entry.1 {
                assert_eq!(list.len(), 1);
                if let Value::Map(ref d) = list[0] {
                    assert_eq!(d.len(), 2);
                    assert!(!d.iter().any(|(k, _)| *k == Value::Text("transports".into())));
                } else {
                    panic!("Expected descriptor map");
                }
            }
        }
    }

    #[test]
    fn test_extract_make_credential_id() {
        let cred_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0x11; 32]); // rpIdHash (32 bytes)
        auth_data.push(0x45); // flags: UP=1, UV=1, AT=1 (bit 6)
        auth_data.extend_from_slice(&[0, 0, 0, 1]); // signCount (4 bytes)
        auth_data.extend_from_slice(&[0x22; 16]); // aaguid (16 bytes)
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes()); // credIdLen (2 bytes)
        auth_data.extend_from_slice(&cred_id); // credId
        auth_data.extend_from_slice(&[0xA1, 0x01, 0x02]); // dummy COSE key bytes

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("packed".into())));
        map.push((Value::Integer(2.into()), Value::Bytes(auth_data)));
        map.push((Value::Integer(3.into()), Value::Map(Vec::new())));

        let mut cbor_with_status = vec![CTAP2_OK];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor_with_status).unwrap();

        let extracted = extract_make_credential_id(&cbor_with_status);
        assert_eq!(extracted, Some(cred_id.clone()));

        // Test without CTAP2_OK status byte prefix
        let extracted_no_status = extract_make_credential_id(&cbor_with_status[1..]);
        assert_eq!(extracted_no_status, Some(cred_id));

        // Test with AT flag not set (0x05 instead of 0x45)
        let mut no_at_auth_data = vec![0x11; 32];
        no_at_auth_data.push(0x05); // No AT flag
        no_at_auth_data.extend_from_slice(&[0; 4]);
        let mut no_at_map = Vec::new();
        no_at_map.push((Value::Integer(2.into()), Value::Bytes(no_at_auth_data)));
        let mut no_at_cbor = Vec::new();
        ciborium::ser::into_writer(&Value::Map(no_at_map), &mut no_at_cbor).unwrap();
        assert_eq!(extract_make_credential_id(&no_at_cbor), None);
    }

    #[test]
    fn test_prepare_make_credential_preserves_non_es256_params() {
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Bytes(vec![0xAA; 32])));
        let mut rp_map = Vec::new();
        rp_map.push((Value::Text("id".into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(2.into()), Value::Map(rp_map)));
        let mut user_map = Vec::new();
        user_map.push((Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])));
        user_map.push((Value::Text("name".into()), Value::Text("test".into())));
        map.push((Value::Integer(3.into()), Value::Map(user_map)));

        // Request only RS256 (-257), no ES256 (-7)
        let mut param = Vec::new();
        param.push((Value::Text("alg".into()), Value::Integer((-257).into())));
        param.push((Value::Text("type".into()), Value::Text("public-key".into())));
        map.push((Value::Integer(4.into()), Value::Array(vec![Value::Map(param)])));

        let mut cbor = vec![CTAP_CMD_MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let (sanitized, summary) = prepare_make_credential_for_cable(&cbor);
        assert!(summary.contains("credParams=[original]"));

        // Verify RS256 is preserved in CBOR
        let val: Value = ciborium::from_reader(&sanitized[1..]).unwrap();
        if let Value::Map(entries) = val {
            let (_, params_val) = entries.iter().find(|(k, _)| *k == Value::Integer(4.into())).unwrap();
            if let Value::Array(ref p_arr) = params_val {
                assert_eq!(p_arr.len(), 1);
                if let Value::Map(ref fields) = p_arr[0] {
                    let (_, alg_val) = fields.iter().find(|(k, _)| *k == Value::Text("alg".into())).unwrap();
                    assert_eq!(*alg_val, Value::Integer((-257).into()));
                }
            }
        }
    }

    #[test]
    fn test_parse_assertion_request_extracts_client_data_hash() {
        let hash = vec![0x42; 32];
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text("webauthn.io".into())));
        map.push((Value::Integer(2.into()), Value::Bytes(hash.clone())));

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();

        let req = parse_assertion_request(&cbor);
        assert_eq!(req.rp_id, "webauthn.io");
        assert_eq!(req.client_data_hash, hash);
    }
}

