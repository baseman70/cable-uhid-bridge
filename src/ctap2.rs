use ciborium::value::Value;

pub const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
pub const CTAP_CMD_GET_INFO: u8 = 0x04;

pub const CTAP2_OK: u8 = 0x00;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;

/// Builds a standard CTAP 2.1 GetInfo response indicating support for
/// modern passkeys with resident keys (rk) and user verification (uv).
pub fn build_get_info_response() -> Vec<u8> {
    let mut map = Vec::new();

    // 0x01: versions: ["FIDO_2_0", "FIDO_2_1"]
    map.push((
        Value::Integer(1.into()),
        Value::Array(vec![
            Value::Text("FIDO_2_0".into()),
            Value::Text("FIDO_2_1".into()),
        ]),
    ));

    // 0x02: extensions: ["largeBlob", "prf"]
    map.push((
        Value::Integer(2.into()),
        Value::Array(vec![
            Value::Text("largeBlob".into()),
            Value::Text("prf".into()),
        ]),
    ));

    // 0x03: aaguid (16 bytes)
    map.push((
        Value::Integer(3.into()),
        Value::Bytes(vec![
            0xf2, 0x4a, 0x8e, 0x70, 0xd0, 0xd3, 0xf8, 0x2c,
            0x29, 0x37, 0x32, 0x52, 0x3c, 0xc4, 0xde, 0x5a,
        ]),
    ));

    // 0x04: options: { "rk": true, "up": true, "uv": true, "plat": false }
    map.push((
        Value::Integer(4.into()),
        Value::Map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(true)),
            (Value::Text("plat".into()), Value::Bool(false)),
        ]),
    ));

    // 0x05: maxMsgSize: 1200 bytes
    map.push((
        Value::Integer(5.into()),
        Value::Integer(1200.into()),
    ));

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).expect("Failed to serialize GetInfo");
    out
}
