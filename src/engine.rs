use std::time::{Duration, Instant};
use webauthn_authenticator_rs::types::CableRequestType;

use crate::ctap2::*;

/// Represents an assertion cached in memory to support two-stage
/// multi-credential selection (where the browser first requests an assertion,
/// then immediately sends a targeted second assertion for the chosen credential)
/// without prompting the user on their phone a second time.
#[derive(Debug, Clone)]
pub struct CachedAssertion {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub credential_id: Option<Vec<u8>>,
    pub response: Vec<u8>,
    pub created_at: Instant,
}

impl CachedAssertion {
    pub fn new(
        rp_id: String,
        client_data_hash: Vec<u8>,
        credential_id: Option<Vec<u8>>,
        response: Vec<u8>,
    ) -> Self {
        Self {
            rp_id,
            client_data_hash,
            credential_id,
            response,
            created_at: Instant::now(),
        }
    }

    /// Checks if this cached assertion satisfies an incoming GetAssertion request.
    pub fn matches(&self, req: &AssertionRequest, max_age: Duration) -> bool {
        if self.created_at.elapsed() > max_age {
            return false;
        }
        if self.rp_id != req.rp_id {
            return false;
        }
        // If client_data_hash is present in either, ensure they match cryptographically
        if !self.client_data_hash.is_empty()
            && !req.client_data_hash.is_empty()
            && self.client_data_hash != req.client_data_hash
        {
            return false;
        }
        // If the request specifies allowList credentials, verify our cached credential matches
        if !req.allow_list.is_empty() {
            if let Some(ref cached_id) = self.credential_id {
                return req.allow_list.iter().any(|id| id == cached_id);
            }
        }
        true
    }
}

/// Action to be taken by the transport layer in response to a CBOR command.
#[derive(Debug, PartialEq, Eq)]
pub enum EngineCborAction {
    /// Send CTAP status byte directly (e.g. CTAP2_ERR_OPERATION_DENIED or CTAP2_ERR_KEEPALIVE_CANCEL)
    SendStatus(u8),
    /// Send CTAP2_OK (0x00) with CBOR payload
    SendResponse(Vec<u8>),
    /// caBLE transaction needed
    StartCableTransaction {
        req_type: CableRequestType,
        rp_id: String,
        cable_payload: Vec<u8>,
    },
    /// Request was empty or unparseable, ignore
    Ignore,
}

/// Result of a completed or aborted transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum TransactionResult {
    Success(Vec<u8>),
    UserCancelled,
    HostCancelled,
    HostReset,
    Failed(String),
}

/// The core bridge engine and state machine.
pub struct BridgeEngine {
    pub last_cancelled: Option<Instant>,
    pub cooldown_duration: Duration,
    pub assertion_cache: Option<CachedAssertion>,
    pub cache_ttl: Duration,
    pub pending_client_data_hash: Vec<u8>,
}

impl Default for BridgeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeEngine {
    pub fn new() -> Self {
        Self {
            last_cancelled: None,
            cooldown_duration: Duration::from_millis(5000),
            assertion_cache: None,
            cache_ttl: Duration::from_secs(10),
            pending_client_data_hash: Vec::new(),
        }
    }

    /// Check if the engine is currently in a cancellation cooldown window.
    pub fn is_in_cooldown(&self) -> bool {
        if let Some(cancelled_at) = self.last_cancelled {
            cancelled_at.elapsed() < self.cooldown_duration
        } else {
            false
        }
    }

    /// Record a cancellation or termination event to enter/extend cooldown.
    pub fn record_cancellation(&mut self) {
        self.last_cancelled = Some(Instant::now());
    }

    /// Reset cooldown manually (e.g. for testing or explicit session restart).
    #[allow(dead_code)]
    pub fn reset_cooldown(&mut self) {
        self.last_cancelled = None;
    }

    /// Handle an incoming CBOR message from the host browser.
    pub fn handle_cbor_request(&mut self, data: &[u8]) -> EngineCborAction {
        if data.is_empty() {
            return EngineCborAction::Ignore;
        }

        let ctap_cmd = data[0];

        match ctap_cmd {
            CTAP_CMD_GET_INFO => {
                let get_info_cbor = build_get_info_response();
                EngineCborAction::SendResponse(get_info_cbor)
            }

            CTAP_CMD_GET_ASSERTION => {
                // Check cancellation cooldown: if active, reject immediately with KEEPALIVE_CANCEL
                // to instruct the browser client (Firefox/Chrome) to immediately abort the WebAuthn
                // ceremony instead of entering a retry loop.
                if self.is_in_cooldown() {
                    return EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL);
                }

                let assertion_req = parse_assertion_request(data);
                self.pending_client_data_hash = assertion_req.client_data_hash.clone();

                // Handle silent/pre-flight assertion checks (options: { "up": false })
                if !assertion_req.user_presence {
                    if assertion_req.allow_list_len == 0 {
                        // Registration pre-flight: check for resident credentials to exclude.
                        return EngineCborAction::SendStatus(CTAP2_ERR_NO_CREDENTIALS);
                    } else {
                        // Silent probe with allowList: resolve silently with synthetic assertion
                        if let Some((cred_descriptor, _cred_id)) =
                            extract_first_allow_list_credential(data)
                        {
                            let resp = build_silent_assertion_response(
                                &assertion_req.rp_id,
                                cred_descriptor,
                            );
                            return EngineCborAction::SendResponse(resp);
                        }
                    }
                }

                // Check assertion cache: two-stage multi-credential selection replay
                if let Some(cached) = self.assertion_cache.take() {
                    if cached.matches(&assertion_req, self.cache_ttl) {
                        tracing::info!("Satisfied GetAssertion request for '{}' from assertion cache (two-stage replay)", assertion_req.rp_id);
                        println!("⚡ Replayed cached assertion to browser for '{}' (two-stage selection completed seamlessly)!\n", assertion_req.rp_id);
                        return EngineCborAction::SendResponse(cached.response);
                    } else {
                        // Restore cache if it was not matched
                        self.assertion_cache = Some(cached);
                    }
                }

                let (cable_payload, _summary) = prepare_get_assertion_for_cable(data);
                EngineCborAction::StartCableTransaction {
                    req_type: CableRequestType::GetAssertion,
                    rp_id: assertion_req.rp_id,
                    cable_payload,
                }
            }

            CTAP_CMD_MAKE_CREDENTIAL => {
                // Check cancellation cooldown: if active, reject immediately with KEEPALIVE_CANCEL
                if self.is_in_cooldown() {
                    return EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL);
                }

                let (cable_payload, _summary) = prepare_make_credential_for_cable(data);
                let rp_id = extract_make_credential_rp_id(&cable_payload);

                // Intercept and reject browser dummy touch / selection probes
                // (e.g. Chromium/Firefox MakeCredentialTask::GetTouchRequest with rpId 'make.me.blink' or '.dummy')
                if rp_id == "make.me.blink" || rp_id == ".dummy" || rp_id == "dummy" {
                    return EngineCborAction::SendStatus(CTAP2_ERR_OPERATION_DENIED);
                }

                EngineCborAction::StartCableTransaction {
                    req_type: CableRequestType::DiscoverableMakeCredential,
                    rp_id,
                    cable_payload,
                }
            }

            _other => EngineCborAction::SendStatus(CTAP2_ERR_UNSUPPORTED_OPTION),
        }
    }

    /// Process the outcome of a caBLE transaction.
    /// Returns the CTAP status or response payload to send back on the channel,
    /// or None if no response should be sent (e.g. host reset).
    pub fn handle_transaction_outcome(
        &mut self,
        req_type: CableRequestType,
        rp_id: &str,
        result: TransactionResult,
    ) -> Option<EngineCborAction> {
        match result {
            TransactionResult::Success(resp) => {
                if req_type == CableRequestType::GetAssertion {
                    // Extract credential ID and cache response for rapid two-stage replay
                    let cred_id = extract_assertion_credential_id(&resp);
                    let client_data_hash = std::mem::take(&mut self.pending_client_data_hash);
                    self.assertion_cache = Some(CachedAssertion::new(
                        rp_id.to_string(),
                        client_data_hash,
                        cred_id,
                        resp.clone(),
                    ));
                }
                Some(EngineCborAction::SendResponse(resp))
            }
            TransactionResult::UserCancelled => {
                self.record_cancellation();
                // Return KEEPALIVE_CANCEL (0x2D) so the browser aborts WebAuthn immediately
                Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
            }
            TransactionResult::HostCancelled => {
                self.record_cancellation();
                Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
            }
            TransactionResult::HostReset => {
                self.record_cancellation();
                // Channel was re-initialized by host; no status sent on the old channel
                None
            }
            TransactionResult::Failed(_err) => {
                self.record_cancellation();
                Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn make_test_get_assertion_cbor(rp_id: &str, up: bool, allow_list: Vec<Vec<u8>>) -> Vec<u8> {
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Text(rp_id.to_string())));
        map.push((Value::Integer(2.into()), Value::Bytes(vec![0xAA; 32]))); // clientDataHash

        if !allow_list.is_empty() {
            let desc_array: Vec<Value> = allow_list
                .into_iter()
                .map(|id| {
                    Value::Map(vec![
                        (Value::Text("id".into()), Value::Bytes(id)),
                        (Value::Text("type".into()), Value::Text("public-key".into())),
                    ])
                })
                .collect();
            map.push((Value::Integer(3.into()), Value::Array(desc_array)));
        }

        if !up {
            let opt_map = vec![(Value::Text("up".into()), Value::Bool(false))];
            map.push((Value::Integer(5.into()), Value::Map(opt_map)));
        }

        let mut cbor = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();
        cbor
    }

    fn make_test_make_credential_cbor(rp_id: &str) -> Vec<u8> {
        let rp_map = vec![
            (Value::Text("id".into()), Value::Text(rp_id.to_string())),
            (Value::Text("name".into()), Value::Text(rp_id.to_string())),
        ];
        let user_map = vec![
            (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
            (Value::Text("name".into()), Value::Text("user".into())),
        ];
        let cred_param = Value::Map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("alg".into()), Value::Integer((-7).into())),
        ]);

        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Bytes(vec![0xAA; 32]))); // clientDataHash
        map.push((Value::Integer(2.into()), Value::Map(rp_map)));
        map.push((Value::Integer(3.into()), Value::Map(user_map)));
        map.push((Value::Integer(4.into()), Value::Array(vec![cred_param])));

        let mut cbor = vec![CTAP_CMD_MAKE_CREDENTIAL];
        ciborium::ser::into_writer(&Value::Map(map), &mut cbor).unwrap();
        cbor
    }

    fn make_test_assertion_response(cred_id: &[u8]) -> Vec<u8> {
        let desc = Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(cred_id.to_vec())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]);
        let resp_map = vec![
            (Value::Integer(1.into()), desc),
            (Value::Integer(2.into()), Value::Bytes(vec![0xAA; 37])),
            (Value::Integer(3.into()), Value::Bytes(vec![0xBB; 64])),
        ];
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&Value::Map(resp_map), &mut cbor).unwrap();
        cbor
    }

    #[test]
    fn test_engine_get_info() {
        let mut engine = BridgeEngine::new();
        let action = engine.handle_cbor_request(&[CTAP_CMD_GET_INFO]);
        if let EngineCborAction::SendResponse(resp) = action {
            assert!(!resp.is_empty());
            let val: Value = ciborium::from_reader(&resp[..]).unwrap();
            if let Value::Map(entries) = val {
                assert!(entries.iter().any(|(k, _)| *k == Value::Integer(1.into()))); // versions
                assert!(entries.iter().any(|(k, _)| *k == Value::Integer(4.into()))); // maxMsgSize
                assert!(entries.iter().any(|(k, _)| *k == Value::Integer(7.into()))); // maxCredentialCountInList
                assert!(entries.iter().any(|(k, _)| *k == Value::Integer(8.into()))); // maxCredentialIdLength
                assert!(entries.iter().any(|(k, _)| *k == Value::Integer(10.into())));
            // algorithms
            } else {
                panic!("Expected CBOR Map");
            }
        } else {
            panic!("Expected SendResponse for GetInfo, got {:?}", action);
        }
    }

    #[test]
    fn test_user_cancelled_returns_keepalive_cancel_and_activates_cooldown() {
        let mut engine = BridgeEngine::new();
        assert!(!engine.is_in_cooldown());

        let outcome = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::UserCancelled,
        );

        assert_eq!(
            outcome,
            Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
        );
        assert!(engine.is_in_cooldown());
    }

    #[test]
    fn test_host_cancelled_returns_keepalive_cancel_and_activates_cooldown() {
        let mut engine = BridgeEngine::new();
        let outcome = engine.handle_transaction_outcome(
            CableRequestType::DiscoverableMakeCredential,
            "webauthn.io",
            TransactionResult::HostCancelled,
        );

        assert_eq!(
            outcome,
            Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
        );
        assert!(engine.is_in_cooldown());
    }

    #[test]
    fn test_host_reset_activates_cooldown_and_returns_none() {
        let mut engine = BridgeEngine::new();
        let outcome = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::HostReset,
        );

        assert_eq!(outcome, None);
        assert!(engine.is_in_cooldown());
    }

    #[test]
    fn test_failed_transaction_returns_keepalive_cancel_and_activates_cooldown() {
        let mut engine = BridgeEngine::new();
        let outcome = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Failed("Connection dropped".into()),
        );

        assert_eq!(
            outcome,
            Some(EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL))
        );
        assert!(engine.is_in_cooldown());
    }

    #[test]
    fn test_cooldown_blocks_get_assertion_with_keepalive_cancel() {
        let mut engine = BridgeEngine::new();
        engine.record_cancellation();
        assert!(engine.is_in_cooldown());

        let req = make_test_get_assertion_cbor("webauthn.io", true, vec![]);
        let action = engine.handle_cbor_request(&req);

        // MUST be KEEPALIVE_CANCEL (0x2D) to stop browser retry loop
        assert_eq!(
            action,
            EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_cooldown_blocks_make_credential_with_keepalive_cancel() {
        let mut engine = BridgeEngine::new();
        engine.record_cancellation();
        assert!(engine.is_in_cooldown());

        let req = make_test_make_credential_cbor("webauthn.io");
        let action = engine.handle_cbor_request(&req);

        assert_eq!(
            action,
            EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_cooldown_handles_rapid_retries_without_leaking() {
        let mut engine = BridgeEngine::new();
        engine.record_cancellation();

        let req = make_test_get_assertion_cbor("webauthn.io", true, vec![]);
        for _ in 0..10 {
            let action = engine.handle_cbor_request(&req);
            assert_eq!(
                action,
                EngineCborAction::SendStatus(CTAP2_ERR_KEEPALIVE_CANCEL)
            );
        }
    }

    #[test]
    fn test_cooldown_expiration_allows_next_transaction() {
        let mut engine = BridgeEngine::new();
        // Set cancellation to 10 seconds ago (cooldown is 5 seconds)
        engine.last_cancelled = Some(Instant::now() - Duration::from_secs(10));
        assert!(!engine.is_in_cooldown());

        let req = make_test_get_assertion_cbor("webauthn.io", true, vec![]);
        let action = engine.handle_cbor_request(&req);

        match action {
            EngineCborAction::StartCableTransaction {
                req_type, rp_id, ..
            } => {
                assert_eq!(req_type, CableRequestType::GetAssertion);
                assert_eq!(rp_id, "webauthn.io");
            }
            other => panic!(
                "Expected StartCableTransaction after cooldown expiry, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_silent_get_assertion_preflight_allowlist_zero_returns_no_credentials() {
        let mut engine = BridgeEngine::new();
        let req = make_test_get_assertion_cbor("webauthn.io", false, vec![]);
        let action = engine.handle_cbor_request(&req);

        assert_eq!(
            action,
            EngineCborAction::SendStatus(CTAP2_ERR_NO_CREDENTIALS)
        );
    }

    #[test]
    fn test_silent_get_assertion_probe_returns_synthetic_assertion() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![10, 20, 30, 40];
        let req = make_test_get_assertion_cbor("webauthn.io", false, vec![cred_id.clone()]);
        let action = engine.handle_cbor_request(&req);

        if let EngineCborAction::SendResponse(resp) = action {
            assert!(!resp.is_empty());
            let val: Value = ciborium::from_reader(&resp[..]).unwrap();
            if let Value::Map(entries) = val {
                assert_eq!(entries.len(), 3);
            } else {
                panic!("Expected CBOR Map");
            }
        } else {
            panic!("Expected SendResponse for silent probe, got {:?}", action);
        }
    }

    #[test]
    fn test_make_credential_dummy_probes_rejected_without_cable() {
        let mut engine = BridgeEngine::new();

        for dummy in &["make.me.blink", ".dummy", "dummy"] {
            let req = make_test_make_credential_cbor(dummy);
            let action = engine.handle_cbor_request(&req);
            assert_eq!(
                action,
                EngineCborAction::SendStatus(CTAP2_ERR_OPERATION_DENIED),
                "Failed dummy probe check for rpId: {}",
                dummy
            );
        }
    }

    #[test]
    fn test_make_credential_legitimate_starts_cable() {
        let mut engine = BridgeEngine::new();
        let req = make_test_make_credential_cbor("webauthn.io");
        let action = engine.handle_cbor_request(&req);

        match action {
            EngineCborAction::StartCableTransaction {
                req_type, rp_id, ..
            } => {
                assert_eq!(req_type, CableRequestType::DiscoverableMakeCredential);
                assert_eq!(rp_id, "webauthn.io");
            }
            other => panic!("Expected StartCableTransaction, got {:?}", other),
        }
    }

    #[test]
    fn test_get_assertion_interactive_starts_cable() {
        let mut engine = BridgeEngine::new();
        let req = make_test_get_assertion_cbor("webauthn.io", true, vec![]);
        let action = engine.handle_cbor_request(&req);

        match action {
            EngineCborAction::StartCableTransaction {
                req_type, rp_id, ..
            } => {
                assert_eq!(req_type, CableRequestType::GetAssertion);
                assert_eq!(rp_id, "webauthn.io");
            }
            other => panic!("Expected StartCableTransaction, got {:?}", other),
        }
    }

    #[test]
    fn test_two_stage_assertion_replay_matches_credential() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let assertion_resp = make_test_assertion_response(&cred_id);

        // Stage 1: Phone completes assertion via caBLE
        let outcome = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp.clone()),
        );
        assert_eq!(
            outcome,
            Some(EngineCborAction::SendResponse(assertion_resp.clone()))
        );
        assert!(engine.assertion_cache.is_some());

        // Stage 2: Browser immediately sends targeted GetAssertion with matching credential
        let follow_up = make_test_get_assertion_cbor("webauthn.io", true, vec![cred_id.clone()]);
        let action = engine.handle_cbor_request(&follow_up);

        // Must return cached response directly without starting a new caBLE transaction!
        assert_eq!(action, EngineCborAction::SendResponse(assertion_resp));
    }

    #[test]
    fn test_two_stage_assertion_replay_miss_different_credential() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let other_cred = vec![0xDE, 0xAD, 0x00, 0x01];
        let assertion_resp = make_test_assertion_response(&cred_id);

        engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp),
        );

        // Browser sends GetAssertion with completely different credential ID
        let follow_up = make_test_get_assertion_cbor("webauthn.io", true, vec![other_cred]);
        let action = engine.handle_cbor_request(&follow_up);

        // Must not match cache; should start a new transaction
        match action {
            EngineCborAction::StartCableTransaction { .. } => {}
            other => panic!(
                "Expected StartCableTransaction on credential miss, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_two_stage_assertion_replay_miss_different_rp() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let assertion_resp = make_test_assertion_response(&cred_id);

        engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp),
        );

        // Request for different RP
        let follow_up = make_test_get_assertion_cbor("github.com", true, vec![cred_id]);
        let action = engine.handle_cbor_request(&follow_up);

        match action {
            EngineCborAction::StartCableTransaction { rp_id, .. } => {
                assert_eq!(rp_id, "github.com");
            }
            other => panic!("Expected StartCableTransaction on RP miss, got {:?}", other),
        }
    }

    #[test]
    fn test_two_stage_assertion_replay_expired() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let assertion_resp = make_test_assertion_response(&cred_id);

        engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp),
        );

        // Age the cache past TTL (10s)
        if let Some(ref mut cached) = engine.assertion_cache {
            cached.created_at = Instant::now() - Duration::from_secs(15);
        }

        let follow_up = make_test_get_assertion_cbor("webauthn.io", true, vec![cred_id]);
        let action = engine.handle_cbor_request(&follow_up);

        match action {
            EngineCborAction::StartCableTransaction { .. } => {}
            other => panic!(
                "Expected StartCableTransaction on expired cache, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_empty_request_ignored() {
        let mut engine = BridgeEngine::new();
        let action = engine.handle_cbor_request(&[]);
        assert_eq!(action, EngineCborAction::Ignore);
    }

    #[test]
    fn test_unsupported_ctap_command() {
        let mut engine = BridgeEngine::new();
        let action = engine.handle_cbor_request(&[0x77, 0x00]);
        assert_eq!(
            action,
            EngineCborAction::SendStatus(CTAP2_ERR_UNSUPPORTED_OPTION)
        );
    }

    #[test]
    fn test_two_stage_assertion_replay_matches_discoverable_none_credential() {
        let mut engine = BridgeEngine::new();
        let dummy_resp = vec![0x00, 0xAA, 0xBB];

        let _ = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(dummy_resp.clone()),
        );

        // Subsequent targeted assertion request with allowList should match when cached cred_id is None
        let req2 = make_test_get_assertion_cbor("webauthn.io", true, vec![vec![1, 2, 3]]);
        let action = engine.handle_cbor_request(&req2);
        assert_eq!(action, EngineCborAction::SendResponse(dummy_resp));
    }

    #[test]
    fn test_two_stage_assertion_replay_matches_same_client_data_hash_and_single_use() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let hash = vec![0x55; 32];
        let assertion_resp = make_test_assertion_response(&cred_id);

        // Stage 1: Request arrives, setting pending_client_data_hash
        let mut map1 = Vec::new();
        map1.push((
            Value::Integer(1.into()),
            Value::Text("webauthn.io".to_string()),
        ));
        map1.push((Value::Integer(2.into()), Value::Bytes(hash.clone())));
        let mut cbor1 = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map1), &mut cbor1).unwrap();

        let action1 = engine.handle_cbor_request(&cbor1);
        assert!(matches!(
            action1,
            EngineCborAction::StartCableTransaction { .. }
        ));

        // Complete transaction 1: populates cache with pending_client_data_hash
        let outcome = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp.clone()),
        );
        assert_eq!(
            outcome,
            Some(EngineCborAction::SendResponse(assertion_resp.clone()))
        );
        assert!(engine.assertion_cache.is_some());

        // Stage 2: Follow-up with identical clientDataHash matches and replays!
        let mut map2 = Vec::new();
        map2.push((
            Value::Integer(1.into()),
            Value::Text("webauthn.io".to_string()),
        ));
        map2.push((Value::Integer(2.into()), Value::Bytes(hash)));
        map2.push((
            Value::Integer(3.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(cred_id)),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ));
        let mut cbor2 = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map2.clone()), &mut cbor2).unwrap();

        let action2 = engine.handle_cbor_request(&cbor2);
        assert_eq!(action2, EngineCborAction::SendResponse(assertion_resp));

        // Cache must be consumed! A subsequent request cannot replay the same cache again.
        assert!(engine.assertion_cache.is_none());
        let action3 = engine.handle_cbor_request(&cbor2);
        assert!(matches!(
            action3,
            EngineCborAction::StartCableTransaction { .. }
        ));
    }

    #[test]
    fn test_two_stage_assertion_replay_miss_different_client_data_hash() {
        let mut engine = BridgeEngine::new();
        let cred_id = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let hash1 = vec![0x11; 32];
        let hash2 = vec![0x22; 32];
        let assertion_resp = make_test_assertion_response(&cred_id);

        // Stage 1 with hash1
        let mut map1 = Vec::new();
        map1.push((
            Value::Integer(1.into()),
            Value::Text("webauthn.io".to_string()),
        ));
        map1.push((Value::Integer(2.into()), Value::Bytes(hash1)));
        let mut cbor1 = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map1), &mut cbor1).unwrap();

        let _ = engine.handle_cbor_request(&cbor1);
        let _ = engine.handle_transaction_outcome(
            CableRequestType::GetAssertion,
            "webauthn.io",
            TransactionResult::Success(assertion_resp),
        );

        // Stage 2 with completely different hash2 must NOT match cache
        let mut map2 = Vec::new();
        map2.push((
            Value::Integer(1.into()),
            Value::Text("webauthn.io".to_string()),
        ));
        map2.push((Value::Integer(2.into()), Value::Bytes(hash2)));
        map2.push((
            Value::Integer(3.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(cred_id)),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ));
        let mut cbor2 = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&Value::Map(map2), &mut cbor2).unwrap();

        let action2 = engine.handle_cbor_request(&cbor2);
        assert!(matches!(
            action2,
            EngineCborAction::StartCableTransaction { .. }
        ));
    }
}
