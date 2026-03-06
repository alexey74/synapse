//! JSON
//!
//! Matrix event JSON utility functions.

use std::collections::BTreeMap;

use anyhow::Context as _;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signed_json::CanonicalizationOptions;

use super::constants::{
    aliases_field, create_field,
    event_field::{
        AGE_TS, AUTH_EVENTS, CONTENT, DEPTH, EVENT_ID, HASHES, MEMBERSHIP, ORIGIN,
        ORIGIN_SERVER_TS, PREV_EVENTS, PREV_STATE, REPLACES_STATE, ROOM_ID, SENDER, SIGNATURES,
        STATE_KEY, TYPE, UNSIGNED,
    },
    event_type::{
        M_ROOM_ALIASES, M_ROOM_CREATE, M_ROOM_HISTORY_VISIBILITY, M_ROOM_JOIN_RULES, M_ROOM_MEMBER,
        M_ROOM_POWER_LEVELS, M_ROOM_REDACTION,
    },
    history_visibility_field, join_rules_field, membership_field, power_levels_field,
    redaction_field, RoomVersion, MAX_PDU_SIZE_BYTES,
};
use crate::identifier::{EventID, IdentifierError};

/// Calculates the event_id of an event.
///
/// The event_id is the `reference_hash` of the redacted event json, preceded by a `$`.
/// `calculate_event_id` can be used to determine the `event_id` for events in room versions V3+.
pub fn calculate_event_id(event: &Value, room_version: &RoomVersion) -> anyhow::Result<EventID> {
    if matches!(room_version, RoomVersion::V1 | RoomVersion::V2) {
        anyhow::bail!(
            "Attempted to calculate event_id using reference hash for room version v1/v2"
        );
    }

    let reference_hash = compute_event_reference_hash(event, room_version)?;

    format!("${reference_hash}")
        .as_str()
        .try_into()
        .map_err(|err: IdentifierError| anyhow::format_err!(err))
        .context("Failed converting to event_id")
}

/// Computes the event reference hash. This is the hash of the redacted event.
fn compute_event_reference_hash(
    event: &Value,
    room_version: &RoomVersion,
) -> anyhow::Result<String> {
    let mut redacted_value = redact(event, room_version)?;

    let redacted_value_mut = redacted_value
        .as_object_mut()
        .context("Failed getting `redacted_value` as mutable object")?;

    redacted_value_mut.remove(SIGNATURES);
    redacted_value_mut.remove(UNSIGNED);

    let canonicalization_options = match room_version {
        RoomVersion::V1 | RoomVersion::V2 | RoomVersion::V3 | RoomVersion::V4 | RoomVersion::V5 => {
            CanonicalizationOptions::relaxed()
        }
        _ => CanonicalizationOptions::strict(),
    };
    let json = signed_json::to_string_canonical(&redacted_value_mut, canonicalization_options)
        .map_err(|err| anyhow::anyhow!(err))?;
    if json.len() > MAX_PDU_SIZE_BYTES {
        anyhow::bail!("Event larger than max PDU size.");
    }

    let hash = Sha256::digest(json.as_bytes());

    let base64_alphabet = if *room_version == RoomVersion::V3 {
        base64::alphabet::STANDARD
    } else {
        base64::alphabet::URL_SAFE
    };
    let base64_engine = base64::engine::GeneralPurpose::new(
        &base64_alphabet,
        base64::engine::general_purpose::NO_PAD,
    );

    Ok(base64_engine.encode(hash))
}

/// Attempts to redact the provided event, returning a copy of the redacted event if successful.
///
/// Events redacted with this function are meant to be sent over federation.
pub fn redact(event: &Value, room_version: &RoomVersion) -> anyhow::Result<Value> {
    // TODO: add redacted because when needed

    let mut allowed_keys = BTreeMap::from([
        (EVENT_ID, ()),
        (SENDER, ()),
        (ROOM_ID, ()),
        (HASHES, ()),
        (SIGNATURES, ()),
        (CONTENT, ()),
        (TYPE, ()),
        (STATE_KEY, ()),
        (DEPTH, ()),
        (PREV_EVENTS, ()),
        (AUTH_EVENTS, ()),
        (ORIGIN_SERVER_TS, ()),
    ]);

    // Earlier room versions had additional allowed keys
    if !use_updated_redaction_rules(room_version) {
        allowed_keys.extend([(PREV_STATE, ()), (MEMBERSHIP, ()), (ORIGIN, ())]);
    }

    let event_type = event
        .get(TYPE)
        .with_context(|| format!("Missing {TYPE} field in json"))?
        .as_str()
        .with_context(|| format!("{TYPE} field is not a string"))?;

    let event_content = event
        .get(CONTENT)
        .with_context(|| format!("Missing {CONTENT} field in json"))?;

    let mut new_content = serde_json::json!({});
    let new_content_mut = new_content
        .as_object_mut()
        .context("Failed getting `new_content` as mutable object")?;

    let mut add_content_field = |field: &str| {
        if let Some(existing_field) = event_content.get(field) {
            new_content_mut.insert(field.to_string(), existing_field.clone());
        }
    };

    match event_type {
        M_ROOM_MEMBER => {
            add_content_field(membership_field::MEMBERSHIP);
            if use_restricted_join_rule_fix(room_version) {
                add_content_field(membership_field::JOIN_AUTHORISED_VIA_USERS_SERVER);
            }
            if use_updated_redaction_rules(room_version) {
                // Preserve the signed field under third_party_invite.
                if let Some(third_party_invite) =
                    event_content.get(membership_field::THIRD_PARTY_INVITE)
                {
                    if third_party_invite.as_object().is_some() {
                        let mut new_third_party_invite = serde_json::json!({});
                        if let Some(signed) = third_party_invite.get(membership_field::SIGNED) {
                            new_third_party_invite =
                                serde_json::json!({membership_field::SIGNED: signed.clone()});
                        }
                        new_content_mut.insert(
                            membership_field::THIRD_PARTY_INVITE.to_string(),
                            new_third_party_invite,
                        );
                    }
                }
            }
        }
        M_ROOM_CREATE => {
            if use_updated_redaction_rules(room_version) {
                // MSC2176 rules state that create events cannot have their `content` redacted.
                if let Some(event_content_object) = event_content.as_object() {
                    for (field, _value) in event_content_object {
                        add_content_field(field);
                    }
                }
            }
            if !use_implicit_room_creator(room_version) {
                // Some room versions give meaning to `creator`
                add_content_field(create_field::CREATOR);
            }
            if use_room_ids_as_hashes(room_version) {
                // room_id is not allowed on the create event as it's derived from the event ID
                allowed_keys.remove(ROOM_ID);
            }
        }
        M_ROOM_JOIN_RULES => {
            add_content_field(join_rules_field::JOIN_RULE);
            if use_restricted_join_rule(room_version) {
                add_content_field(join_rules_field::ALLOW);
            }
        }
        M_ROOM_POWER_LEVELS => {
            add_content_field(power_levels_field::USERS);
            add_content_field(power_levels_field::USERS_DEFAULT);
            add_content_field(power_levels_field::EVENTS);
            add_content_field(power_levels_field::EVENTS_DEFAULT);
            add_content_field(power_levels_field::STATE_DEFAULT);
            add_content_field(power_levels_field::BAN);
            add_content_field(power_levels_field::KICK);
            add_content_field(power_levels_field::REDACT);
            if use_updated_redaction_rules(room_version) {
                add_content_field(power_levels_field::INVITE);
            }
        }
        M_ROOM_ALIASES if use_special_case_aliases_auth(room_version) => {
            add_content_field(aliases_field::ALIASES);
        }
        M_ROOM_HISTORY_VISIBILITY => {
            add_content_field(history_visibility_field::HISTORY_VISIBILITY)
        }
        M_ROOM_REDACTION if use_updated_redaction_rules(room_version) => {
            add_content_field(redaction_field::REDACTS);
        }
        _ => (),
    };

    let mut allowed_fields = serde_json::json!({});
    let allowed_fields_mut = allowed_fields
        .as_object_mut()
        .context("Failed getting `allowed_fields` as mutable object")?;

    for (k, v) in event
        .as_object()
        .context("Event is not a JSON object")?
        .iter()
    {
        if allowed_keys.contains_key(&k.as_str()) {
            allowed_fields_mut.insert(k.clone(), v.clone());
        }
    }

    allowed_fields_mut.insert(CONTENT.to_string(), new_content);

    Ok(allowed_fields)
}

/// Attempts to redact the provided event, returning a copy of the redacted event if successful.
/// In order to conform to Synapse's internal redaction logic, this function allows keeping a few
/// extra fields in the redacted event.
///
/// Events redacted with this function **should not** be sent over federation.
pub fn redact_internal(event: &Value, room_version: &RoomVersion) -> anyhow::Result<Value> {
    let mut redacted = redact(event, room_version)?;
    let redacted_mut = redacted
        .as_object_mut()
        .context("Failed getting `redacted` as mutable object")?;

    let mut new_unsigned = serde_json::json!({});
    let new_unsigned_mut = new_unsigned
        .as_object_mut()
        .context("Failed getting `new_unsigned` as mutable object")?;

    if let Some(unsigned) = event.get(UNSIGNED) {
        if let Some(age_ts) = unsigned.get(AGE_TS) {
            new_unsigned_mut.insert(AGE_TS.to_string(), age_ts.clone());
        }
        if let Some(replaces_state) = unsigned.get(REPLACES_STATE) {
            new_unsigned_mut.insert(REPLACES_STATE.to_string(), replaces_state.clone());
        }
    }

    redacted_mut.insert(UNSIGNED.to_string(), new_unsigned);

    Ok(redacted)
}

/// Whether the `redacts` field has been moved from the top level to inside `content` for the given
/// room version. The top-level `origin`, `membership`, and `prev_state` properties are no longer
/// protected from redaction. The `m.room.create` event now keeps the entire content property. The
/// `m.room.redaction` event keeps the `redacts` property under `content`. The
/// `m.room.power_levels` event keeps the `invite` property under `content`.
///
/// Added in room version 11.
/// <https://spec.matrix.org/v1.16/rooms/v11/#redactions>
pub fn use_updated_redaction_rules(room_version_id: &RoomVersion) -> bool {
    !matches!(
        room_version_id,
        RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
            | RoomVersion::V9
            | RoomVersion::V10
            | RoomVersion::OrgMatrixMsc1767_10
            | RoomVersion::OrgMatrixMsc3757_10
    )
}

/// Whether `m.room.aliases` has significant meaning.
/// This means that the `aliases` property under `content` is no longer kept for the `m.room.aliases`
/// event type.
///
/// Removed in room version 6.
/// <https://spec.matrix.org/v1.16/rooms/v6/#redactions>
fn use_special_case_aliases_auth(room_version_id: &RoomVersion) -> bool {
    matches!(
        room_version_id,
        RoomVersion::V1 | RoomVersion::V2 | RoomVersion::V3 | RoomVersion::V4 | RoomVersion::V5
    )
}

/// `m.room.join_rules` events now keep `allow` in addition to other keys in `content` when being
/// redacted.
///
/// Added in room version 8.
/// <https://spec.matrix.org/v1.16/rooms/v8/#redactions>
fn use_restricted_join_rule(room_version_id: &RoomVersion) -> bool {
    !matches!(
        room_version_id,
        RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
    )
}

/// `m.room.member` events now keep `join_authorised_via_users_server` in addition to other keys in
/// `content` when being redacted.
///
/// Added in room version 9.
/// <https://spec.matrix.org/v1.16/rooms/v9/#redactions>
fn use_restricted_join_rule_fix(room_version_id: &RoomVersion) -> bool {
    !matches!(
        room_version_id,
        RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
    )
}

/// The content of a `m.room.create` event no longer has a `creator` property, which previously was
/// always equivalent to the `sender` of the event.
///
/// Added in room version 11.
/// <https://spec.matrix.org/v1.16/rooms/v11/#redactions>
fn use_implicit_room_creator(room_version_id: &RoomVersion) -> bool {
    !matches!(
        room_version_id,
        RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
            | RoomVersion::V9
            | RoomVersion::V10
            | RoomVersion::OrgMatrixMsc1767_10
            | RoomVersion::OrgMatrixMsc3757_10
    )
}

/// Whether room ids are hashes, or still the older localpart:domain style.
/// Returns true if the room_id is a hash for the given room version.
///
/// Added in room version 12.
/// <https://spec.matrix.org/v1.16/rooms/v12/#redactions>
pub fn use_room_ids_as_hashes(room_version_id: &RoomVersion) -> bool {
    !matches!(
        room_version_id,
        RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
            | RoomVersion::V9
            | RoomVersion::V10
            | RoomVersion::V11
            | RoomVersion::OrgMatrixMsc1767_10
            | RoomVersion::OrgMatrixMsc3757_10
            | RoomVersion::OrgMatrixMsc3757_11
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{calculate_event_id, redact, redact_internal};
    use crate::events::constants::RoomVersion;
    use crate::identifier::EventID;

    #[test]
    fn test_calculate_event_id() {
        let original = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{
                    "msgtype":"m.text",
                    "body":"invited people can see history",
                    "m.mentions":{}
                },
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );
        let redacted = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{},
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                }
            }
        );

        let expected = EventID::try_from("$zRz9jjiT9wZc3Hl9ij_74aCmTjqV3YMlj9sj3Uqxg6o").unwrap();
        let expected_v3 =
            EventID::try_from("$zRz9jjiT9wZc3Hl9ij/74aCmTjqV3YMlj9sj3Uqxg6o").unwrap();

        let original_event_id = calculate_event_id(&original, &RoomVersion::V10).unwrap();
        let redacted_event_id = calculate_event_id(&redacted, &RoomVersion::V10).unwrap();
        let _ = calculate_event_id(&original, &RoomVersion::V2).unwrap_err();
        let v3_event_id = calculate_event_id(&original, &RoomVersion::V3).unwrap();

        assert_eq!(expected, original_event_id);
        assert_eq!(expected, redacted_event_id);
        assert_eq!(expected_v3, v3_event_id);
    }

    #[test]
    /// Tests to ensure events with overly large values for `depth` are handled appropriately.
    /// This was added in room version 6 <https://spec.matrix.org/v1.16/rooms/v6/#event-format>.
    fn test_calculate_event_id_big_int_old_rooms() {
        let original = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{
                    "msgtype":"m.text",
                    "body":"invited people can see history",
                    "m.mentions":{}
                },
                // NOTE: use the biggest acceptable number
                "depth":u64::MAX,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );

        // These should succeed.
        let _event_id = calculate_event_id(&original, &RoomVersion::V3).unwrap();
        let _event_id = calculate_event_id(&original, &RoomVersion::V4).unwrap();
        let _event_id = calculate_event_id(&original, &RoomVersion::V5).unwrap();

        // These should not succeed.
        let versions = [
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let _event_id = calculate_event_id(&original, &version).unwrap_err();
        }
    }

    #[test]
    /// Tests that calling `redact` on invalid event json that is missing the `type` property
    /// fails.
    /// The `type` field is required by all versions of the spec. Any json encountered where
    /// this field is missing must be considered invalid.
    fn test_redact_missing_type() {
        let original = json!(
            {
                "bad_key":"bad_value",
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{
                    "msgtype":"m.text",
                    "body":"invited people can see history",
                    "m.mentions":{}
                },
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let _ = redact(&original, &version).unwrap_err();
        }
    }

    #[test]
    /// Tests that calling `redact` on invalid event json that is missing the `content` property
    /// fails.
    /// The `content` field is required by all versions of the spec. Any json encountered where
    /// this field is missing must be considered invalid.
    fn test_redact_missing_content() {
        let original = json!(
            {
                "bad_key":"bad_value",
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let _ = redact(&original, &version).unwrap_err();
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.message` events against latest room versions.
    /// This is only testing v10+ as it is rather cumbersome to create the proper json for all
    /// rooms versions.
    fn test_redact_m_room_message() {
        let original = json!(
            {
                "bad_key":"bad_value",
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{
                    "msgtype":"m.text",
                    "body":"invited people can see history",
                    "m.mentions":{}
                },
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );
        let expected = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{},
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
            }
        );
        let expected_internal = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{},
                "depth":24,
                "origin":"localhost:8008",
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );
        let expected_v11 = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{},
                "depth":24,
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
            }
        );
        let expected_internal_v11 = json!(
            {
                "auth_events":[
                    "$gbHO7IPUHybc7ULFnT7P0r3iWlZFHGmr6zBfEYCUyKw",
                    "$hy1eZFYcgNxMFNNBgCD5fyOzyWRcBkxfNcrUI5ZpZlE",
                    "$Nt_z68EwFfPqBeHjzEHGsp461Z4EfNEzR-KH5bOYdOY"
                ],
                "prev_events":[
                    "$4FbpZrgPQTwoLD9H5y7jcikucCypUOn78mXhQX7WliY"
                ],
                "type":"m.room.message",
                "room_id":"!DHmIIVvxFASSFgDGzr:localhost:8008",
                "sender":"@tester_b:localhost:8008",
                "content":{},
                "depth":24,
                "origin_server_ts":1731769874137_i64,
                "hashes":{
                    "sha256":"FoYV1w3TW/B2mVT0gX2/BZKpCwrrvGXqXFdUhN9LZYU"
                },
                "signatures":{
                    "localhost:8008":{
                        "ed25519:a_phSE":"G8cfk/m97sndxMNrEZ2nMMSXkVeJE05G7if4JiVzAwGfD3TwnF/jfSHt2acWrpNqv/aEhZug3WLofc2id+rVBw"
                    }
                },
                "unsigned":{
                    "age_ts":1731769874137_i64
                }
            }
        );

        let redacted = redact(&original, &RoomVersion::V10).unwrap();
        let redacted_internal = redact_internal(&original, &RoomVersion::V10).unwrap();

        assert_eq!(expected, redacted);
        assert_eq!(expected_internal, redacted_internal,);

        let versions = [RoomVersion::V11, RoomVersion::V12];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            let redacted_internal = redact_internal(&original, &version).unwrap();

            assert_eq!(expected_v11, redacted, "Room Version {version}");
            assert_eq!(
                expected_internal_v11, redacted_internal,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic adheres to changes due to [super::use_updated_redaction_rules].
    /// Tests against all known room versions.
    fn test_redact_updated_redaction_rules() {
        let original = json!(
            {
                "type":"m.room.message",
                "prev_state":{},
                "membership":{},
                "origin":"some_place",
                "content":{},
            }
        );

        let expected_updated_redaction_rules = json!(
            {
                "type":"m.room.message",
                "content":{},
            }
        );
        let expected_pre_updated_redaction_rules = json!(
            {
                "type":"m.room.message",
                "prev_state":{},
                "membership":{},
                "origin":"some_place",
                "content":{},
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
        ];
        for version in versions {
            let redacted_1 = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_updated_redaction_rules, redacted_1,
                "Room Version {version}"
            );
        }

        let versions = [RoomVersion::V11, RoomVersion::V12];
        for version in versions {
            let redacted_2 = redact(&original, &version).unwrap();
            assert_eq!(
                expected_updated_redaction_rules, redacted_2,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.member` events against all known room versions.
    fn test_redact_m_room_member() {
        let original = json!(
            {
                "type":"m.room.member",
                "content":{
                    "bad_key":"bad_value",
                    "membership":"join",
                    "join_authorised_via_users_server":"server",
                    "third_party_invite":{
                        "signed":{},
                    },
                },
            }
        );

        let expected_pre_unrestricted_join_rule_fix = json!(
            {
                "type":"m.room.member",
                "content":{
                    "membership":"join",
                },
            }
        );

        let expected_updated_redaction_rules = json!(
            {
                "type":"m.room.member",
                "content":{
                    "membership":"join",
                    "join_authorised_via_users_server":"server",
                    "third_party_invite":{
                        "signed":{},
                    },
                },
            }
        );
        let expected_pre_updated_redaction_rules = json!(
            {
                "type":"m.room.member",
                "content":{
                    "membership":"join",
                    "join_authorised_via_users_server":"server",
                },
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_unrestricted_join_rule_fix, redacted,
                "Room Version {version}"
            );
        }

        let versions = [RoomVersion::V9, RoomVersion::V10];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }

        let versions = [RoomVersion::V11, RoomVersion::V12];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }
    }

    /// Tests redaction logic for `m.room.create` events against all known room versions.
    #[test]
    fn test_redact_m_room_create() {
        let original = json!(
            {
                "type":"m.room.create",
                "room_id": "!roomid",
                "content":{
                    "bad_key":"bad_value",
                    "other_key":"value",
                    "creator":"user",
                },
            }
        );

        let expected_implicit_room_creator = json!(
            {
                "type":"m.room.create",
                "room_id": "!roomid",
                "content":{
                    "bad_key":"bad_value",
                    "other_key":"value",
                    "creator":"user",
                },
            }
        );
        let expected_room_ids_as_hashes = json!(
            {
                "type":"m.room.create",
                "content":{
                    "bad_key":"bad_value",
                    "other_key":"value",
                    "creator":"user",
                },
            }
        );
        let expected_pre_implicit_room_creator = json!(
            {
                "type":"m.room.create",
                "room_id": "!roomid",
                "content":{
                    "creator":"user",
                },
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_implicit_room_creator, redacted,
                "Room Version {version}"
            );
        }

        let redacted = redact(&original, &RoomVersion::V11).unwrap();
        assert_eq!(expected_implicit_room_creator, redacted);

        let versions = [RoomVersion::OrgMatrixHydra11, RoomVersion::V12];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_room_ids_as_hashes, redacted,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.join_rules` events against all known room versions.
    fn test_redact_m_room_join_rules() {
        let original = json!(
            {
                "type":"m.room.join_rules",
                "content":{
                    "bad_key":"bad_value",
                    "join_rule":"invite",
                    "allow":"user",
                },
            }
        );

        let expected_restricted_join_rule = json!(
            {
                "type":"m.room.join_rules",
                "content":{
                    "join_rule":"invite",
                    "allow":"user",
                },
            }
        );
        let expected_pre_restricted_join_rule = json!(
            {
                "type":"m.room.join_rules",
                "content":{
                    "join_rule":"invite",
                },
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_restricted_join_rule, redacted,
                "Room Version {version}"
            );
        }

        let versions = [
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_restricted_join_rule, redacted,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.power_levels` events against all known room versions.
    fn test_redact_m_room_power_levels() {
        let original = json!(
            {
                "type":"m.room.power_levels",
                "content":{
                    "bad_key":"bad_value",
                    "users":{},
                    "users_default":{},
                    "events":{},
                    "events_default":{},
                    "state_default":{},
                    "ban":{},
                    "kick":{},
                    "redact":{},
                    "invite":{},
                },
            }
        );

        let expected_updated_redaction_rules = json!(
            {
                "type":"m.room.power_levels",
                "content":{
                    "users":{},
                    "users_default":{},
                    "events":{},
                    "events_default":{},
                    "state_default":{},
                    "ban":{},
                    "kick":{},
                    "redact":{},
                    "invite":{},
                },
            }
        );
        let expected_pre_updated_redaction_rules = json!(
            {
                "type":"m.room.power_levels",
                "content":{
                    "users":{},
                    "users_default":{},
                    "events":{},
                    "events_default":{},
                    "state_default":{},
                    "ban":{},
                    "kick":{},
                    "redact":{},
                },
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }

        let versions = [RoomVersion::V11, RoomVersion::V12];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.aliases` events against all known room versions.
    fn test_redact_m_room_aliases() {
        let original = json!(
            {
                "type":"m.room.aliases",
                "content":{
                    "bad_key":"bad_value",
                    "aliases":{},
                },
            }
        );

        let expected_special_case_aliases = json!(
            {
                "type":"m.room.aliases",
                "content":{
                    "aliases":{},
                },
            }
        );
        let expected_post_special_case_aliases = json!(
            {
                "type":"m.room.aliases",
                "content":{},
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_special_case_aliases, redacted,
                "Room Version {version}"
            );
        }

        let versions = [
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_post_special_case_aliases, redacted,
                "Room Version {version}"
            );
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.history_visibility` events against all known room versions.
    fn test_redact_m_room_history_visibility() {
        let original = json!(
            {
                "type":"m.room.history_visibility",
                "content":{
                    "bad_key":"bad_value",
                    "history_visibility":"visibility",
                },
            }
        );

        let expected = json!(
            {
                "type":"m.room.history_visibility",
                "content":{
                    "history_visibility":"visibility",
                },
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
            RoomVersion::V11,
            RoomVersion::V12,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(expected, redacted, "Room Version {version}");
        }
    }

    #[test]
    /// Tests redaction logic for `m.room.redaction` events against all known room versions.
    fn test_redact_m_room_redaction() {
        let original = json!(
            {
                "type":"m.room.redaction",
                "content":{
                    "bad_key":"bad_value",
                    "redacts":"event",
                },
            }
        );

        let expected_updated_redaction_rules = json!(
            {
                "type":"m.room.redaction",
                "content":{
                    "redacts":"event",
                },
            }
        );
        let expected_pre_updated_redaction_rules = json!(
            {
                "type":"m.room.redaction",
                "content":{},
            }
        );

        let versions = [
            RoomVersion::V1,
            RoomVersion::V2,
            RoomVersion::V3,
            RoomVersion::V4,
            RoomVersion::V5,
            RoomVersion::V6,
            RoomVersion::V7,
            RoomVersion::V8,
            RoomVersion::V9,
            RoomVersion::V10,
        ];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_pre_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }

        let versions = [RoomVersion::V11, RoomVersion::V12];
        for version in versions {
            let redacted = redact(&original, &version).unwrap();
            assert_eq!(
                expected_updated_redaction_rules, redacted,
                "Room Version {version}"
            );
        }
    }
}
