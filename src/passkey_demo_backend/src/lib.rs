use candid::{candid_method, CandidType, Principal};
use ic_cdk_macros::{query, update};
use ic_certified_map::Hash;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

mod hash;
mod passkey_example;

pub type UserId = u64;
pub type CredentialId = ByteBuf;
pub type PublicKey = ByteBuf;
pub type SessionKey = PublicKey;
pub type ChallengeKey = String;
pub type DeviceKey = PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub name: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct WebAuthn {
    pub pubkey: PublicKey,
    pub credential_id: CredentialId,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Challenge {
    pub png_base64: String,
    pub challenge_key: ChallengeKey,
}

fn calculate_seed(anchor_number: UserId) -> Hash {
    // demo salt
    let salt = [0u8; 32];

    let mut blob: Vec<u8> = vec![];
    blob.push(salt.len() as u8);
    blob.extend_from_slice(&salt);

    let anchor_number_str = anchor_number.to_string();
    let anchor_number_blob = anchor_number_str.bytes();
    blob.push(anchor_number_blob.len() as u8);
    blob.extend(anchor_number_blob);

    hash::hash_bytes(blob)
}

#[query]
fn get_principal(user_id: UserId) -> Principal {
    let Ok(_) = check_authentication(user_id) else {
        trap(&format!("{} could not be authenticated.", caller()));
    };
    let seed = calculate_seed(user_id);
    let public_key = der_encode_canister_sig_key(seed.to_vec());
    Principal::self_authenticating(public_key)
}

#[update]
async fn prepare_delegation(
    user_id: UserId,
    session_key: SessionKey,
    max_time_to_live: Option<u64>,
) -> (UserKey, Timestamp) {
    let ii_domain = authenticate_and_record_activity(user_id);
    delegation::prepare_delegation(user_id, frontend, session_key, max_time_to_live, &ii_domain)
        .await
}

#[query]
#[candid_method(query)]
fn get_delegation(
    user_id: UserId,
    session_key: SessionKey,
    expiration: Timestamp,
) -> GetDelegationResponse {
    let Ok(_) = check_authentication(user_id) else {
        trap(&format!("{} could not be authenticated.", caller()));
    };
    delegation::get_delegation(user_id, frontend, session_key, expiration)
}

fn check_authentication(anchor_number: UserId) -> Result<(UserId, DeviceKey), ()> {
    let anchor = state::anchor(anchor_number);
    let caller = caller();

    for device in anchor.devices() {
        if caller == Principal::self_authenticating(&device.pubkey)
            || state::with_temp_keys_mut(|temp_keys| {
                temp_keys
                    .check_temp_key(&caller, &device.pubkey, anchor_number)
                    .is_ok()
            })
        {
            return Ok((anchor.clone(), device.pubkey.clone()));
        }
    }
    Err(())
}
