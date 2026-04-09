use auction_bitplane_example::{build_params, encode_bid_into_planes, BID_BITS};
use fhe::bfv::PublicKey;
use fhe_traits::{DeserializeParametrized, FheEncrypter, Serialize};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encrypt_bid(pk_bytes: &[u8], bid: u64, slot: u32) -> Result<Vec<u8>, JsValue> {
    let params = build_params();
    let pk = PublicKey::from_bytes(pk_bytes, &params)
        .map_err(|e| JsValue::from_str(&format!("bad public key: {e}")))?;

    let planes = encode_bid_into_planes(bid, slot as usize, &params);
    debug_assert_eq!(planes.len(), BID_BITS);

    let mut result = Vec::new();
    for pt in &planes {
        let ct = pk
            .try_encrypt(pt, &mut OsRng)
            .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;
        let ct_bytes = ct.to_bytes();
        result.extend_from_slice(&(ct_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&ct_bytes);
    }
    Ok(result)
}
