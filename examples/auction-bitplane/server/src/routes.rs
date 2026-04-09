use actix_web::{web, HttpResponse, Responder};
use auction_bitplane_example::{self, BID_BITS, SLOTS};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use fhe::bfv::Ciphertext;
use fhe_traits::DeserializeParametrized;
use serde::Deserialize;
use serde_json::json;

use crate::auction::{Auction, AuctionResult, AuctionState, Bid};
use crate::AppState;

#[derive(Deserialize)]
pub struct BidRequest {
    pub address: String,
    pub bitplanes: Vec<String>,
}

pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(json!({ "status": "ok" }))
}

pub async fn create_auction(state: web::Data<AppState>) -> impl Responder {
    let id = state
        .next_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let auction = Auction::new(id);

    let mut auctions = match state.auctions.lock() {
        Ok(auctions) => auctions,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({ "error": "state lock poisoned" }))
        }
    };
    auctions.insert(id, auction);

    HttpResponse::Ok().json(json!({
        "id": id,
        "public_key": B64.encode(&state.keys.pk_bytes),
        "slot": 0usize,
    }))
}

pub async fn get_auction(state: web::Data<AppState>, path: web::Path<u64>) -> impl Responder {
    let id = path.into_inner();
    let auctions = match state.auctions.lock() {
        Ok(auctions) => auctions,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({ "error": "state lock poisoned" }))
        }
    };

    match auctions.get(&id) {
        Some(auction) => HttpResponse::Ok().json(json!({
            "id": auction.id,
            "state": auction.state,
            "num_bids": auction.bids.len(),
            "public_key": B64.encode(&state.keys.pk_bytes),
            "result": auction.result,
        })),
        None => HttpResponse::NotFound().json(json!({ "error": "auction not found" })),
    }
}

pub async fn submit_bid(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<BidRequest>,
) -> impl Responder {
    if body.bitplanes.len() != BID_BITS {
        return HttpResponse::BadRequest().json(json!({
            "error": format!("expected {BID_BITS} bitplanes")
        }));
    }

    let mut bitplane_bytes = Vec::with_capacity(BID_BITS);
    for encoded in &body.bitplanes {
        let bytes = match B64.decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => {
                return HttpResponse::BadRequest()
                    .json(json!({ "error": "invalid base64 ciphertext" }))
            }
        };

        if Ciphertext::from_bytes(&bytes, &state.keys.params).is_err() {
            return HttpResponse::BadRequest().json(json!({
                "error": "invalid ciphertext for current parameters"
            }));
        }

        bitplane_bytes.push(bytes);
    }

    let id = path.into_inner();
    let mut auctions = match state.auctions.lock() {
        Ok(auctions) => auctions,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({ "error": "state lock poisoned" }))
        }
    };

    let auction = match auctions.get_mut(&id) {
        Some(auction) => auction,
        None => return HttpResponse::NotFound().json(json!({ "error": "auction not found" })),
    };

    if auction.state != AuctionState::Open {
        return HttpResponse::BadRequest().json(json!({ "error": "auction is not open" }));
    }

    if auction.next_slot >= SLOTS {
        return HttpResponse::BadRequest().json(json!({ "error": "auction is full" }));
    }

    let slot = auction.assign_slot();
    auction.bids.push(Bid {
        address: body.address.clone(),
        slot,
        bitplane_bytes,
    });

    HttpResponse::Ok().json(json!({
        "ok": true,
        "slot": slot,
        "num_bids": auction.bids.len(),
    }))
}

pub async fn close_auction(state: web::Data<AppState>, path: web::Path<u64>) -> impl Responder {
    let id = path.into_inner();

    let bids = {
        let mut auctions = match state.auctions.lock() {
            Ok(auctions) => auctions,
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "state lock poisoned" }))
            }
        };

        let auction = match auctions.get_mut(&id) {
            Some(auction) => auction,
            None => {
                return HttpResponse::NotFound().json(json!({ "error": "auction not found" }))
            }
        };

        if auction.state != AuctionState::Open {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "auction is not open for closing" }));
        }

        if auction.bids.is_empty() {
            return HttpResponse::BadRequest().json(json!({ "error": "no bids submitted" }));
        }

        auction.state = AuctionState::Computing;
        auction
            .bids
            .iter()
            .map(|bid| Bid {
                address: bid.address.clone(),
                slot: bid.slot,
                bitplane_bytes: bid.bitplane_bytes.clone(),
            })
            .collect::<Vec<_>>()
    };

    let mut global_bitplanes: Option<Vec<Ciphertext>> = None;
    for bid in &bids {
        let contribution = match bid
            .bitplane_bytes
            .iter()
            .map(|bytes| Ciphertext::from_bytes(bytes, &state.keys.params))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(contribution) => contribution,
            Err(_) => {
                let mut auctions = match state.auctions.lock() {
                    Ok(auctions) => auctions,
                    Err(_) => {
                        return HttpResponse::InternalServerError()
                            .json(json!({ "error": "state lock poisoned" }))
                    }
                };
                if let Some(auction) = auctions.get_mut(&id) {
                    auction.state = AuctionState::Open;
                }
                return HttpResponse::BadRequest()
                    .json(json!({ "error": "stored bid ciphertext is invalid" }));
            }
        };

        match global_bitplanes.as_mut() {
            Some(global_bitplanes) => {
                auction_bitplane_example::accumulate_bitplanes(global_bitplanes, &contribution);
            }
            None => {
                global_bitplanes = Some(contribution);
            }
        }
    }

    let global_bitplanes = match global_bitplanes {
        Some(global_bitplanes) => global_bitplanes,
        None => {
            let mut auctions = match state.auctions.lock() {
                Ok(auctions) => auctions,
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .json(json!({ "error": "state lock poisoned" }))
                }
            };
            if let Some(auction) = auctions.get_mut(&id) {
                auction.state = AuctionState::Open;
            }
            return HttpResponse::BadRequest().json(json!({ "error": "no bids submitted" }));
        }
    };

    let tally_cts = auction_bitplane_example::compute_tallies(
        &global_bitplanes,
        bids.len(),
        &state.keys.eval_key,
        &state.keys.relin_key,
        &state.keys.params,
    );
    let tally_matrix = auction_bitplane_example::decrypt_tally_matrix(
        &tally_cts,
        bids.len(),
        &state.keys.sk,
        &state.keys.params,
    );
    let (winner_slot, second_slot) =
        auction_bitplane_example::rank_bidders_from_tallies(&tally_matrix);

    let winner_address = match bids.iter().find(|bid| bid.slot == winner_slot) {
        Some(bid) => bid.address.clone(),
        None => {
            let mut auctions = match state.auctions.lock() {
                Ok(auctions) => auctions,
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .json(json!({ "error": "state lock poisoned" }))
                }
            };
            if let Some(auction) = auctions.get_mut(&id) {
                auction.state = AuctionState::Open;
            }
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "winner slot not found" }));
        }
    };

    let second_address = match second_slot {
        Some(second_slot) => match bids.iter().find(|bid| bid.slot == second_slot) {
            Some(bid) => Some(bid.address.clone()),
            None => {
                let mut auctions = match state.auctions.lock() {
                    Ok(auctions) => auctions,
                    Err(_) => {
                        return HttpResponse::InternalServerError()
                            .json(json!({ "error": "state lock poisoned" }))
                    }
                };
                if let Some(auction) = auctions.get_mut(&id) {
                    auction.state = AuctionState::Open;
                }
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "second slot not found" }));
            }
        },
        None => None,
    };

    let result = AuctionResult {
        winner_address,
        winner_slot,
        second_address,
        second_slot,
    };

    let mut auctions = match state.auctions.lock() {
        Ok(auctions) => auctions,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({ "error": "state lock poisoned" }))
        }
    };
    let auction = match auctions.get_mut(&id) {
        Some(auction) => auction,
        None => return HttpResponse::NotFound().json(json!({ "error": "auction not found" })),
    };
    auction.state = AuctionState::Complete;
    auction.result = Some(result.clone());

    HttpResponse::Ok().json(json!({
        "winner_address": result.winner_address,
        "winner_slot": result.winner_slot,
        "second_address": result.second_address,
        "second_slot": result.second_slot,
    }))
}

pub async fn get_result(state: web::Data<AppState>, path: web::Path<u64>) -> impl Responder {
    let id = path.into_inner();
    let auctions = match state.auctions.lock() {
        Ok(auctions) => auctions,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({ "error": "state lock poisoned" }))
        }
    };

    match auctions.get(&id) {
        Some(auction) => match &auction.result {
            Some(result) => HttpResponse::Ok().json(json!({
                "winner_address": result.winner_address,
                "winner_slot": result.winner_slot,
                "second_address": result.second_address,
                "second_slot": result.second_slot,
            })),
            None => HttpResponse::BadRequest()
                .json(json!({ "error": "auction not yet complete", "state": auction.state })),
        },
        None => HttpResponse::NotFound().json(json!({ "error": "auction not found" })),
    }
}
