use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuctionState {
    Open,
    Computing,
    Complete,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuctionResult {
    pub winner_address: String,
    pub winner_slot: usize,
    pub second_address: Option<String>,
    pub second_slot: Option<usize>,
}

#[derive(Debug)]
pub struct Bid {
    pub address: String,
    pub slot: usize,
    pub bitplane_bytes: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct Auction {
    pub id: u64,
    pub state: AuctionState,
    pub bids: Vec<Bid>,
    pub next_slot: usize,
    pub result: Option<AuctionResult>,
}

impl Auction {
    pub fn new(id: u64) -> Self {
        Auction {
            id,
            state: AuctionState::Open,
            bids: Vec::new(),
            next_slot: 0,
            result: None,
        }
    }

    pub fn assign_slot(&mut self) -> usize {
        let slot = self.next_slot;
        self.next_slot += 1;
        slot
    }
}
