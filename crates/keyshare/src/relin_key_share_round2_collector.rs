// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, SpawnHandle};
use e3_events::{E3id, EventContext, RelinKeyShareRound2Created, Sequenced, TypedEvent};
use e3_utils::MAILBOX_LIMIT;
use tracing::{info, warn};

use crate::ThresholdKeyshare;

const DEFAULT_COLLECTION_TIMEOUT: Duration = Duration::from_secs(300);

enum CollectorState {
    Collecting,
    Finished,
    TimedOut,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct AllRelinKeyRound2SharesCollected {
    pub shares: Vec<RelinKeyShareRound2Created>,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct RelinKeyRound2ShareCollectionTimeout;

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct RelinKeyRound2ShareCollectionFailed {
    pub e3_id: E3id,
    pub reason: String,
    pub missing_parties: Vec<u64>,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ExpelPartyFromRelinKeyRound2ShareCollection {
    pub party_id: u64,
    pub ec: EventContext<Sequenced>,
}

pub struct RelinKeyRound2ShareCollector {
    e3_id: E3id,
    expected: HashSet<u64>,
    parent: Addr<ThresholdKeyshare>,
    state: CollectorState,
    shares: HashMap<u64, RelinKeyShareRound2Created>,
    timeout_handle: Option<SpawnHandle>,
}

impl RelinKeyRound2ShareCollector {
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        expected_parties: HashSet<u64>,
        e3_id: E3id,
    ) -> Addr<Self> {
        Self {
            e3_id,
            expected: expected_parties,
            parent,
            state: CollectorState::Collecting,
            shares: HashMap::new(),
            timeout_handle: None,
        }
        .start()
    }
}

impl Actor for RelinKeyRound2ShareCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        self.timeout_handle = Some(ctx.notify_later(
            RelinKeyRound2ShareCollectionTimeout,
            DEFAULT_COLLECTION_TIMEOUT,
        ));
    }
}

impl Handler<TypedEvent<RelinKeyShareRound2Created>> for RelinKeyRound2ShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<RelinKeyShareRound2Created>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let start = Instant::now();

        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        let pid = msg.party_id;
        let Some(_) = self.expected.take(&pid) else {
            warn!(e3_id = %self.e3_id, party_id = pid, "Ignoring duplicate/unexpected relin round2 share");
            return;
        };

        self.shares.insert(pid, msg);

        if self.expected.is_empty() {
            self.state = CollectorState::Finished;
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }
            let mut shares: Vec<_> = std::mem::take(&mut self.shares).into_values().collect();
            shares.sort_by_key(|share| share.party_id);
            self.parent.do_send(TypedEvent::new(
                AllRelinKeyRound2SharesCollected { shares },
                ec,
            ));
            ctx.stop();
        }

        info!(e3_id = %self.e3_id, elapsed = ?start.elapsed(), "Processed RelinKeyShareRound2Created");
    }
}

impl Handler<RelinKeyRound2ShareCollectionTimeout> for RelinKeyRound2ShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        _: RelinKeyRound2ShareCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        self.state = CollectorState::TimedOut;
        self.parent.do_send(RelinKeyRound2ShareCollectionFailed {
            e3_id: self.e3_id.clone(),
            reason: format!(
                "Timeout waiting for relin round2 shares from {} parties",
                self.expected.len()
            ),
            missing_parties: self.expected.iter().copied().collect(),
        });
        ctx.stop();
    }
}

impl Handler<ExpelPartyFromRelinKeyRound2ShareCollection> for RelinKeyRound2ShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpelPartyFromRelinKeyRound2ShareCollection,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        if !self.expected.remove(&msg.party_id) {
            self.shares.remove(&msg.party_id);
            return;
        }

        if self.expected.is_empty() {
            self.state = CollectorState::Finished;
            if let Some(handle) = self.timeout_handle.take() {
                ctx.cancel_future(handle);
            }
            let mut shares: Vec<_> = std::mem::take(&mut self.shares).into_values().collect();
            shares.sort_by_key(|share| share.party_id);
            self.parent.do_send(TypedEvent::new(
                AllRelinKeyRound2SharesCollected { shares },
                msg.ec,
            ));
            ctx.stop();
        }
    }
}
