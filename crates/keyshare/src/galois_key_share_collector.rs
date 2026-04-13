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
use e3_events::{E3id, EventContext, GaloisKeyShareCreated, Sequenced, TypedEvent};
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
pub struct AllGaloisKeySharesCollected {
    pub exponent: u64,
    pub shares: Vec<GaloisKeyShareCreated>,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct GaloisKeyShareCollectionTimeout;

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct GaloisKeyShareCollectionFailed {
    pub e3_id: E3id,
    pub exponent: u64,
    pub reason: String,
    pub missing_parties: Vec<u64>,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ExpelPartyFromGaloisKeyShareCollection {
    pub party_id: u64,
    pub ec: EventContext<Sequenced>,
}

pub struct GaloisKeyShareCollector {
    e3_id: E3id,
    exponent: u64,
    expected: HashSet<u64>,
    parent: Addr<ThresholdKeyshare>,
    state: CollectorState,
    shares: HashMap<u64, GaloisKeyShareCreated>,
    timeout_handle: Option<SpawnHandle>,
}

impl GaloisKeyShareCollector {
    pub fn setup(
        parent: Addr<ThresholdKeyshare>,
        expected_parties: HashSet<u64>,
        e3_id: E3id,
        exponent: u64,
    ) -> Addr<Self> {
        Self {
            e3_id,
            exponent,
            expected: expected_parties,
            parent,
            state: CollectorState::Collecting,
            shares: HashMap::new(),
            timeout_handle: None,
        }
        .start()
    }
}

impl Actor for GaloisKeyShareCollector {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        let handle = ctx.notify_later(GaloisKeyShareCollectionTimeout, DEFAULT_COLLECTION_TIMEOUT);
        self.timeout_handle = Some(handle);
    }
}

impl Handler<TypedEvent<GaloisKeyShareCreated>> for GaloisKeyShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<GaloisKeyShareCreated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let start = Instant::now();

        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        if msg.exponent != self.exponent {
            warn!(
                e3_id = %self.e3_id,
                expected_exponent = self.exponent,
                received_exponent = msg.exponent,
                party_id = msg.party_id,
                "Ignoring GaloisKeyShareCreated with unexpected exponent"
            );
            return;
        }

        let pid = msg.party_id;
        let Some(_) = self.expected.take(&pid) else {
            info!(
                e3_id = %self.e3_id,
                exponent = self.exponent,
                party_id = pid,
                "Ignoring duplicate/unexpected GaloisKeyShareCreated"
            );
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
                AllGaloisKeySharesCollected {
                    exponent: self.exponent,
                    shares,
                },
                ec,
            ));
            ctx.stop();
        }

        info!(
            e3_id = %self.e3_id,
            exponent = self.exponent,
            elapsed = ?start.elapsed(),
            "Processed GaloisKeyShareCreated"
        );
    }
}

impl Handler<GaloisKeyShareCollectionTimeout> for GaloisKeyShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        _: GaloisKeyShareCollectionTimeout,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !matches!(self.state, CollectorState::Collecting) {
            return;
        }

        self.state = CollectorState::TimedOut;
        self.parent.do_send(GaloisKeyShareCollectionFailed {
            e3_id: self.e3_id.clone(),
            exponent: self.exponent,
            reason: format!(
                "Timeout waiting for Galois key shares from {} parties",
                self.expected.len()
            ),
            missing_parties: self.expected.iter().copied().collect(),
        });
        ctx.stop();
    }
}

impl Handler<ExpelPartyFromGaloisKeyShareCollection> for GaloisKeyShareCollector {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpelPartyFromGaloisKeyShareCollection,
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
                AllGaloisKeySharesCollected {
                    exponent: self.exponent,
                    shares,
                },
                msg.ec,
            ));
            ctx.stop();
        }
    }
}
