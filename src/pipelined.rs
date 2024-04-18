use std::collections::{BTreeMap, HashMap};

use parking_lot::Mutex;

use crate::{common::{Signers, Votes}, types::{Block, Certificate, PrivateKey, Signed, Signer, ToBytes, View, Vote, Wish, ID}};


#[derive(Debug, Clone)]
struct Propose {
    view: View,
    block: Block,
    lock: Certificate<Vote>,
    commit: Certificate<Vote>
}

impl ToBytes for Propose {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&self.view.to_bytes());
        buf.extend_from_slice(&self.block.to_bytes());
        buf.extend_from_slice(&self.lock.to_bytes());
        buf.extend_from_slice(&self.commit.to_bytes());
        buf
    }
}

#[derive(Debug)]
struct Consensus {
    participants: Signers,
    keys: HashMap<Signer, PrivateKey>,
    state: Mutex<State>,
}

impl Consensus {
    fn new(participants: Signers, keys: HashMap<Signer, PrivateKey>) -> Self {
        Self {
            participants,
            keys,
            state: Mutex::new(State {
                view: 0.into(),
                voted: 0.into(),
                votes: BTreeMap::new(),
                timeouts: BTreeMap::new(),
                committed: 0,
                chain: BTreeMap::new(),
                proposal: None,
                ticks: 0,
                waiting_delay_view: None,
            }),
        }
    }
}

impl Consensus {
    pub fn on_propose(&self, propose: Signed<Propose>) {}
    
    pub fn on_vote(&self, vote: Signed<Vote>) {}

    pub fn on_wish(&self, wish: Signed<View>) {}

    pub fn on_timeout(&self, timeout: Certificate<View>) {}

    pub fn on_delay(&self) {}

    pub fn propose(&self, id: ID) {}
}

#[derive(Debug)]
struct State{
    view: View,
    voted: View,
    votes: BTreeMap<View, Votes<Vote>>,
    timeouts: BTreeMap<View, Votes<Wish>>,
    committed: u64,
    // chain contains certificates starting from committed to the last known certificate
    // it must overwrite everything after update height, for example:
    // chain contains certificates for heights 10, 11, 12. committed is 10.
    // if certificate 11 is overwritten, 12 must be removed as well.
    chain: BTreeMap<u64, Certificate<Vote>>,

    proposal: Option<Propose>,
    ticks: u8,
    waiting_delay_view: Option<View>,
}