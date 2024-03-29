- [hotstuff2](https://eprint.iacr.org/2023/397.pdf)
  2-round hostuff with novel view synchronization protocol.
- [original hotstuff](https://arxiv.org/pdf/1803.05069.pdf)
  original 3-round hotstuff and pipelined protocol specification.
- [cogsworth](https://cryptoeconomicsystems.pubpub.org/pub/naor-cogsworth-synchronization/release/5)
  view synchronization protocol referenced in hotstuff2.
- [bls12-381 signature library](https://github.com/supranational/blst)
- [bls12-381 overview](https://hackmd.io/@benjaminion/bls12-381)


TODO:
- [ ] implement send_to
  in state machine select expected leader for target round and create Action::SendTo with that leader.
  in node advertise PublicKey before starting sync protocol. key should be advertised together with proof of possesion.
  the proof of possesion is just a signature with the same domain over public key.
  router should be able to match public key to an opened gossip channel when called with send_to.
- [ ] playground testing
- [ ] twins model checker
- [ ] madsim simulation

## Tests

1. `cargo install cargo-nextest --locked`
2. `cargo nextest run`

## Coverage

1. `cargo install cargo-llvm-cov`
2. Open web page with coverage report `cargo llvm-cov nextest --open`

