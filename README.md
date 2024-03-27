- [hotstuff2](https://eprint.iacr.org/2023/397.pdf)
  2-round hostuff with novel view synchronization protocol.
- [original hotstuff](https://arxiv.org/pdf/1803.05069.pdf)
  original 3-round hotstuff and pipelined protocol specification.
- [cogsworth](https://cryptoeconomicsystems.pubpub.org/pub/naor-cogsworth-synchronization/release/5)
  view synchronization protocol referenced in hotstuff2.
- [bls12-381 signature library](https://github.com/supranational/blst)
- [bls12-381 overview](https://hackmd.io/@benjaminion/bls12-381)


TODO:
- [ ] sufficient tracing for debug
- [ ] e2e sanity test
- [ ] introduce `prev` for block

## Tests

1. `cargo install cargo-nextest --locked`
2. `cargo nextest run`

## Coverage

1. `cargo install cargo-llvm-cov`
2. Open web page with coverage report `cargo llvm-cov nextest --open`

