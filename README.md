- [hotstuff2](https://eprint.iacr.org/2023/397.pdf)
  2-round hostuff with novel view synchronization protocol.
- [original hotstuff](https://arxiv.org/pdf/1803.05069.pdf)
  original 3-round hotstuff and pipelined protocol specification.
- [cogsworth](https://cryptoeconomicsystems.pubpub.org/pub/naor-cogsworth-synchronization/release/5)
  view synchronization protocol referenced in hotstuff2.
- [bls12-381 signature library](https://github.com/supranational/blst)
- [bls12-381 overview](https://hackmd.io/@benjaminion/bls12-381)


TODO:
- [ ] coverage
  single and multi instances unit tests that ensure that consensus makes progress
  exactly as i expect it too.
- [ ] proptests
  completely random messages.
  different order for good messages.
  1/3 of the network is voting differently.
- [ ] synchronization
  move signature verification, signing and aggregations to one layer above message processing code.
  participants array should remain immutable by contract, any changes to array should result in different instance.
  message processing will be guarded by single mutex.
- [ ] loom