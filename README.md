## Notes

[Notes](./NOTES.md) on the design of the protocol and relevant background.

## How to run cluster?

0. Get the play binary
```
git clone git@github.com:dshulyak/playground.git
cargo build --release --manifest-path=./play/Cargo.toml
sudo cp ./target/release/play /usr/bin/
```
1. Compile example
```
cargo build --manifest-path=./example/Cargo.toml
```
2. Generate keys for the test
```
./target/debug/example generate -d /tmp/example
```
3. Run cluster 
```
sudo ./play.sh
```

By default script will run 4 nodes cluster. Size can controlled by the SIZE env variable:
```
sudo SIZE=31 ./play.sh
```

The delay between nodes will be 40 ms.
Logs will be available in target directory, which is `/tmp/example` in the example above. 

Playground can be restarted as long as the protocol configuration didn't change between restarts.

4. Reset state

All state is stored in /tmp/example. Delete directory to reset it.
```
sudo rm -rf /tmp/example
```

5. Known issues with running playground
- arp cache threshing, can be diagnosed by looking at dmesg
```
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=204800
```
- docker interfering with other bridges
```
sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
```

## Tests

1. `cargo install cargo-nextest --locked`
2. `cargo nextest run`

## Coverage

1. `cargo install cargo-llvm-cov`
2. Open web page with coverage report `cargo llvm-cov nextest --open`

