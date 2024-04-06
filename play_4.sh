#!/bin/bash

play run \
    -e PATH=./target/debug \
    -e RUST_LOG=debug \
    --redirect \
    -w /tmp/first \
    -c 'example run -d dir0 -k 0.key -p public_keys -c 10.0.0.2:9000 -c 10.0.0.3:9000 -c 10.0.0.4:9000' \
    -c 'example run -d dir1 -k 1.key -p public_keys -c 10.0.0.1:9000 -c 10.0.0.3:9000 -c 10.0.0.4:9000' \
    -c 'example run -d dir2 -k 2.key -p public_keys -c 10.0.0.1:9000 -c 10.0.0.2:9000 -c 10.0.0.4:9000' \
    -c 'example run -d dir3 -k 3.key -p public_keys -c 10.0.0.1:9000 -c 10.0.0.2:9000 -c 10.0.0.3:9000' 