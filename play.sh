#!/bin/bash

RUST_LOG=${RUST_LOG:-info}
RELEASE=${RELEASE:-release}
BINARY_PATH=${BINARY_PATH:-$(pwd)/target/$RELEASE}
SIZE=${SIZE:-4}

# the following options can be used to collect events into local opentelemetry-compatible collector
# -i node{index} -t http://10.0.0.1:4317

RUST_LOG=$RUST_LOG PATH=$PATH:$BINARY_PATH play run \
    -e RUST_LOG=$RUST_LOG \
    -w /tmp/example \
    -p exmp \
    --redirect \
    --netem='delay 40ms' \
    -n $SIZE \
    -c 'example run -d dir{index} -k {index}.key -p public_keys --peer-list peer_list'