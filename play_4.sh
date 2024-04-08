#!/bin/bash

RUST_LOG=${RUST_LOG:-info}
RELEASE=${RELEASE:-release}
BINARY_PATH=${BINARY_PATH:-$(pwd)/target/$RELEASE}

RUST_LOG=$RUST_LOG PATH=$PATH:$BINARY_PATH play run \
    -e RUST_LOG=$RUST_LOG \
    -w /tmp/example \
    --redirect \
    --netem='delay 20ms' \
    -c 'example -i node0 -t http://10.0.0.1:4317 run -d dir0 -k 0.key -p public_keys -c 10.0.0.3:9000 -c 10.0.0.4:9000 -c 10.0.0.5:9000' \
    -c 'example -i node1 -t http://10.0.0.1:4317 run -d dir1 -k 1.key -p public_keys -c 10.0.0.2:9000 -c 10.0.0.4:9000 -c 10.0.0.5:9000' \
    -c 'example -i node2 -t http://10.0.0.1:4317 run -d dir2 -k 2.key -p public_keys -c 10.0.0.2:9000 -c 10.0.0.3:9000 -c 10.0.0.5:9000' \
    -c 'example -i node3 -t http://10.0.0.1:4317 run -d dir3 -k 3.key -p public_keys -c 10.0.0.2:9000 -c 10.0.0.3:9000 -c 10.0.0.4:9000' 