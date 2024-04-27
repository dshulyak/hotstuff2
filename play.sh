#!/bin/bash

APP_LOG=${APP_LOG:-info}
RELEASE=${RELEASE:-release}
BINARY_PATH=${BINARY_PATH:-$(pwd)/target/$RELEASE}
SIZE=${SIZE:-4}
LATENCY=${LATENCY:-40ms}

# the following options can be used to collect events into local opentelemetry-compatible collector
# 10.0.0.1 is the ip address of the bridge configured by playground
# on 4317 i expect to run a jaeger instance
# example -i node{index} -t http://10.0.0.1:4317 run

RUST_LOG=$RUST_LOG PATH=$PATH:$BINARY_PATH play run \
    -e RUST_LOG=$APP_LOG \
    -w /tmp/example \
    -p ex \
    --redirect \
    --netem="delay ${LATENCY}" \
    -n $SIZE \
    -c 'example -i node{index} -t http://10.0.0.1:4317 run -d dir{index} -k {index}.key -p public_keys --peer-list peer_list'