extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["src/proto/messages.proto"], &["src/proto/"]).unwrap();
}