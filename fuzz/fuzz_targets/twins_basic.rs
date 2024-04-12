#![no_main]

use libfuzzer_sys::fuzz_target;
use hotstuff2::model::{ArbitraryOp, Model};

type Op = ArbitraryOp<7, 2>;

fuzz_target!(|operations: [Op; 100]| {
    let mut model = Model::new(7, 2);
    for op in operations {
        model.step(op.into()).unwrap();
    }
});
