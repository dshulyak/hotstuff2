#![no_main]

use libfuzzer_sys::fuzz_target;
use hotstuff2::model::{Model, Op};

fuzz_target!(|actions: [Op; 100]| {
    let mut model = Model::new(7, 2);
    for action in actions {
        if let Err(err) = model.step(action) {
            assert!(false, "error: {:?}", err)
        }
    }
});
