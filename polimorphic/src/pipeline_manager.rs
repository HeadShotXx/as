use crate::primitives::Primitive;
use rand::Rng;

pub fn transform_pipeline(primitives: Vec<Primitive>, rng: &mut impl Rng) -> Vec<Primitive> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < primitives.len() {
        // Objective 2: Merging adjacent compatible stages
        if i + 1 < primitives.len() {
            match (&primitives[i], &primitives[i+1]) {
                (Primitive::Map(table), Primitive::BitLoad { .. }) => {
                    if rng.gen_bool(0.5) {
                        out.push(Primitive::MappedBitLoad { table: table.clone() });
                        i += 2;
                        continue;
                    }
                },
                (Primitive::Map(table), Primitive::BaseLoad { .. }) => {
                    if rng.gen_bool(0.5) {
                        out.push(Primitive::MappedBaseLoad { table: table.clone() });
                        i += 2;
                        continue;
                    }
                },
                _ => {}
            }
        }

        // Objective 2: Splitting a stage into two internal sub-stages
        match &primitives[i] {
            Primitive::BitLoad { .. } | Primitive::BaseLoad { .. } => {
                if rng.gen_bool(0.4) {
                    out.push(Primitive::BitLoadPart { start_pct: 0, end_pct: 50 });
                    out.push(Primitive::BitLoadPart { start_pct: 50, end_pct: 100 });
                    i += 1;
                    continue;
                }
            },
            _ => {}
        }

        // Objective 2: Injecting intermediate representations/stages
        if rng.gen_bool(0.1) {
            out.push(Primitive::Noop { val: rng.gen() });
        }
        if rng.gen_bool(0.1) {
            out.push(Primitive::Sync);
        }

        out.push(primitives[i].clone());
        i += 1;
    }
    out
}
