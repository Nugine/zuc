use std::hint::black_box;

use const_str::hex;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn eia3_128_mac(c: &mut Criterion) {
    let mac = |input: &[u8]| -> u32 {
        let count = 0x561e_b2dd;
        let bearer = 0x14;
        let direction = 0;
        let length = input.len() as u32 * 8;
        let ik = &hex!("47 05 41 25 56 1e b2 dd a9 40 59 da 05 09 78 50");
        zuc::eia3_128_generate_mac(count, bearer, direction, ik, length, input)
    };

    let mut group = c.benchmark_group("eia3_128_mac");

    for &size in &[1000, 2000, 3000, 10000, 20000, 30000] {
        group.throughput(criterion::Throughput::Bytes(size as u64));

        let input = {
            let mut v: Vec<u8> = Vec::with_capacity(size);
            v.extend((0..size).map(|_| rand::random::<u8>()));
            v
        };

        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, input| {
            b.iter(|| black_box(mac(input)));
        });
    }

    group.finish();
}

criterion_group!(benches, eia3_128_mac);
criterion_main!(benches);
