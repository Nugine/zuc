use std::hint::black_box;

use criterion::BenchmarkId;
use criterion::Throughput;
use criterion::{criterion_group, criterion_main, Criterion};

use const_str::hex;

fn zuc128_keystream(c: &mut Criterion) {
    static K: [u8; 16] = [
        0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, //
        0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b, //
    ];

    static IV: [u8; 16] = [
        0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, //
        0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66, //
    ];

    let mut group = c.benchmark_group("zuc128_keystream");

    for &size in &[1000, 2000, 3000, 10000, 20000, 30000] {
        group.throughput(Throughput::Bytes((size * 4) as u64)); // 每次 generate 生成 u32 (4 bytes)
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &s| {
            let mut zuc = zuc::zuc128::Zuc128Keystream::new(&K, &IV);
            let mut buffer = vec![0u32; s];
            b.iter(|| {
                buffer.iter_mut().for_each(|chunk| {
                    *chunk = zuc.generate();
                });
            });
        });
    }
    group.finish();
}

fn eia3_mac(c: &mut Criterion) {
    let mac = |input: &[u8]| -> u32 {
        let count = 0x561e_b2dd;
        let bearer = 0x14;
        let direction = 0;
        let length = input.len() as u32 * 8 - 15;
        let ik = &hex!("47 05 41 25 56 1e b2 dd a9 40 59 da 05 09 78 50");
        zuc::eia3::eia3_generate_mac(count, bearer, direction, ik, length, input)
    };

    let mut group = c.benchmark_group("eia3_mac");

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

fn zuc256_mac(c: &mut Criterion) {
    let mac = |input: &[u8]| -> u128 {
        let length = input.len() as u32 * 8 - 15;
        let ik = &[0xff; 32];
        let iv = &[0xff; 23];
        zuc::zuc256::zuc256_generate_mac::<u128>(ik, iv, length, input)
    };

    let mut group = c.benchmark_group("zuc256_mac_128");

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

criterion_group!(benches, zuc128_keystream, eia3_mac, zuc256_mac);
criterion_main!(benches);
