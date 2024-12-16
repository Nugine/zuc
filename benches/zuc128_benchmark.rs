use criterion::*;
use zuc::Zuc128Core;

static K: [u8; 16] = [
    0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, //
    0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b, //
];

static IV: [u8; 16] = [
    0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, //
    0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66, //
];

fn zuc128_generate_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("zuc128_generate_throughput");

    for &size in &[1000, 2000, 3000, 10000, 20000, 30000] {
        group.throughput(Throughput::Bytes((size * 4) as u64)); // 每次 generate 生成 u32 (4 bytes)
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &s| {
            let mut zuc = Zuc128Core::new(&K, &IV);
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

criterion_group!(benches, zuc128_generate_throughput);
criterion_main!(benches);
