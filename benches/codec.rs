//! Codec micro-benchmarks: M3UA message encode/decode across the message classes.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! All fixtures are built from the public API (RFC 4666 wire layout), so the
//! benches measure exactly the work this crate does — common-header pack/unpack,
//! TLV parameter encode/decode, and the Protocol Data copy path — with no I/O.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use m3ua::{M3uaMessage, ProtocolData};

/// A representative MTP3-User payload (synthetic: a short SCCP-ish body). Length
/// is what matters for the copy path, not the contents.
fn sample_user_data() -> Vec<u8> {
    let mut ud = vec![0x09, 0x00, 0x03, 0x05, 0x0a, 0x0b, 0x0c, 0x0d];
    ud.extend_from_slice(&[0xAB; 24]);
    ud
}

fn bench_codec(c: &mut Criterion) {
    // Transfer: a DATA message carrying Protocol Data (the hot path).
    let pd = ProtocolData::new(0x0011_2233, 0x0044_5566, 3, 2, 0, 5, sample_user_data());
    let data = M3uaMessage::data(None, Some(42), pd, None);

    // SSNM: a DUNA advertising three affected point codes.
    let duna = M3uaMessage::duna(Some(42), vec![0x0000_1000, 0x0000_1001, 0x0000_1002]);

    // ASPSM: an ASP-UP with an ASP Identifier + Info String.
    let aspup = M3uaMessage::asp_up(Some(1), Some("bench"));

    let data_bytes = data.encode();
    let duna_bytes = duna.encode();
    let aspup_bytes = aspup.encode();

    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    g.bench_function("data/decode", |b| {
        b.iter(|| M3uaMessage::decode(&data_bytes).unwrap())
    });
    g.bench_function("data/encode", |b| {
        b.iter_batched(|| data.clone(), |m| m.encode(), BatchSize::SmallInput)
    });
    g.bench_function("duna/decode", |b| {
        b.iter(|| M3uaMessage::decode(&duna_bytes).unwrap())
    });
    g.bench_function("duna/encode", |b| {
        b.iter_batched(|| duna.clone(), |m| m.encode(), BatchSize::SmallInput)
    });
    g.bench_function("aspup/decode", |b| {
        b.iter(|| M3uaMessage::decode(&aspup_bytes).unwrap())
    });
    g.bench_function("aspup/encode", |b| {
        b.iter_batched(|| aspup.clone(), |m| m.encode(), BatchSize::SmallInput)
    });

    // The full extraction path a DATA consumer runs: decode + pull the payload.
    g.bench_function("data/decode+protocol_data", |b| {
        b.iter(|| {
            let m = M3uaMessage::decode(&data_bytes).unwrap();
            m.protocol_data().unwrap()
        })
    });
    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
