# arp-parse

[![Main](https://github.com/fengyc/arp-parse-rs/actions/workflows/main.yml/badge.svg)](https://github.com/fengyc/arp-parse-rs/actions/workflows/main.yml)

RFC826 ARP packet parsing and building.

## Examples

Parse arp frame

    let buff = [...];
    let slice = arp_parse::parse(&buff).unwrap();
    let op_code = slice.op_code();
    ...

Build arp frame

    let mut buff = [...];
    let builder = ARPSliceBuilder::new(buff).unwrap();

There are some examples in test cases.

## License

MIT
