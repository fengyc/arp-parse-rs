# arp-parse

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

## License

MIT
