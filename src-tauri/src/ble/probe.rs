//! BLE probe — a diagnostic CLI used to learn the GATT layout from a real phone
//! (build-order step 2/3). Run as:
//!
//! ```text
//!   olink ble-probe scan [seconds]   # list nearby BLE advertisers
//!   olink ble-probe advertise        # advertise 0xAA16, log everything
//! ```
//!
//! `advertise` is effectively our own capture tool: every connect, read, write
//! (hex-dumped), MTU and notify subscription the phone performs is logged, which
//! is exactly the information the open GATT-layout question needs.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use bluer::adv::Advertisement;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use bluer::{AdapterEvent, DeviceEvent, DeviceProperty, DiscoveryFilter, DiscoveryTransport, Uuid};
use futures_util::{pin_mut, StreamExt};

use super::{PAIRING_AUX_UUID, PAIRING_SERVICE_UUID};

fn uuid(s: &str) -> Uuid {
    s.parse().expect("valid uuid literal")
}

/// Short form for SIG-base UUIDs (`0000xxxx-0000-1000-8000-00805f9b34fb` → `0xXXXX`).
fn short(u: &Uuid) -> String {
    let s = u.to_string();
    if s.starts_with("0000") && s.ends_with("-0000-1000-8000-00805f9b34fb") {
        format!("0x{}", s[4..8].to_uppercase())
    } else {
        s
    }
}

fn is_interesting(uuids: &HashSet<Uuid>, svc: &BTreeMap<Uuid, Vec<u8>>) -> bool {
    let targets = [uuid(PAIRING_SERVICE_UUID), uuid(PAIRING_AUX_UUID)];
    targets.iter().any(|t| uuids.contains(t) || svc.contains_key(t))
}

/// Entry point for `ble-probe <mode>`.
pub async fn run(args: &[String]) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("scan") => {
            let secs = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(30);
            scan(secs).await
        }
        Some("advertise") => advertise().await,
        Some("att") => {
            let addr: bluer::Address = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: ble-probe att <MAC>"))?
                .parse()?;
            att_dump(addr).await
        }
        Some("listen") => {
            let addr: bluer::Address = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: ble-probe listen <MAC> [seconds]"))?
                .parse()?;
            let secs = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(60);
            att_listen(addr, secs).await
        }
        Some("gatt") => {
            let addr: bluer::Address = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: ble-probe gatt <MAC>"))?
                .parse()?;
            gatt_dump(addr).await
        }
        _ => {
            eprintln!("usage: ble-probe scan [seconds] | ble-probe advertise | ble-probe gatt <MAC>");
            Ok(())
        }
    }
}

async fn adapter() -> anyhow::Result<bluer::Adapter> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;
    println!(
        "adapter {} ({}) powered",
        adapter.name(),
        adapter.address().await?
    );
    Ok(adapter)
}

async fn describe(adapter: &bluer::Adapter, addr: bluer::Address) -> anyhow::Result<()> {
    let dev = adapter.device(addr)?;
    let name = dev.name().await?.unwrap_or_default();
    let rssi = dev.rssi().await?.map(|r| r.to_string()).unwrap_or("-".into());
    let uuids = dev.uuids().await?.unwrap_or_default();
    let svc = dev.service_data().await?.unwrap_or_default();
    let mfr = dev.manufacturer_data().await?.unwrap_or_default();

    let flag = if is_interesting(&uuids, &svc.clone().into_iter().collect()) {
        "  <<< AA16/AA17 >>>"
    } else {
        ""
    };
    println!("\n{addr}  rssi {rssi}  name {name:?}{flag}");
    if !uuids.is_empty() {
        let list: Vec<_> = uuids.iter().map(short).collect();
        println!("    service uuids: {}", list.join(", "));
    }
    for (u, data) in &svc {
        println!("    service data {}: {}", short(u), hex::encode(data));
    }
    for (company, data) in &mfr {
        println!("    manufacturer 0x{company:04X}: {}", hex::encode(data));
    }
    Ok(())
}

/// Passive-ish LE scan, printing each advertiser and any change to its data.
async fn scan(secs: u64) -> anyhow::Result<()> {
    let adapter = adapter().await?;
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            duplicate_data: true,
            ..Default::default()
        })
        .await?;
    println!("scanning BLE for {secs}s — open O+ Connect on the phone now…");
    let events = adapter.discover_devices().await?;
    pin_mut!(events);
    let deadline = tokio::time::sleep(Duration::from_secs(secs));
    tokio::pin!(deadline);
    let mut seen = HashSet::new();
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            ev = events.next() => match ev {
                Some(AdapterEvent::DeviceAdded(addr)) => {
                    if !seen.insert(addr) { continue; }
                    let _ = describe(&adapter, addr).await;
                    // Re-describe whenever its advertised data changes (e.g. the
                    // phone starts beaconing once O+ Connect is opened).
                    let adapter = adapter.clone();
                    tokio::spawn(async move {
                        let Ok(dev) = adapter.device(addr) else { return };
                        let Ok(ev) = dev.events().await else { return };
                        pin_mut!(ev);
                        while let Some(DeviceEvent::PropertyChanged(p)) = ev.next().await {
                            if matches!(p, DeviceProperty::Uuids(_) | DeviceProperty::ServiceData(_)
                                | DeviceProperty::ManufacturerData(_) | DeviceProperty::Name(_)) {
                                print!("\n(changed)");
                                let _ = describe(&adapter, addr).await;
                            }
                        }
                    });
                }
                Some(_) => {}
                None => break,
            }
        }
    }
    println!("\nscan done — {} devices seen", seen.len());
    Ok(())
}

/// Advertise the pairing service and log everything a central does to it.
async fn advertise() -> anyhow::Result<()> {
    let adapter = adapter().await?;
    let svc_uuid = uuid(PAIRING_SERVICE_UUID);
    let aux_uuid = uuid(PAIRING_AUX_UUID);

    // One permissive characteristic per UUID so whatever the phone tries
    // (read / write / write-without-response / notify) succeeds and gets logged.
    let probe_char = |label: &'static str, u: Uuid| Characteristic {
        uuid: u,
        read: Some(CharacteristicRead {
            read: true,
            fun: Box::new(move |req| {
                Box::pin(async move {
                    println!(
                        "[{label}] READ  from {} offset {} mtu {}",
                        req.device_address, req.offset, req.mtu
                    );
                    Ok(vec![])
                })
            }),
            ..Default::default()
        }),
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |value, req| {
                Box::pin(async move {
                    println!(
                        "[{label}] WRITE from {} {:?} offset {} mtu {} len {}\n    {}",
                        req.device_address,
                        req.op_type,
                        req.offset,
                        req.mtu,
                        value.len(),
                        hex::encode(&value)
                    );
                    Ok(())
                })
            })),
            ..Default::default()
        }),
        notify: Some(CharacteristicNotify {
            notify: true,
            indicate: true,
            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                Box::pin(async move {
                    println!(
                        "[{label}] SUBSCRIBE (confirming={}) — phone wants notifications here",
                        notifier.confirming()
                    );
                    // Keep the notifier alive until the phone unsubscribes.
                    tokio::spawn(async move {
                        let n = notifier;
                        n.stopped().await;
                        println!("[{label}] UNSUBSCRIBE");
                    });
                })
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Mirror the phone's verified layout (service 0xAA15 > AA16/AA17/AA20), and
    // keep the docs' original guess (service 0xAA16) alongside it.
    let aa15 = uuid("0000aa15-0000-1000-8000-00805f9b34fb");
    let aa20 = uuid("0000aa20-0000-1000-8000-00805f9b34fb");
    let app = Application {
        services: vec![
            Service {
                uuid: aa15,
                primary: true,
                characteristics: vec![
                    probe_char("AA15/AA16", svc_uuid),
                    probe_char("AA15/AA17", aux_uuid),
                    probe_char("AA15/AA20", aa20),
                ],
                ..Default::default()
            },
            Service {
                uuid: svc_uuid,
                primary: true,
                characteristics: vec![probe_char("AA16/AA16", svc_uuid), probe_char("AA16/AA17", aux_uuid)],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let _app_handle = adapter.serve_gatt_application(app).await?;

    let adv = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: [aa15, svc_uuid].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("Linux".into()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(adv).await?;
    println!(
        "advertising service 0xAA16 (+0xAA17). Leave this running and trigger a pair from \
         the phone. Ctrl+C to stop."
    );

    // Watch connections so we see the phone arrive/leave even if it never touches
    // our characteristics.
    let events = adapter.events().await?;
    pin_mut!(events);
    while let Some(ev) = events.next().await {
        if let AdapterEvent::DeviceAdded(addr) = ev {
            let dev = adapter.device(addr)?;
            if dev.is_connected().await.unwrap_or(false) {
                println!("CONNECTED  {addr}");
            }
            let adapter = adapter.clone();
            tokio::spawn(async move {
                let Ok(dev) = adapter.device(addr) else { return };
                let Ok(ev) = dev.events().await else { return };
                pin_mut!(ev);
                while let Some(DeviceEvent::PropertyChanged(p)) = ev.next().await {
                    match p {
                        DeviceProperty::Connected(true) => {
                            let name = dev.name().await.ok().flatten().unwrap_or_default();
                            println!("CONNECTED  {addr} {name:?}");
                        }
                        DeviceProperty::Connected(false) => println!("DISCONNECTED {addr}"),
                        DeviceProperty::ServicesResolved(true) => {
                            println!("           {addr} services resolved")
                        }
                        _ => {}
                    }
                }
            });
        }
    }
    Ok(())
}

/// Connect to a peer (central role) and dump its whole GATT tree, reading every
/// readable characteristic and descriptor. Read-only: never writes.
async fn gatt_dump(addr: bluer::Address) -> anyhow::Result<()> {
    let adapter = adapter().await?;
    let dev = adapter.device(addr)?;
    println!("device {addr} name {:?} paired {} connected {}",
        dev.name().await?, dev.is_paired().await?, dev.is_connected().await?);
    if !dev.is_connected().await? {
        println!("connecting…");
        dev.connect().await?;
    }
    for _ in 0..40 {
        if dev.is_services_resolved().await? { break; }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    for svc in dev.services().await? {
        println!("\nSERVICE {}  primary {}", short(&svc.uuid().await?), svc.primary().await?);
        for ch in svc.characteristics().await? {
            let flags = ch.flags().await?;
            let mut f = vec![];
            if flags.read { f.push("read"); }
            if flags.write { f.push("write"); }
            if flags.write_without_response { f.push("write-no-resp"); }
            if flags.notify { f.push("notify"); }
            if flags.indicate { f.push("indicate"); }
            if flags.encrypt_read || flags.encrypt_write || flags.encrypt_authenticated_read
                || flags.encrypt_authenticated_write { f.push("(encrypted)"); }
            println!("  CHAR {}  [{}]", short(&ch.uuid().await?), f.join(" "));
            if flags.read {
                match ch.read().await {
                    Ok(v) => println!("       value {} {:?}", hex::encode(&v),
                        String::from_utf8_lossy(&v)),
                    Err(e) => println!("       read failed: {e}"),
                }
            }
            for d in ch.descriptors().await? {
                let v = d.read().await.map(|v| hex::encode(v)).unwrap_or_else(|e| format!("({e})"));
                println!("       DESC {}  {}", short(&d.uuid().await?), v);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw ATT client over BR/EDR L2CAP PSM 31 (read-only). Used when the phone is
// linked over classic Bluetooth and BlueZ hasn't resolved its GATT services.
// ---------------------------------------------------------------------------

struct Att {
    sock: bluer::l2cap::SeqPacket,
}

impl Att {
    async fn req(&self, pdu: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sock.send(pdu).await?;
        let mut buf = vec![0u8; 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), self.sock.recv(&mut buf)).await??;
            let r = buf[..n].to_vec();
            // Skip server-initiated notifications/indications (0x1B / 0x1D).
            if matches!(r.first(), Some(0x1B) | Some(0x1D)) {
                if r[0] == 0x1D { self.sock.send(&[0x1E]).await?; }
                println!("    (unsolicited {:02x}: {})", r[0], hex::encode(&r));
                continue;
            }
            return Ok(r);
        }
    }
}

fn att_uuid(b: &[u8]) -> String {
    match b.len() {
        2 => format!("0x{:04X}", u16::from_le_bytes([b[0], b[1]])),
        16 => {
            let mut be = b.to_vec();
            be.reverse();
            short(&Uuid::from_slice(&be).unwrap())
        }
        _ => hex::encode(b),
    }
}

async fn att_dump(addr: bluer::Address) -> anyhow::Result<()> {
    let att = att_connect(addr).await?;

    // MTU exchange (we offer 512).
    let r = att.req(&[0x02, 0x00, 0x02]).await?;
    println!("MTU response {}", hex::encode(&r));

    // 1. Primary services: Read By Group Type 0x2800.
    let mut services = vec![];
    let mut start: u16 = 1;
    loop {
        let mut q = vec![0x10];
        q.extend(start.to_le_bytes());
        q.extend(0xFFFFu16.to_le_bytes());
        q.extend(0x2800u16.to_le_bytes());
        let r = att.req(&q).await?;
        if r[0] != 0x11 { break; }
        let len = r[1] as usize;
        let mut end = 0;
        for e in r[2..].chunks(len) {
            let s = u16::from_le_bytes([e[0], e[1]]);
            end = u16::from_le_bytes([e[2], e[3]]);
            services.push((s, end, att_uuid(&e[4..])));
        }
        if end == 0xFFFF { break; }
        start = end + 1;
    }

    for (s, e, u) in &services {
        println!("\nSERVICE {u}  handles 0x{s:04x}-0x{e:04x}");
        // 2. Characteristic declarations: Read By Type 0x2803.
        let mut chars = vec![];
        let mut start = *s;
        while start <= *e {
            let mut q = vec![0x08];
            q.extend(start.to_le_bytes());
            q.extend(e.to_le_bytes());
            q.extend(0x2803u16.to_le_bytes());
            let r = att.req(&q).await?;
            if r[0] != 0x09 { break; }
            let len = r[1] as usize;
            let mut last = start;
            for d in r[2..].chunks(len) {
                let decl = u16::from_le_bytes([d[0], d[1]]);
                let props = d[2];
                let val = u16::from_le_bytes([d[3], d[4]]);
                chars.push((decl, props, val, att_uuid(&d[5..])));
                last = decl;
            }
            if last == 0xFFFF { break; }
            start = last + 1;
        }
        for (i, (decl, props, val, u)) in chars.iter().enumerate() {
            let mut f = vec![];
            for (bit, n) in [(0x02, "read"), (0x04, "write-no-resp"), (0x08, "write"),
                             (0x10, "notify"), (0x20, "indicate"), (0x40, "signed-write")] {
                if props & bit != 0 { f.push(n); }
            }
            println!("  CHAR {u}  value-handle 0x{val:04x}  [{}]", f.join(" "));
            if props & 0x02 != 0 {
                let mut q = vec![0x0A];
                q.extend(val.to_le_bytes());
                let r = att.req(&q).await?;
                if r[0] == 0x0B {
                    println!("       value {} {:?}", hex::encode(&r[1..]), String::from_utf8_lossy(&r[1..]));
                } else {
                    println!("       read error {}", hex::encode(&r));
                }
            }
            // 3. Descriptors between this value handle and the next declaration.
            let dend = chars.get(i + 1).map(|c| c.0 - 1).unwrap_or(*e);
            if *val < dend {
                let mut q = vec![0x04];
                q.extend((val + 1).to_le_bytes());
                q.extend(dend.to_le_bytes());
                let r = att.req(&q).await?;
                if r[0] == 0x05 {
                    let step = if r[1] == 1 { 4 } else { 18 };
                    for d in r[2..].chunks(step) {
                        let h = u16::from_le_bytes([d[0], d[1]]);
                        println!("       DESC {}  handle 0x{h:04x}", att_uuid(&d[2..]));
                    }
                }
            }
        }
        let _ = decl_unused(&chars);
    }
    Ok(())
}

fn decl_unused<T>(_: &T) {}

async fn att_connect(addr: bluer::Address) -> anyhow::Result<Att> {
    let _adapter = adapter().await?;
    let sa = bluer::l2cap::SocketAddr::new(addr, bluer::AddressType::BrEdr, 31);
    println!("opening ATT (L2CAP PSM 31) to {addr}…");
    let mut last_err = None;
    let mut sock = None;
    for level in [bluer::l2cap::SecurityLevel::Medium, bluer::l2cap::SecurityLevel::Low,
                  bluer::l2cap::SecurityLevel::High] {
        let s = bluer::l2cap::Socket::<bluer::l2cap::SeqPacket>::new_seq_packet()?;
        s.bind(bluer::l2cap::SocketAddr::any_br_edr())?;
        s.set_security(bluer::l2cap::Security { level, key_size: 0 })?;
        match s.connect(sa).await {
            Ok(c) => { println!("connected with security {level:?}"); sock = Some(c); break; }
            Err(e) => { println!("  security {level:?}: {e}"); last_err = Some(e); }
        }
    }
    let Some(sock) = sock else { return Err(last_err.unwrap().into()) };
    // The kernel can report "connected" before L2CAP configuration finishes;
    // give the config exchange a moment before the first PDU.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let att = Att { sock };
    Ok(att)
}

/// Subscribe to the pairing characteristic AA16 (notify + indicate), read the
/// AA18 descriptor and AA20, then print whatever the phone pushes. Writes only
/// the CCCD (subscription); never writes AA17.
async fn att_listen(addr: bluer::Address, secs: u64) -> anyhow::Result<()> {
    let att = att_connect(addr).await?;
    let _ = att.req(&[0x02, 0x00, 0x02]).await?; // MTU 512
    for (label, h) in [("AA16 value", 0x0092u16), ("AA18 desc", 0x0093), ("AA20 value", 0x0098)] {
        let mut q = vec![0x0A];
        q.extend(h.to_le_bytes());
        let r = att.req(&q).await?;
        println!("read {label} (0x{h:04x}): {}", hex::encode(&r));
    }
    // CCCD 0x0094 <- 0x0003 (notifications + indications).
    let r = att.req(&[0x12, 0x94, 0x00, 0x03, 0x00]).await?;
    println!("subscribe AA16: {}", hex::encode(&r));
    println!("listening {secs}s for anything the phone sends…");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut buf = vec![0u8; 1024];
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, att.sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let r = &buf[..n];
                println!("RECV op {:02x} len {}: {}", r[0], n, hex::encode(r));
                if r[0] == 0x1D { att.sock.send(&[0x1E]).await?; }
            }
            Ok(Err(e)) => { println!("socket closed: {e}"); break; }
            Err(_) => break,
        }
    }
    println!("done");
    Ok(())
}
