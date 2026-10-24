//! Fixture-only test runner. Arguments name local fixture directories, not keys.
use std::{path::PathBuf, time::Duration};
use tailfeather_hosted::{Client, Config};
fn config(root: &std::path::Path, name: &str, auth: String) -> Config {
    Config {
        directory: root.join(name),
        control_url: "https://localhost:18443".into(),
        hostname: name.into(),
        auth_key: auth,
        control_ca_der: std::fs::read(root.join("ca.der")).unwrap(),
        relay_only: !std::env::args().any(|arg| arg == "--direct"),
        ephemeral: std::env::args().any(|arg| arg == "--ephemeral"),
    }
}
fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let root = PathBuf::from(std::env::args_os().nth(1).expect("fixture directory"));
    let keys: Vec<String> =
        serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let server=Client::start(config(&root,"hosted-server",keys[0].clone())).unwrap();
        let client=Client::start(config(&root,"hosted-client",keys[1].clone())).unwrap();
        let server_ip=tokio::time::timeout(Duration::from_secs(60),server.ready()).await.unwrap().unwrap();
        let client_ip=tokio::time::timeout(Duration::from_secs(60),client.ready()).await.unwrap().unwrap();
        println!("PASS: real Headscale registration/map with private CA; server={server_ip}, client={client_ip}");
        if std::env::args().any(|arg|arg=="--offline-direct") {
            println!("READY: stop the fixture, then create continue in its directory");
            use std::io::Write;std::io::stdout().flush().unwrap();
            tokio::time::timeout(Duration::from_secs(60),async { while !root.join("continue").exists(){tokio::time::sleep(Duration::from_millis(20)).await;} }).await.unwrap();
        }
        assert!(tailfeather_hosted::is_enrolled(&root.join("hosted-server"),"https://localhost:18443").unwrap());
        assert!(tailfeather_hosted::is_enrolled(&root.join("hosted-server"),"https://other.invalid").is_err());
        let mut listener=server.listen(2222).await.unwrap();
        assert_eq!(server.drain().await.unwrap_err().kind(),std::io::ErrorKind::InvalidInput);
        let mut from=client.connect(server_ip,2222).await.unwrap();
        let mut to=tokio::time::timeout(Duration::from_secs(30),listener.accept()).await.unwrap().unwrap();
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        from.write_all(&[0,1,2,255,10]).await.unwrap();
        let mut input=[0;5];tokio::time::timeout(Duration::from_secs(10),to.read_exact(&mut input)).await.unwrap().unwrap();assert_eq!(input,[0,1,2,255,10]);
        to.write_all(b"round-trip").await.unwrap();
        let mut echoed=[0;10];tokio::time::timeout(Duration::from_secs(10),from.read_exact(&mut echoed)).await.unwrap().unwrap();assert_eq!(&echoed,b"round-trip");
        let mode=if std::env::args().any(|arg|arg=="--direct") {"direct UDP"}else{"DERP"};
        println!("PASS: userspace TCP binary round trip over real private-CA Headscale {mode}");
        let payload=vec![0x5a;1024*1024];let mut received=vec![0;payload.len()];
        let transferred=tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(10),async {
            let (sent,read)=tokio::join!(from.write_all(&payload),to.read_exact(&mut received));
            sent.unwrap();read.unwrap();
        }).await.unwrap();
        assert_eq!(payload,received);
        println!("PASS: 1 MiB {mode} transfer in {:?}",transferred.elapsed());
        from.write_all(b"final-write").await.unwrap();
        drop(from);
        client.drain().await.unwrap();
        drop(client);
        let mut final_bytes=[0;11];
        tokio::time::timeout(Duration::from_secs(5),to.read_exact(&mut final_bytes)).await.unwrap().unwrap();
        assert_eq!(&final_bytes,b"final-write");
        assert_eq!(tokio::time::timeout(Duration::from_secs(5),to.read(&mut final_bytes)).await.unwrap().unwrap(),0);
        println!("PASS: final bytes and FIN drain before the client node shuts down");
        if std::env::args().any(|arg|arg=="--offline-direct") {
            println!("PASS: direct TCP works with control and DERP offline");return;
        }
        drop(to);drop(listener);drop(server);
        let client=Client::start(config(&root,"hosted-client",String::new())).unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(60),client.ready()).await.unwrap().unwrap(),client_ip);
        println!("PASS: session identity reconnects without an auth key and keeps its address");
        let rejected=Client::start(config(&root,"hosted-rejected","fixture-invalid-key".into())).unwrap();
        let error=tokio::time::timeout(Duration::from_secs(10),rejected.ready()).await.unwrap().unwrap_err();
        assert_eq!(error.to_string(),"registration rejected");
        println!("PASS: rejected preauth key returns an error instead of hanging ready()");
    });
}
