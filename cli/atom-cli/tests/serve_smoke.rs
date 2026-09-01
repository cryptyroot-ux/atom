use std::io::{Read, Write};
use std::net::TcpListener;

use atom_ledger::HmacSha256Signer;
use atom_server::app::serve;
use atom_server::store::Store;

/// Finds a free ephemeral port, returns it, and releases the listener so the
/// server can bind it.
fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn serve_health_reports_healthy() {
    let port = ephemeral_port();
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let signer = Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ));
    let store = Store::open_in_memory(signer).unwrap();
    let handle = tokio::spawn(async move {
        serve("0.0.0-alpha", 24, addr, store).await.unwrap();
    });

    let body = wait_for_health(port).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "healthy");

    handle.abort();
}

async fn wait_for_health(port: u16) -> String {
    for _ in 0..100 {
        if let Ok(Some(body)) = tokio::task::spawn_blocking(move || try_get(port, "/health")).await
        {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server never became healthy");
}

fn try_get(port: u16, path: &str) -> Option<String> {
    use std::time::Duration;
    let stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut stream = stream;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    if body.contains("healthy") {
        Some(body.to_owned())
    } else {
        None
    }
}
