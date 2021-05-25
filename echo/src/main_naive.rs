use futures_lite::{AsyncReadExt, AsyncWriteExt};
use glommio::net::TcpListener;
use glommio::prelude::*;

fn main() {
    let server_handle = LocalExecutorBuilder::new()
        .spawn(|| async move {

            let listener = TcpListener::bind("127.0.0.1:10000").unwrap();
            println!("Server Listening on {}", listener.local_addr().unwrap());
            let mut stream = listener.accept().await.unwrap();
            loop {
                let mut buf = [0u8; 16];
                let bytes_read = stream.read(&mut buf).await.unwrap();
                if bytes_read == 0 {
                    break;
                } else {
                    stream.write(&buf).await.unwrap();
                    println!("Echoed: {}", String::from_utf8_lossy(&buf));
                }
            }

        })
        .unwrap();

    server_handle.join().unwrap();
}
