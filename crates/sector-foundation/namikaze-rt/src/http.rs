// SPDX-License-Identifier: MPL-2.0
//! Minimal HTTP/1.1 server for loopback services (namikaze-share,
//! namikaze-mirror). Thread-per-connection, request-line + headers only,
//! bodies are read with Content-Length. This is deliberately not a general
//! web framework: only what the two shipped services need.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

/// An incoming request.
pub struct Request {
    /// Method token (GET/HEAD/...).
    pub method: String,
    /// Request target without the query string.
    pub path: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
}

impl Request {
    #[allow(dead_code)]
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A response under construction.
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    /// Text response.
    pub fn text(status: u16, body: &str) -> Self {
        Self { status, content_type: "text/plain; charset=utf-8", body: Vec::from(body) }
    }

    /// Binary response.
    pub fn bytes(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self { status, content_type, body }
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

/// A bound server; iterate incoming requests with [`Server::incoming`].
pub struct Server {
    listener: TcpListener,
}

impl Server {
    /// Bind to `addr:port` (e.g. "127.0.0.1:8900").
    pub fn bind(addr: &str, port: u16) -> crate::Result<Self> {
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self { listener })
    }

    /// The local port actually bound (useful with port 0).
    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Handle connections forever, one thread each. The handler returns the
    /// response for every request; a panic in the handler becomes a 500.
    pub fn serve<F>(&self, handler: F) -> crate::Result<()>
    where
        F: Fn(&Request) -> Response + Send + Sync + 'static,
    {
        let handler = std::sync::Arc::new(handler);
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = std::sync::Arc::clone(&handler);
            std::thread::spawn(move || {
                let _ = handle_conn(stream, handler.as_ref());
            });
        }
        Ok(())
    }
}

fn handle_conn<F>(stream: TcpStream, handler: &F) -> std::io::Result<()>
where
    F: Fn(&Request) -> Response,
{
    let peer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        return Ok(());
    }
    let path = target.split('?').next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    // Drain the body (Content-Length) so keep-alive pipelines stay aligned.
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if len > 0 {
        let mut sink = vec![0u8; len.min(64 * 1024 * 1024)];
        reader.read_exact(&mut sink)?;
    }
    let req = Request { method, path, headers };
    let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&req)))
        .unwrap_or_else(|_| Response::text(500, "internal server error"));
    write_response(peer, &req.method, &resp)
}

fn write_response(mut stream: TcpStream, method: &str, resp: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        status_text(resp.status),
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(&resp.body)?;
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_serve_one_request() {
        let server = Server::bind("127.0.0.1", 0).unwrap();
        let port = server.local_port();
        let handle = std::thread::spawn(move || {
            server
                .serve(|req| {
                    if req.path == "/hi" {
                        Response::text(200, "hello")
                    } else {
                        Response::text(404, "no")
                    }
                })
                .unwrap()
        });
        // small race window is fine: retry connect
        let mut ok = false;
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ok, "server did not come up");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"GET /hi HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = String::new();
        BufReader::new(s).read_line(&mut buf).unwrap();
        assert!(buf.starts_with("HTTP/1.1 200 OK"), "{buf}");
        handle.thread().unpark();
    }
}
