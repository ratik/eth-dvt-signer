//! A minimal HTTP/1.1 client (one request per connection), enough for the node's JSON API.

use std::{
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

/// Send `method path` with an optional JSON body. Returns the status code and the body.
pub fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse(&raw)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn parse(raw: &[u8]) -> io::Result<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| invalid("no end of headers"))?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("bad status line"))?;
    let chunked = lines.any(|line| {
        line.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    });
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_string()
    };
    Ok((status, body))
}

fn dechunk(mut body: &str) -> io::Result<String> {
    let mut out = String::new();
    loop {
        let (size, rest) = body
            .split_once("\r\n")
            .ok_or_else(|| invalid("bad chunk"))?;
        let size = usize::from_str_radix(size.trim(), 16).map_err(|_| invalid("bad chunk size"))?;
        if size == 0 {
            return Ok(out);
        }
        out.push_str(rest.get(..size).ok_or_else(|| invalid("short chunk"))?);
        body = rest.get(size + 2..).unwrap_or("");
    }
}

/// Send a request and return the open connection without reading the answer: dropping it hangs up
/// (a client that gave up).
pub fn open(addr: SocketAddr, method: &str, path: &str, body: &str) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(stream)
}
