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
    request_with(addr, method, path, &[], body, timeout)
}

/// Like [request], with extra request headers. Returns the status code, the `Content-Type` and
/// the body.
pub fn request_with(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(u16, String)> {
    request_typed(addr, method, path, headers, body, timeout)
        .map(|(status, _, body)| (status, body))
}

/// Like [request_with], also returning the response's `Content-Type` (empty if none).
pub fn request_typed(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(u16, String, String)> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let body = body.unwrap_or("");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse(&raw)
}

/// Like [request_typed], over TLS with `config` (the node's CA pinned, a client certificate if
/// any). Returns the status, the body, and the server's leaf certificate (DER).
pub fn request_tls(
    addr: SocketAddr,
    config: std::sync::Arc<rustls::ClientConfig>,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(u16, String, Vec<u8>)> {
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let mut connection = rustls::ClientConnection::new(config, name)
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nAccept: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        // A server that closes without `close_notify` after a complete answer.
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(err) => return Err(err),
    }
    let leaf = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|certificate| certificate.as_ref().to_vec())
        .unwrap_or_default();
    let (status, _, body) = parse(&raw)?;
    Ok((status, body, leaf))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn parse(raw: &[u8]) -> io::Result<(u16, String, String)> {
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
    let headers: Vec<String> = lines.map(str::to_ascii_lowercase).collect();
    let chunked = headers
        .iter()
        .any(|line| line.starts_with("transfer-encoding: chunked"));
    let content_type = headers
        .iter()
        .find_map(|line| line.strip_prefix("content-type:"))
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_string()
    };
    Ok((status, content_type, body))
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
