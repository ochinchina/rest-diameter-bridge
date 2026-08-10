use crate::alarm::AlarmSender;
use crate::avp::{Avp, AvpCode, AvpFlags, AvpMap, name_value_to_avp};
use crate::command::{Command, CommandBuffer, CommandCode, CommandFlags, CommandMap};
use crate::config::StackCapability;


use crate::transport::{
    CommandProcessorContext, Connection, ConnectionManager, HopByHopIdMapper, IdGenerator, AnswerManager, RedirectHostManager,CommandHandler
};

use crate::utils::create_capability_avps;
use crate::utils::{is_empty_file};
use dtls::config::Config as DtlsConfig;
use dtls::conn::DTLSConn;
use dtls::crypto::Certificate as DtlsCertificate;
use log::{debug, error, info};

use serde_json::Value;
use webrtc_util::Error;
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use webrtc_util::conn::Conn as DtlsTransport;

#[cfg(target_os = "linux")]
mod sctp {
    use std::io;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    const IPPROTO_SCTP: libc::c_int = 132;

    pub struct SctpStream {
        inner: AsyncFd<OwnedFd>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    }

    impl SctpStream {
        pub async fn connect(addresses: &[String]) -> Result<Self, String> {
            if addresses.is_empty() {
                return Err("No addresses provided for SCTP connection".to_string());
            }

            // Resolve the first address to determine the address family
            let first_addr: SocketAddr = addresses[0]
                .to_socket_addrs()
                .map_err(|e| format!("Failed to resolve address '{}': {}", addresses[0], e))?
                .next()
                .ok_or_else(|| format!("No address resolved for '{}'", addresses[0]))?;

            let domain = if first_addr.is_ipv6() {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };

            // Create SCTP one-to-one socket
            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, IPPROTO_SCTP) };
            if fd < 0 {
                return Err(format!(
                    "Failed to create SCTP socket: {}",
                    io::Error::last_os_error()
                ));
            }

            let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

            // Set non-blocking
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(format!(
                    "Failed to get socket flags: {}",
                    io::Error::last_os_error()
                ));
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(format!(
                    "Failed to set non-blocking: {}",
                    io::Error::last_os_error()
                ));
            }

            // Use sctp_connectx to connect with multiple addresses (multi-homing)
            let mut sockaddrs: Vec<u8> = Vec::new();
            let mut addr_count = 0usize;

            for addr_str in addresses {
                let addr: SocketAddr = addr_str
                    .to_socket_addrs()
                    .map_err(|e| format!("Failed to resolve address '{}': {}", addr_str, e))?
                    .next()
                    .ok_or_else(|| format!("No address resolved for '{}'", addr_str))?;

                match addr {
                    SocketAddr::V4(v4) => {
                        let sa = libc::sockaddr_in {
                            sin_family: libc::AF_INET as libc::sa_family_t,
                            sin_port: v4.port().to_be(),
                            sin_addr: libc::in_addr {
                                s_addr: u32::from_ne_bytes(v4.ip().octets()),
                            },
                            sin_zero: [0; 8],
                        };
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                &sa as *const _ as *const u8,
                                std::mem::size_of::<libc::sockaddr_in>(),
                            )
                        };
                        sockaddrs.extend_from_slice(bytes);
                    }
                    SocketAddr::V6(v6) => {
                        let sa = libc::sockaddr_in6 {
                            sin6_family: libc::AF_INET6 as libc::sa_family_t,
                            sin6_port: v6.port().to_be(),
                            sin6_flowinfo: v6.flowinfo(),
                            sin6_addr: libc::in6_addr {
                                s6_addr: v6.ip().octets(),
                            },
                            sin6_scope_id: v6.scope_id(),
                        };
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                &sa as *const _ as *const u8,
                                std::mem::size_of::<libc::sockaddr_in6>(),
                            )
                        };
                        sockaddrs.extend_from_slice(bytes);
                    }
                }
                addr_count += 1;
            }

            // Initiate non-blocking connect
            let ret = unsafe {
                libc::connect(
                    fd,
                    sockaddrs.as_ptr() as *const libc::sockaddr,
                    if first_addr.is_ipv6() {
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                    } else {
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                    },
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err(format!("SCTP connect failed: {}", err));
                }
            }

            // Wrap in AsyncFd for tokio integration
            let async_fd =
                AsyncFd::new(owned_fd).map_err(|e| format!("Failed to create AsyncFd: {}", e))?;

            // Wait for connect to complete
            loop {
                let mut guard = async_fd
                    .writable()
                    .await
                    .map_err(|e| format!("Failed waiting for SCTP connect: {}", e))?;

                // Check SO_ERROR to see if connect succeeded
                let mut err: libc::c_int = 0;
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                let ret = unsafe {
                    libc::getsockopt(
                        async_fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut err as *mut _ as *mut libc::c_void,
                        &mut len,
                    )
                };
                if ret < 0 {
                    return Err(format!(
                        "getsockopt SO_ERROR failed: {}",
                        io::Error::last_os_error()
                    ));
                }
                if err == 0 {
                    guard.clear_ready();
                    break;
                } else if err == libc::EINPROGRESS {
                    guard.clear_ready();
                    continue;
                } else {
                    return Err(format!(
                        "SCTP connect failed: {}",
                        io::Error::from_raw_os_error(err)
                    ));
                }
            }

            // If we have multiple addresses, bind additional local addresses via sctp_bindx
            // For connectx with multiple remote addresses, use SCTP_SOCKOPT_CONNECTX
            if addr_count > 1 {
                // Use setsockopt SCTP_SOCKOPT_CONNECTX for multi-homed connection
                // This is already handled by the initial connect for the primary address;
                // additional peer addresses can be added via sctp_connectx if available
                // For simplicity, we connect to the first address and the SCTP stack
                // will handle path failover if the peer advertises multiple addresses in INIT-ACK
            }

            let local_addr = socket_addr(async_fd.as_raw_fd(), false)?;

            Ok(SctpStream {
                inner: async_fd,
                local_addr,
                remote_addr: first_addr,
            })
        }

        pub async fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| format!("Failed waiting for readable: {}", e))?;

                let ret = unsafe {
                    libc::recv(
                        self.inner.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };

                if ret >= 0 {
                    guard.clear_ready();
                    return Ok(ret as usize);
                }

                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(format!("SCTP read error: {}", err));
            }
        }

        pub async fn read_exact(&self, buf: &mut [u8]) -> Result<(), String> {
            let mut offset = 0;
            while offset < buf.len() {
                let n = self.read(&mut buf[offset..]).await?;
                if n == 0 {
                    return Err("SCTP connection closed unexpectedly".to_string());
                }
                offset += n;
            }
            Ok(())
        }

        pub async fn write_all(&self, data: &[u8]) -> Result<(), String> {
            let mut offset = 0;
            while offset < data.len() {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| format!("Failed waiting for writable: {}", e))?;

                let ret = unsafe {
                    libc::send(
                        self.inner.as_raw_fd(),
                        data[offset..].as_ptr() as *const libc::c_void,
                        data.len() - offset,
                        libc::MSG_NOSIGNAL,
                    )
                };

                if ret >= 0 {
                    offset += ret as usize;
                    guard.clear_ready();
                } else {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(format!("SCTP write error: {}", err));
                }
            }
            Ok(())
        }

        pub async fn send_message(&self, data: &[u8]) -> Result<usize, String> {
            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| format!("Failed waiting for writable: {}", e))?;

                let ret = unsafe {
                    libc::send(
                        self.inner.as_raw_fd(),
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };

                if ret >= 0 {
                    guard.clear_ready();
                    return Ok(ret as usize);
                }

                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(format!("SCTP write error: {}", err));
            }
        }

        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        pub fn remote_addr(&self) -> SocketAddr {
            self.remote_addr
        }

        pub async fn shutdown(&self) -> Result<(), String> {
            let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_RDWR) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                // Ignore "not connected" errors during shutdown
                if err.raw_os_error() != Some(libc::ENOTCONN) {
                    return Err(format!("SCTP shutdown error: {}", err));
                }
            }
            Ok(())
        }
    }

    // Safety: The OwnedFd inside AsyncFd is Send + Sync
    unsafe impl Send for SctpStream {}
    unsafe impl Sync for SctpStream {}

    fn socket_addr(fd: libc::c_int, peer: bool) -> Result<SocketAddr, String> {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let ret = unsafe {
            if peer {
                libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len)
            } else {
                libc::getsockname(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len)
            }
        };
        if ret < 0 {
            return Err(format!(
                "Failed to get SCTP socket address: {}",
                io::Error::last_os_error()
            ));
        }

        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                let address = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in) };
                Ok(SocketAddr::new(
                    std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                    u16::from_be(address.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let address = unsafe { &*(&storage as *const _ as *const libc::sockaddr_in6) };
                Ok(SocketAddr::new(
                    std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                    u16::from_be(address.sin6_port),
                ))
            }
            family => Err(format!("Unsupported SCTP address family: {}", family)),
        }
    }

    pub struct SctpListener {
        inner: AsyncFd<OwnedFd>,
    }

    impl SctpListener {
        pub async fn bind(addresses: &[String]) -> Result<Self, String> {
            if addresses.is_empty() {
                return Err("No addresses provided for SCTP listener".to_string());
            }

            let first_addr: SocketAddr = addresses[0]
                .to_socket_addrs()
                .map_err(|e| format!("Failed to resolve address '{}': {}", addresses[0], e))?
                .next()
                .ok_or_else(|| format!("No address resolved for '{}'", addresses[0]))?;

            let domain = if first_addr.is_ipv6() {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };

            let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, IPPROTO_SCTP) };
            if fd < 0 {
                return Err(format!(
                    "Failed to create SCTP socket: {}",
                    io::Error::last_os_error()
                ));
            }

            let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

            // Set SO_REUSEADDR
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }

            // Bind to the first address
            let bind_result = match first_addr {
                SocketAddr::V4(v4) => {
                    let sa = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    unsafe {
                        libc::bind(
                            fd,
                            &sa as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        )
                    }
                }
                SocketAddr::V6(v6) => {
                    let sa = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr {
                            s6_addr: v6.ip().octets(),
                        },
                        sin6_scope_id: v6.scope_id(),
                    };
                    unsafe {
                        libc::bind(
                            fd,
                            &sa as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        )
                    }
                }
            };
            if bind_result < 0 {
                return Err(format!(
                    "Failed to bind SCTP socket to {}: {}",
                    first_addr,
                    io::Error::last_os_error()
                ));
            }

            // Listen
            let ret = unsafe { libc::listen(fd, 128) };
            if ret < 0 {
                return Err(format!(
                    "Failed to listen on SCTP socket: {}",
                    io::Error::last_os_error()
                ));
            }

            // Set non-blocking
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(format!(
                    "Failed to get socket flags: {}",
                    io::Error::last_os_error()
                ));
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(format!(
                    "Failed to set non-blocking: {}",
                    io::Error::last_os_error()
                ));
            }

            let async_fd =
                AsyncFd::new(owned_fd).map_err(|e| format!("Failed to create AsyncFd: {}", e))?;

            Ok(SctpListener { inner: async_fd })
        }

        pub async fn accept(&self) -> Result<(SctpStream, SocketAddr), String> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| format!("Failed waiting for accept: {}", e))?;

                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

                let client_fd = unsafe {
                    libc::accept(
                        self.inner.as_raw_fd(),
                        &mut storage as *mut _ as *mut libc::sockaddr,
                        &mut len,
                    )
                };

                if client_fd < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(format!("SCTP accept error: {}", err));
                }

                guard.clear_ready();

                // Set non-blocking on the accepted socket
                let flags = unsafe { libc::fcntl(client_fd, libc::F_GETFL) };
                if flags < 0 {
                    unsafe { libc::close(client_fd) };
                    return Err(format!(
                        "Failed to get socket flags: {}",
                        io::Error::last_os_error()
                    ));
                }
                let ret =
                    unsafe { libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
                if ret < 0 {
                    unsafe { libc::close(client_fd) };
                    return Err(format!(
                        "Failed to set non-blocking: {}",
                        io::Error::last_os_error()
                    ));
                }

                let owned_fd = unsafe { OwnedFd::from_raw_fd(client_fd) };
                let async_fd = AsyncFd::new(owned_fd)
                    .map_err(|e| format!("Failed to create AsyncFd: {}", e))?;

                let local_addr = socket_addr(client_fd, false)?;
                let remote_addr = socket_addr(client_fd, true)?;

                let stream = SctpStream {
                    inner: async_fd,
                    local_addr,
                    remote_addr,
                };

                return Ok((stream, remote_addr));
            }
        }
    }

    unsafe impl Send for SctpListener {}
    unsafe impl Sync for SctpListener {}
}

#[cfg(target_os = "linux")]
use sctp::SctpListener;
#[cfg(target_os = "linux")]
use sctp::SctpStream;


#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl DtlsTransport for SctpStream {
    async fn connect(&self, _addr: SocketAddr) -> std::result::Result<(), Error> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, Error>{
        self.read(buf)
            .await
            .map_err(|e| std::io::Error::other(e).into())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::result::Result<(usize, SocketAddr), Error> {
        Ok((self.recv(buf).await?, self.remote_addr()))
    }

    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, Error> {
        self.send_message(buf)
            .await
            .map_err(|e| std::io::Error::other(e).into())
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::result::Result<usize, Error> {
        if target != self.remote_addr() {
            return Err(std::io::Error::other(format!(
                "SCTP association is connected to {}, not {}",
                self.remote_addr(),
                target
            ))
            .into());
        }
        self.send(buf).await
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, Error> {
        Ok(SctpStream::local_addr(self))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(SctpStream::remote_addr(self))
    }

    async fn close(&self) -> std::result::Result<(), Error> {
        self.shutdown()
            .await
            .map_err(|e| std::io::Error::other(e).into())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(target_os = "linux")]
enum SctpConnectionStream {
    Plain(Arc<SctpStream>),
    Dtls(Arc<DTLSConn>),
}

#[cfg(target_os = "linux")]
impl SctpConnectionStream {
    async fn read(&self, buffer: &mut [u8]) -> Result<usize, String> {
        match self {
            Self::Plain(stream) => stream.read(buffer).await,
            Self::Dtls(stream) => stream
                .read(buffer, None)
                .await
                .map_err(|e| format!("DTLS read error: {}", e)),
        }
    }

    async fn write_all(&self, data: &[u8]) -> Result<(), String> {
        match self {
            Self::Plain(stream) => stream.write_all(data).await,
            Self::Dtls(stream) => {
                let written = stream
                    .write(data, None)
                    .await
                    .map_err(|e| format!("DTLS write error: {}", e))?;
                if written != data.len() {
                    return Err(format!(
                        "Incomplete DTLS write: wrote {} of {} bytes",
                        written,
                        data.len()
                    ));
                }
                Ok(())
            }
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        match self {
            Self::Plain(stream) => stream.shutdown().await,
            Self::Dtls(stream) => stream
                .close()
                .await
                .map_err(|e| format!("DTLS shutdown error: {}", e)),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct SctpClientConnection {
    // Similar to TcpClientConnection but using SCTP instead of TCP
    addresses: Vec<String>,
    my_host: String,
    my_realm: String,
    peer_host: String,
    peer_realm: String,
    key_file: String,
    cert_file: String,
    ca_cert_file: String,    
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    end_to_end_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    command_map: CommandMap,
    avp_map: AvpMap,
    connection_manager: Arc<Box<ConnectionManager>>,
    answer_manager: Arc<Box<AnswerManager>>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
    command_handler: Arc<dyn CommandHandler + Send + Sync>,
    writer: Arc<Mutex<Option<Arc<SctpConnectionStream>>>>,
}

#[cfg(target_os = "linux")]
impl SctpClientConnection {
    pub fn new(
        addresses: Vec<String>,
        my_host: String,
        my_realm: String,
        peer_host: String,
        peer_realm: String,
        key_file: String,
        cert_file: String,
        ca_cert_file: String,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        end_to_end_id_generator: Arc<Box<IdGenerator>>,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        command_map: CommandMap,
        avp_map: AvpMap,
        connection_manager: Arc<Box<ConnectionManager>>,
        answer_manager: Arc<Box<AnswerManager>>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
        command_handler: Arc<dyn CommandHandler + Send + Sync>
    ) -> Self {
        SctpClientConnection {
            addresses,
            my_host,
            my_realm,
            peer_host,
            peer_realm,
            key_file: key_file,
            cert_file: cert_file,
            ca_cert_file: ca_cert_file,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            hop_by_hop_id_mapper,
            command_map,
            avp_map,
            connection_manager,
            answer_manager,
            redirect_host_manager,
            command_handler,
            writer: Arc::new(Mutex::new(None)),
        }
    }

    
    pub fn spawn_start(&self) {
        let mut connection = self.clone();
        tokio::spawn(async move {
            if let Err(error) = connection.start().await {
                error!("SctpClientConnection start error: {}", error);
            }
        });
    }

    fn dtls_enabled(&self) -> bool {
        !self.cert_file.is_empty()
            && !self.key_file.is_empty()
            && !is_empty_file(&self.cert_file)
            && !is_empty_file(&self.key_file)
    }

    async fn secure_stream(&self, stream: Arc<SctpStream>) -> Result<SctpConnectionStream, String> {
        if !self.dtls_enabled() {
            return Ok(SctpConnectionStream::Plain(stream));
        }

        let key_pem = std::fs::read_to_string(&self.key_file)
            .map_err(|e| format!("Failed to read key file {}: {}", self.key_file, e))?;
        let cert_pem = std::fs::read_to_string(&self.cert_file)
            .map_err(|e| format!("Failed to read cert file {}: {}", self.cert_file, e))?;
        let certificate = DtlsCertificate::from_pem(&format!("{}\n{}", key_pem, cert_pem))
            .map_err(|e| format!("Failed to parse DTLS certificate and PKCS#8 key: {}", e))?;

        let mut roots_cas = rustls::RootCertStore::empty();
        if !self.ca_cert_file.is_empty() && !is_empty_file(&self.ca_cert_file) {
            let ca_pem = std::fs::read(&self.ca_cert_file)
                .map_err(|e| format!("Failed to read CA cert file {}: {}", self.ca_cert_file, e))?;
            for ca_cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
                roots_cas
                    .add(ca_cert.map_err(|e| format!("Failed to parse CA certificate: {}", e))?)
                    .map_err(|e| format!("Failed to add CA certificate: {}", e))?;
            }
        } else {
            roots_cas.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let config = DtlsConfig {
            certificates: vec![certificate],
            roots_cas,
            server_name: self.my_host.clone(),
            ..Default::default()
        };
        let transport: Arc<dyn DtlsTransport + Send + Sync> = stream;
        let dtls = DTLSConn::new(transport, config, true, None)
            .await
            .map_err(|e| format!("DTLS handshake failed: {}", e))?;
        info!("DTLS connection established to {:?}", self.addresses);
        Ok(SctpConnectionStream::Dtls(Arc::new(dtls)))
    }

    pub async fn start(&mut self) -> Result<(), String> {
        loop {
            match SctpStream::connect(&self.addresses).await {
                Ok(stream) => {
                    info!(
                        "Successfully connected to SCTP server at {:?}",
                        self.addresses
                    );
                    let stream = Arc::new(self.secure_stream(Arc::new(stream)).await?);
                    *self.writer.lock().await = Some(stream.clone());
                    self.send_cer().await?;

                    let cea = self.read_command_from_sctp(&stream).await?;
                    info!("Received CEA: {:?}", cea);

                    if cea.code != CommandCode::CapabilitiesExchange as u32 || !cea.is_answer() {
                        return Err(format!(
                            "Expected CEA with command code {}, got {}",
                            CommandCode::CapabilitiesExchange as u32,
                            cea.code
                        ));
                    }

                    if let Some(result_code) = cea.get_result_code() {
                        if result_code / 2000 != 2 {
                            return Err(format!(
                                "Connection rejected by server with result code {}",
                                result_code
                            ));
                        }
                    } else {
                        return Err("CEA response missing Result-Code AVP".to_string());
                    }

                    let reader_stream = stream.clone();
                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) =self_clone.handle_connection(reader_stream).await {
                            error!("SCTP connection error: {}", e);
                        }
                    });

                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to connect to SCTP server at {:?}: {}. Retrying in 5 seconds...",
                        self.addresses, e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn send_cer(&mut self) -> Result<(), String> {
        let cer_command = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            CommandFlags::Request as u8 | CommandFlags::Proxiable as u8,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![],
        );
        self.send(&cer_command).await
    }

    async fn read_command_from_sctp(
        &self,
        stream: &Arc<SctpConnectionStream>,
    ) -> Result<Command, String> {
        let mut length_buffer = [0u8; 4];
        read_exact(stream, &mut length_buffer).await?;
        let message_length = u32::from_be_bytes(length_buffer) & 0x00FFFFFF;
        let mut buffer = vec![0u8; message_length as usize - 4];
        read_exact(stream, &mut buffer).await?;
        let mut command_buffer = CommandBuffer::from_bytes(&length_buffer);
        command_buffer.append(&buffer);
        command_buffer
            .read_command()
            .ok_or_else(|| "Failed to parse command from SCTP stream".to_string())
    }

    async fn handle_connection(&self, stream: Arc<SctpConnectionStream>) -> Result<(), String> {
        let mut buffer = [0u8; 4096];
        let mut command_buffer = CommandBuffer::new();
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    info!("SCTP connection closed by server");
                    return Ok(());
                }
                Ok(n) => {
                    info!("SCTP received {} bytes", n);
                    command_buffer.append(&buffer[..n]);
                    let commands = command_buffer.read_commands();
                    for mut command in commands {
                        info!(
                            "Received {} command: {:?}",
                            if command.is_request() {
                                "request"
                            } else {
                                "answer"
                            },
                            command
                        );
                        self.process_command(&mut command).await?;
                    }
                }
                Err(e) => {
                    error!("Failed to read from SCTP connection: {}", e);
                    return Err(e);
                }
            }
        }
    }

    async fn process_command(&self, command: &mut Command) -> Result<(), String> {
        if command.code == CommandCode::DeviceWatchdog as u32 {
            if command.is_request() {
                self.send_dwa().await?;
            } else {
                info!("Received DWA response from server, connection is healthy");
            }
            return Ok(());
        }

        if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
            return Ok(());
        }

        let context = CommandProcessorContext {
            connection_id: &self.get_id(),  
            my_host: &self.my_host,
            my_realm: &self.my_realm,
            peer_host: &self.peer_host,
            peer_realm: &self.peer_realm,
            command_map: &self.command_map,
            avp_map: &self.avp_map,
            connection_manager: &self.connection_manager,
            hop_by_hop_id_generator: &self.hop_by_hop_id_generator,
            hop_by_hop_id_mapper: &self.hop_by_hop_id_mapper,
            answer_manager: &self.answer_manager,
            command_handler: self.command_handler.as_ref(),
            redirect_host_manager: &self.redirect_host_manager,
        };

        context.process_command(command).await
    }

    async fn send_dwa(&self) -> Result<(), String> {
        let dwa_command = Command::new(
            CommandCode::DeviceWatchdog as u32,
            0,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![],
        );
        self.send(&dwa_command).await
    }

    async fn process_dpr(&self, command: &mut Command) -> Result<(), String> {
        info!("Received DPR request: {:?}", command);
        let dpa_command = Command::new(
            CommandCode::DisconnectPeer as u32,
            0,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![],
        );
        self.send(&dpa_command).await?;
        info!("Sent DPA response: {:?}", dpa_command);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn read_exact(stream: &SctpConnectionStream, buffer: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = stream.read(&mut buffer[offset..]).await?;
        if read == 0 {
            return Err("SCTP connection closed unexpectedly".to_string());
        }
        offset += read;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Connection for SctpClientConnection {
    fn get_id(&self) -> String {
        self.addresses.join(",")
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        let data = command.encode();
        let guard = self.writer.lock().await;
        let stream = guard
            .as_ref()
            .ok_or_else(|| "SCTP connection not established".to_string())?;
        stream.write_all(&data).await
    }

    async fn close(&self) -> Result<(), String> {
        let mut guard = self.writer.lock().await;
        if let Some(stream) = guard.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }

    async fn is_closed(&self) -> bool {
        false
    }

    async fn get_connections(
        &self,
        _connections: &mut Vec<Arc<Box<dyn Connection + Send + Sync>>>,
    ) {
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}

#[cfg(target_os = "linux")]
pub struct SctpDiameterServer {
    my_host: String,
    my_realm: String,
    capability: StackCapability,
    key_file: String,
    cert_file: String,
    ca_cert_file: String,
    addresses: Vec<String>,
    connection_manager: Arc<Box<ConnectionManager>>,
    command_map: CommandMap,
    avp_map: AvpMap,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
    answer_manager: Arc<Box<AnswerManager>>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
}

#[cfg(target_os = "linux")]
impl SctpDiameterServer {
    pub fn new(
        my_host: String,
        my_realm: String,
        capability: StackCapability,
        key_file: String,
        cert_file: String,
        ca_cert_file: String,
        addresses: Vec<String>,
        connection_manager: Arc<Box<ConnectionManager>>,
        command_map: CommandMap,
        avp_map: AvpMap,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
        answer_manager: Arc<Box<AnswerManager>>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
    ) -> Self {
        SctpDiameterServer {
            my_host,
            my_realm,
            capability,
            key_file,
            cert_file,
            ca_cert_file,
            addresses,
            connection_manager,
            command_map,
            avp_map,
            hop_by_hop_id_mapper,
            hop_by_hop_id_generator,
            command_handler,
            alarm_sender,
            answer_manager,
            redirect_host_manager,
        }
    }

    fn dtls_enabled(&self) -> bool {
        !self.cert_file.is_empty()
            && !self.key_file.is_empty()
            && !is_empty_file(&self.cert_file)
            && !is_empty_file(&self.key_file)
    }

    async fn secure_stream(&self, stream: Arc<SctpStream>) -> Result<SctpConnectionStream, String> {
        if !self.dtls_enabled() {
            return Ok(SctpConnectionStream::Plain(stream));
        }

        let key_pem = std::fs::read_to_string(&self.key_file)
            .map_err(|e| format!("Failed to read key file {}: {}", self.key_file, e))?;
        let cert_pem = std::fs::read_to_string(&self.cert_file)
            .map_err(|e| format!("Failed to read cert file {}: {}", self.cert_file, e))?;
        let certificate = DtlsCertificate::from_pem(&format!("{}\n{}", key_pem, cert_pem))
            .map_err(|e| format!("Failed to parse DTLS certificate and PKCS#8 key: {}", e))?;

        let mut roots_cas = rustls::RootCertStore::empty();
        if !self.ca_cert_file.is_empty() && !is_empty_file(&self.ca_cert_file) {
            let ca_pem = std::fs::read(&self.ca_cert_file)
                .map_err(|e| format!("Failed to read CA cert file {}: {}", self.ca_cert_file, e))?;
            for ca_cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
                roots_cas
                    .add(ca_cert.map_err(|e| format!("Failed to parse CA certificate: {}", e))?)
                    .map_err(|e| format!("Failed to add CA certificate: {}", e))?;
            }
        }

        let config = DtlsConfig {
            certificates: vec![certificate],
            roots_cas,
            ..Default::default()
        };
        let transport: Arc<dyn DtlsTransport + Send + Sync> = stream;
        let dtls = DTLSConn::new(transport, config, false, None)
            .await
            .map_err(|e| format!("DTLS handshake failed: {}", e))?;
        info!("DTLS server connection established");
        Ok(SctpConnectionStream::Dtls(Arc::new(dtls)))
    }

    pub async fn start(&self) -> Result<(), String> {
        let listener = SctpListener::bind(&self.addresses).await?;
        if self.dtls_enabled() {
            info!(
                "SctpDiameterServer listening on {:?} with DTLS",
                self.addresses
            );
        } else {
            info!("SctpDiameterServer listening on {:?}", self.addresses);
        }

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted SCTP connection from {}", addr);
                    let peer_addr = addr.to_string();

                    let secured_stream = match self.secure_stream(Arc::new(stream)).await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            error!("DTLS handshake failed for {}: {}", peer_addr, e);
                            continue;
                        }
                    };

                    let command_map = self.command_map.clone();
                    let avp_map = self.avp_map.clone();
                    let capability = self.capability.clone();
                    let hop_by_hop_id_mapper = self.hop_by_hop_id_mapper.clone();
                    let hop_by_hop_id_generator = self.hop_by_hop_id_generator.clone();
                    let command_handler = self.command_handler.clone();
                    let alarm_sender = self.alarm_sender.clone();
                    let my_host = self.my_host.clone();
                    let my_realm = self.my_realm.clone();
                    let connection_manager = self.connection_manager.clone();

                    match Self::handle_cer_exchange(
                        my_host.clone(),
                        my_realm.clone(),
                        &peer_addr,
                        &secured_stream,
                        &avp_map,
                        &command_map,
                        &capability,
                    )
                    .await
                    {
                        Ok(cer) => {
                            _ = SctpServerConnection::new(
                                peer_addr,
                                secured_stream,
                                my_host,
                                my_realm,
                                cer.get_origin_host().unwrap_or_default(),
                                cer.get_origin_realm().unwrap_or_default(),
                                command_map,
                                avp_map,             
                                connection_manager,                   
                                hop_by_hop_id_generator,
                                hop_by_hop_id_mapper,
                                self.answer_manager.clone(),
                                command_handler,
                                alarm_sender,
                                self.redirect_host_manager.clone()
                            );
                        }
                        Err(e) => {
                            error!("Failed to complete CER exchange with {}: {}", peer_addr, e);
                            _ = secured_stream.shutdown().await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to accept SCTP connection: {}", e);
                }
            }
        }
    }

    async fn handle_cer_exchange(
        host: String,
        realm: String,
        peer_address: &str,
        stream: &Arc<SctpConnectionStream>,
        avp_map: &AvpMap,
        command_map: &CommandMap,
        capability: &StackCapability,
    ) -> Result<Command, String> {
        let cer = Self::read_command_from_sctp(stream).await?;
        info!(
            "Received {} command: {} from sctp client: {}",
            if cer.is_request() {
                "request"
            } else {
                "answer"
            },
            cer.to_pretty_json_str(command_map, avp_map),
            peer_address
        );
        if cer.code != CommandCode::CapabilitiesExchange as u32 || !cer.is_request() {
            return Err(format!(
                "Expected CER with command code {}, got {} from connection {}",
                CommandCode::CapabilitiesExchange as u32,
                cer.code,
                peer_address
            ));
        }

        if cer.get_origin_host().is_none() || cer.get_origin_realm().is_none() {
            return Err(format!(
                "CER missing Origin-Host or Origin-Realm AVP from connection {}",
                peer_address
            ));
        }

        let cea = Self::create_cea(host, realm, &cer, avp_map, capability);
        stream.write_all(&cea.encode()).await?;

        Ok(cer)
    }

    async fn read_command_from_sctp(stream: &Arc<SctpConnectionStream>) -> Result<Command, String> {
        let mut length_buffer = [0u8; 4];
        read_exact(stream, &mut length_buffer).await?;
        let message_length = u32::from_be_bytes(length_buffer) & 0x00FFFFFF;
        let mut buffer = vec![0u8; message_length as usize - 4];
        read_exact(stream, &mut buffer).await?;
        let mut command_buffer = CommandBuffer::from_bytes(&length_buffer);
        command_buffer.append(&buffer);
        command_buffer
            .read_command()
            .ok_or_else(|| "Failed to parse command from SCTP stream".to_string())
    }

    fn create_cea(
        host: String,
        realm: String,
        cer_command: &Command,
        avp_map: &AvpMap,
        capability: &StackCapability,
    ) -> Command {
        let mut cea = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            CommandFlags::Proxiable as u8,
            0,
            cer_command.hop_by_hop_id,
            cer_command.end_to_end_id,
            vec![
                name_value_to_avp("Origin-Host", &Value::String(host), avp_map).unwrap(),
                name_value_to_avp("Origin-Realm", &Value::String(realm), avp_map).unwrap(),
                name_value_to_avp("Vendor-Id", &Value::Number(0.into()), avp_map).unwrap(),
            ],
        );
        cea.add_avps(create_capability_avps(capability, avp_map));
        cea.set_result_code(2001);
        cea
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct SctpServerConnection {
    id: String,
    my_host: String,
    my_realm: String,
    peer_host: String,
    peer_realm: String,
    avp_map: AvpMap,
    command_map: CommandMap,
    writer: Arc<Mutex<Option<Arc<SctpConnectionStream>>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    answer_manager: Arc<Box<AnswerManager>>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,    
    alarm_sender: Option<AlarmSender>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
}

#[cfg(target_os = "linux")]
impl SctpServerConnection {
    pub fn new(
        peer_addr: String,
        stream: Arc<SctpConnectionStream>,
        my_host: String,
        my_realm: String,
        peer_host: String,
        peer_realm: String,
        command_map: CommandMap,
        avp_map: AvpMap,
        connection_manager: Arc<Box<ConnectionManager>>,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        answer_manager: Arc<Box<AnswerManager>>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
    ) -> Self {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conn = SctpServerConnection {
            id: peer_addr.clone(),
            my_host: my_host.clone(),
            my_realm: my_realm.clone(),
            peer_host: peer_host.clone(),
            peer_realm: peer_realm.clone(),
            avp_map: avp_map.clone(),
            command_map: command_map.clone(),
            writer: Arc::new(Mutex::new(Some(stream.clone()))),
            closed: closed.clone(),
            hop_by_hop_id_generator: hop_by_hop_id_generator.clone(),
            hop_by_hop_id_mapper: hop_by_hop_id_mapper.clone(),
            answer_manager: answer_manager.clone(),
            command_handler: command_handler.clone(),
            alarm_sender: alarm_sender.clone(),
            redirect_host_manager: redirect_host_manager.clone(),
        };

        let conn_clone = conn.clone();

        tokio::spawn(async move {
            connection_manager
                .add_connection(Arc::new(Box::new(conn_clone.clone())))
                .await;
            conn_clone.clear_alarm().await;

            conn_clone
                .handle_connection(stream, connection_manager.clone())
                .await
                .ok();

            let alarm_raise_message = format!(
                "Lost connection from diameter peer {}@{} at {}",
                conn_clone.peer_host, conn_clone.peer_realm, conn_clone.id
            );
            conn_clone.raise_alarm(&alarm_raise_message).await;

            connection_manager
                .remove_connection_by_id(&conn_clone.get_id())
                .await;
        });

        conn
    }

    async fn raise_alarm(&self, message: &str) {
        if let Some(alarm_sender) = &self.alarm_sender {
            alarm_sender
                .raise_alarm(&self.id, &self.peer_host, &self.peer_realm, message)
                .await;
        }
    }

    async fn clear_alarm(&self) {
        if let Some(alarm_sender) = &self.alarm_sender {
            alarm_sender
                .clear_alarm(&self.id, &self.peer_host, &self.peer_realm)
                .await;
        }
    }

    async fn handle_connection(
        &self,
        stream: Arc<SctpConnectionStream>,
        connection_manager: Arc<Box<ConnectionManager>>,
    ) -> Result<(), String> {
        let mut buffer = [0u8; 4096];
        let mut command_buffer = CommandBuffer::new();
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    info!("SCTP connection closed by client");
                    return Ok(());
                }
                Ok(n) => {
                    debug!("Received {} bytes from SCTP client", n);
                    command_buffer.append(&buffer[..n]);
                    let commands = command_buffer.read_commands();
                    for mut command in commands {
                        match self
                            .process_command(&mut command, &connection_manager)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to process command: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from SCTP connection: {}", e);
                    return Err(e);
                }
            }
        }
    }

    async fn process_command(
        &self,
        command: &mut Command,
        connection_manager: &Arc<Box<ConnectionManager>>,
    ) -> Result<(), String> {
        info!(
            "Received {} command: {} from sctp client: {}",
            if command.is_request() {
                "request"
            } else {
                "answer"
            },
            command.to_pretty_json_str(&self.command_map, &self.avp_map),
            self.id
        );
        if command.code == CommandCode::DeviceWatchdog as u32 && command.is_request() {
            self.process_dwa(command).await?;
            return Ok(());
        }

        if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
            return Ok(());
        }

        let context = CommandProcessorContext {
            connection_id: &self.id,
            my_host: &self.my_host,
            my_realm: &self.my_realm,
            peer_host: &self.peer_host,
            peer_realm: &self.peer_realm,
            command_map: &self.command_map,
            avp_map: &self.avp_map,
            connection_manager,
            hop_by_hop_id_generator: &self.hop_by_hop_id_generator,
            hop_by_hop_id_mapper: &self.hop_by_hop_id_mapper,
            answer_manager: &self.answer_manager,
            command_handler: self.command_handler.as_ref(),
            redirect_host_manager: &self.redirect_host_manager,
        };

        context.process_command(command).await
    }

    async fn process_dwa(&self, command: &Command) -> Result<(), String> {
        let dwa = Command::new(
            CommandCode::DeviceWatchdog as u32,
            CommandFlags::Proxiable as u8,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::ResultCode as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    2001,
                ),
            ],
        );
        info!(
            "Sending DWA: {} to sctp client: {}",
            dwa.to_pretty_json_str(&self.command_map, &self.avp_map),
            self.id
        );
        self.send(&dwa).await
    }

    async fn process_dpr(&self, command: &Command) -> Result<(), String> {
        let dpr = Command::new(
            CommandCode::DisconnectPeer as u32,
            CommandFlags::Proxiable as u8,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::ResultCode as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    2001,
                ),
            ],
        );
        info!(
            "Sending DPA: {} to sctp client: {}",
            dpr.to_pretty_json_str(&self.command_map, &self.avp_map),
            self.id
        );
        self.send(&dpr).await?;
        self.close().await
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Connection for SctpServerConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        info!(
            "Sending command with code {} and hop-by-hop ID {} to sctp client {}: {}",
            command.code,
            command.hop_by_hop_id,
            format!("{}@{}", self.peer_host, self.peer_realm),
            command.to_pretty_json_str(&self.command_map, &self.avp_map),
        );
        let data = command.encode();
        let guard = self.writer.lock().await;
        let stream = guard
            .as_ref()
            .ok_or_else(|| "SCTP connection already closed".to_string())?;
        stream.write_all(&data).await
    }

    async fn close(&self) -> Result<(), String> {
        let mut guard = self.writer.lock().await;
        if let Some(stream) = guard.take() {
            stream.shutdown().await?;
        }
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    async fn get_connections(
        &self,
        _connections: &mut Vec<Arc<Box<dyn Connection + Send + Sync>>>,
    ) {
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}
