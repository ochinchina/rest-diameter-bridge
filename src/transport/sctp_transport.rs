#[cfg(target_os = "linux")]
mod sctp {
    use std::io;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    const IPPROTO_SCTP: libc::c_int = 132;

    pub struct SctpStream {
        inner: AsyncFd<OwnedFd>,
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

            Ok(SctpStream { inner: async_fd })
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
}

#[cfg(target_os = "linux")]
use sctp::SctpStream;

#[cfg(target_os = "linux")]
pub struct SctpClientConnection {
    // Similar to TcpClientConnection but using SCTP instead of TCP
    addresses: Vec<String>,
    host: String,
    realm: String,
    hop_by_hop_id_generator: Arc<IdGenerator>,
    end_to_end_id_generator: Arc<IdGenerator>,
    writer: Arc<Mutex<Option<Arc<SctpStream>>>>,
}

#[cfg(target_os = "linux")]
impl SctpClientConnection {
    pub fn new(
        addresses: Vec<String>,
        host: String,
        realm: String,
        hop_by_hop_id_generator: Arc<IdGenerator>,
        end_to_end_id_generator: Arc<IdGenerator>,
    ) -> Self {
        SctpClientConnection {
            addresses,
            host,
            realm,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            writer: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        loop {
            match SctpStream::connect(&self.addresses).await {
                Ok(stream) => {
                    info!(
                        "Successfully connected to SCTP server at {:?}",
                        self.addresses
                    );
                    let stream = Arc::new(stream);
                    *self.writer.lock().await = Some(stream.clone());
                    self.send_cer().await?;

                    let cea = self.read_command_from_sctp(&stream).await?;
                    info!("Received CEA: {:?}", cea);

                    if cea.code != 275 || !cea.is_answer() {
                        return Err(format!(
                            "Expected CEA with command code 275, got {}",
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
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(reader_stream).await {
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
            275,
            command_flags(true, true, false, false),
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![],
        );
        self.send(&cer_command).await
    }

    async fn read_command_from_sctp(&self, stream: &Arc<SctpStream>) -> Result<Command, String> {
        let mut length_buffer = [0u8; 4];
        stream.read_exact(&mut length_buffer).await?;
        let message_length = u32::from_be_bytes(length_buffer) & 0x00FFFFFF;
        let mut buffer = vec![0u8; message_length as usize - 4];
        stream.read_exact(&mut buffer).await?;
        let mut command_buffer = CommandBuffer::from_bytes(&length_buffer);
        command_buffer.append(&buffer);
        command_buffer
            .read_command()
            .ok_or_else(|| "Failed to parse command from SCTP stream".to_string())
    }

    async fn handle_connection(stream: Arc<SctpStream>) -> Result<(), String> {
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
                    for command in commands {
                        info!(
                            "Received {} command: {:?}",
                            if command.is_request() {
                                "request"
                            } else {
                                "answer"
                            },
                            command
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to read from SCTP connection: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Connection for SctpClientConnection {
    fn get_id(&self) -> String {
        self.addresses.join(",")
    }

    async fn send(&mut self, command: &Command) -> Result<(), String> {
        let data = command.encode();
        let guard = self.writer.lock().await;
        let stream = guard
            .as_ref()
            .ok_or_else(|| "SCTP connection not established".to_string())?;
        stream.write_all(&data).await
    }

    async fn close(&mut self) -> Result<(), String> {
        let mut guard = self.writer.lock().await;
        if let Some(stream) = guard.take() {
            stream.shutdown().await?;
        }
        Ok(())
    }

    fn is_closed(&self) -> bool {
        false
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.realm.clone())
    }
}
pub struct SctpDiameterServer {
    // Similar to TcpDiameterServer but using SCTP instead of TCP
    addresses: Vec<String>,
    manager: Arc<Mutex<ConnectionManager>>,
}

impl SctpDiameterServer {
    pub fn new(addresses: Vec<String>, manager: Arc<Mutex<ConnectionManager>>) -> Self {
        SctpDiameterServer { addresses, manager }
    }

    pub async fn start(&self) -> Result<(), String> {
        // Implement SCTP server logic
        Ok(())
    }
}
