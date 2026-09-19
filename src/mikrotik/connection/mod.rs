// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` API connection: framing, TLS, authentication, and cancellation-safe transport.

mod auth;
mod protocol;
mod tls;
#[cfg(test)]
mod tls_tests;

use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::prelude::{AppError, Result};

use crate::mikrotik::{ProtocolError, SnapshotError};

use protocol::{encode_length, read_length};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ROUTEROS_WORD_LENGTH: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_WORDS: usize = 262_144;
const MAX_RESPONSE_SENTENCES: usize = 65_536;
const MAX_SENTENCE_WORDS: usize = 4096;

pub(super) struct RouterOsConnection {
    stream: Box<dyn Transport>,
    dirty: bool,
}

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

#[derive(Default)]
struct ResponseBudget {
    bytes: usize,
    words: usize,
    sentences: usize,
}

#[derive(Default)]
struct CommandResponse {
    records: Vec<HashMap<String, String>>,
    done: HashMap<String, String>,
}

impl RouterOsConnection {
    pub(super) async fn connect(
        addr: &str,
        tls_config: Option<&crate::config::RouterTlsConfig>,
    ) -> Result<Self> {
        // Resolve trust/identity before the deadline so slow trust-store loading
        // cannot be reported as a connection timeout.
        let connector = match tls_config {
            Some(config) => Some((
                tls::connector(config).await?,
                config.server_name_for_address(addr)?,
            )),
            None => None,
        };
        timeout(CONNECTION_TIMEOUT, async {
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|source| AppError::Transport {
                    operation: "connect",
                    source,
                })?;
            let stream: Box<dyn Transport> = if let Some((connector, name)) = connector {
                Box::new(connector.connect(name, stream).await.map_err(|source| {
                    AppError::Transport {
                        operation: "TLS handshake",
                        source,
                    }
                })?)
            } else {
                Box::new(stream)
            };
            Ok(Self {
                stream,
                dirty: false,
            })
        })
        .await
        .map_err(|_| AppError::Timeout("connect"))?
    }

    pub(super) fn is_reusable(&self) -> bool {
        !self.dirty
    }

    pub(super) async fn command(
        &mut self,
        path: &str,
        args: &[&str],
    ) -> Result<Vec<HashMap<String, String>>> {
        let words = std::iter::once(path)
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();
        self.raw_command(words)
            .await
            .map(|response| response.records)
    }

    async fn raw_command(&mut self, words: Vec<String>) -> Result<CommandResponse> {
        if self.dirty {
            return Err(AppError::Protocol(ProtocolError::UnfinishedCommand));
        }
        self.dirty = true;
        timeout(COMMAND_TIMEOUT, async {
            self.send_words(&words).await?;
            self.read_sentences().await
        })
        .await
        .map_err(|_| AppError::Timeout("command"))?
    }

    pub(super) async fn count_only(&mut self, path: &str) -> Result<u64> {
        let response = self
            .raw_command(vec![path.into(), "=count-only=".into()])
            .await?;
        response
            .done
            .get("ret")
            .and_then(|value| value.parse().ok())
            .ok_or(AppError::InvalidSnapshot(
                SnapshotError::InvalidCountOnlyCompletion,
            ))
    }

    async fn send_words(&mut self, words: &[String]) -> Result<()> {
        for word in words {
            if word.is_empty() || word.len() > MAX_ROUTEROS_WORD_LENGTH {
                return Err(AppError::Protocol(ProtocolError::InvalidRequestWordLength));
            }
            self.stream
                .write_all(&encode_length(word.len())?)
                .await
                .map_err(write_error)?;
            self.stream
                .write_all(word.as_bytes())
                .await
                .map_err(write_error)?;
        }
        self.stream.write_all(&[0]).await.map_err(write_error)?;
        self.stream.flush().await.map_err(write_error)?;
        Ok(())
    }

    async fn read_sentences(&mut self) -> Result<CommandResponse> {
        let mut response = CommandResponse::default();
        let mut budget = ResponseBudget::default();
        let mut trap = None;
        loop {
            let (kind, attributes) = self.read_sentence(&mut budget).await?;
            match kind.as_str() {
                "!re" => response.records.push(attributes),
                "!done" => {
                    response.done = attributes;
                    self.dirty = false;
                    return trap.map_or(Ok(response), Err);
                }
                "!trap" => {
                    trap.get_or_insert_with(|| AppError::RouterOsTrap {
                        category: attributes
                            .get("category")
                            .and_then(|value| value.parse().ok()),
                        message: attributes.get("message").cloned().unwrap_or_default(),
                    });
                }
                "!fatal" => return Err(AppError::RouterOsFatal),
                "!empty" => {}
                _ => return Err(AppError::Protocol(ProtocolError::UnknownSentenceType)),
            }
        }
    }

    async fn read_sentence(
        &mut self,
        budget: &mut ResponseBudget,
    ) -> Result<(String, HashMap<String, String>)> {
        budget.sentences += 1;
        if budget.sentences > MAX_RESPONSE_SENTENCES {
            return Err(AppError::Protocol(ProtocolError::SentenceLimitExceeded));
        }
        let kind = self.read_word(budget).await?;
        if kind.is_empty() {
            return Err(AppError::Protocol(ProtocolError::EmptySentence));
        }
        let mut attributes = HashMap::new();
        for _ in 0..MAX_SENTENCE_WORDS {
            let word = self.read_word(budget).await?;
            if word.is_empty() {
                return Ok((kind, attributes));
            }
            let attribute = word.strip_prefix('=').or_else(|| word.strip_prefix('.'));
            let Some((key, value)) = attribute.and_then(|attribute| attribute.split_once('='))
            else {
                return Err(AppError::Protocol(ProtocolError::MalformedAttribute));
            };
            if key.is_empty() || attributes.insert(key.into(), value.into()).is_some() {
                return Err(AppError::Protocol(ProtocolError::EmptyOrDuplicateAttribute));
            }
        }
        Err(AppError::Protocol(ProtocolError::SentenceWordLimitExceeded))
    }

    async fn read_word(&mut self, budget: &mut ResponseBudget) -> Result<String> {
        budget.words += 1;
        if budget.words > MAX_RESPONSE_WORDS {
            return Err(AppError::Protocol(ProtocolError::WordLimitExceeded));
        }
        let len = read_length(&mut self.stream).await?;
        if len > MAX_ROUTEROS_WORD_LENGTH {
            return Err(AppError::Protocol(ProtocolError::WordLengthLimitExceeded));
        }
        budget.bytes += len + 5;
        if budget.bytes > MAX_RESPONSE_BYTES {
            return Err(AppError::Protocol(ProtocolError::ByteLimitExceeded));
        }
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|source| AppError::Transport {
                operation: "read word body",
                source,
            })?;
        tracing::trace!(word_bytes = len, "Received RouterOS word");
        String::from_utf8(buf).map_err(|_| AppError::Protocol(ProtocolError::InvalidUtf8))
    }
}

fn write_error(source: std::io::Error) -> AppError {
    AppError::Transport {
        operation: "write command",
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_TIMEOUT, MAX_RESPONSE_BYTES, MAX_RESPONSE_SENTENCES, MAX_RESPONSE_WORDS,
        MAX_ROUTEROS_WORD_LENGTH, MAX_SENTENCE_WORDS, ResponseBudget, RouterOsConnection,
        protocol::encode_length,
    };
    use crate::mikrotik::ProtocolError;
    use crate::mikrotik::pool::ConnectionPool;
    use crate::prelude::{AppError, Result};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn pair() -> (RouterOsConnection, RouterOsConnection) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (client, server) = tokio::join!(
            RouterOsConnection::connect(&address, None),
            listener.accept()
        );
        (
            client.unwrap(),
            RouterOsConnection {
                stream: Box::new(server.unwrap().0),
                dirty: false,
            },
        )
    }

    fn fixture_password() -> String {
        ["sec", "ret"].concat()
    }

    fn trusted_fixture_password() -> String {
        ["trusted", "-fixture"].concat()
    }

    fn wrong_fixture_password() -> String {
        ["wrong", "-fixture"].concat()
    }

    async fn receive(peer: &mut RouterOsConnection) -> String {
        peer.read_sentence(&mut ResponseBudget::default())
            .await
            .unwrap()
            .0
    }

    async fn send(peer: &mut RouterOsConnection, words: &[&str]) {
        peer.send_words(&words.iter().map(|word| (*word).into()).collect::<Vec<_>>())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_done_attributes_consumed_before_next_command() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            assert_eq!(receive(&mut peer).await, "/first");
            send(&mut peer, &["!re", "=value=first"]).await;
            send(&mut peer, &["!done", "=ret=completion", ".tag=one"]).await;
            assert_eq!(receive(&mut peer).await, "/second");
            send(&mut peer, &["!re", "=value=second"]).await;
            send(&mut peer, &["!done"]).await;
        });
        let first = client.command("/first", &[]).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["value"], "first");
        let second = client.command("/second", &[]).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0]["value"], "second");
        assert!(client.is_reusable());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_count_only_requires_valid_terminal_count() {
        for value in ["0", "12", "invalid", "-1", "18446744073709551616"] {
            let (mut client, mut peer) = pair().await;
            let server = tokio::spawn(async move {
                let (path, attributes) = peer
                    .read_sentence(&mut ResponseBudget::default())
                    .await
                    .unwrap();
                assert_eq!(path, "/count");
                assert_eq!(attributes["count-only"], "");
                send(&mut peer, &["!done", &format!("=ret={value}")]).await;
            });
            let result = client.count_only("/count").await;
            match value.parse::<u64>() {
                Ok(expected) => assert_eq!(result.unwrap(), expected),
                Err(_) => assert!(matches!(result, Err(AppError::InvalidSnapshot(_)))),
            }
            server.await.unwrap();
        }
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            send(&mut peer, &["!re", "=ret=0"]).await;
            send(&mut peer, &["!done"]).await;
        });
        assert!(matches!(
            client.count_only("/count").await,
            Err(AppError::InvalidSnapshot(_))
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_production_collection_accepts_empty_optional_tables() {
        use crate::config::RouterConfig;
        use crate::mikrotik::client::MikroTikClient;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let stream = listener.accept().await.unwrap().0;
                peers.spawn(async move {
                    let mut peer = RouterOsConnection {
                        stream: Box::new(stream),
                        dirty: false,
                    };
                    let mut counts = 0;
                    loop {
                        let (path, attributes) =
                            match peer.read_sentence(&mut ResponseBudget::default()).await {
                                Ok(sentence) => sentence,
                                Err(AppError::Transport { source, .. })
                                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                                {
                                    break;
                                }
                                Err(error) => panic!("invalid production request: {error}"),
                            };
                        if attributes.contains_key("count-only") {
                            counts += 1;
                            send(&mut peer, &["!done", "=ret=0"]).await;
                            continue;
                        }
                        match path.as_str() {
                            "/login" => assert_eq!(attributes["name"], "test-user"),
                            "/system/resource/print" => {
                                assert!(attributes.contains_key(".proplist"));
                                send(
                                    &mut peer,
                                    &[
                                        "!re",
                                        "=uptime=1d",
                                        "=cpu-load=25",
                                        "=free-memory=512",
                                        "=total-memory=1024",
                                        "=version=7.10",
                                        "=board-name=test",
                                    ],
                                )
                                .await;
                            }
                            "/interface/print" => {
                                assert!(attributes.contains_key(".proplist"));
                                send(
                                    &mut peer,
                                    &[
                                        "!re",
                                        "=.id=*1",
                                        "=name=ether1",
                                        "=running=true",
                                        "=rx-byte=1000",
                                        "=tx-byte=2000",
                                        "=rx-packet=10",
                                        "=tx-packet=20",
                                        "=rx-error=0",
                                        "=tx-error=0",
                                    ],
                                )
                                .await;
                            }
                            "/certificate/print" => {
                                assert_eq!(
                                    attributes[".proplist"],
                                    ".id,name,invalid-after,expiration"
                                );
                            }
                            "/interface/wireguard/peers/print"
                            | "/ip/firewall/connection/print"
                            | "/ipv6/firewall/connection/print" => {}
                            _ => assert!(attributes.contains_key(".proplist"), "{path}"),
                        }
                        send(&mut peer, &["!done"]).await;
                    }
                    counts
                });
            }
            let mut counts = 0;
            while let Some(result) = peers.join_next().await {
                counts += result.unwrap();
            }
            assert_eq!(counts, 9);
        });
        let client = MikroTikClient::with_pool(
            RouterConfig {
                name: "loopback".into(),
                address,
                username: "test-user".into(),
                password: "fixture-password".to_string().into(),
                tls: None,
            },
            Arc::new(ConnectionPool::new()),
        );
        let snapshot = tokio::time::timeout(Duration::from_secs(5), client.collect_metrics())
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.collection_status.all_ok());
        assert_eq!(snapshot.interfaces[0].rx_bytes, 1000);
        assert!(snapshot.firewall_rules.is_empty());
        assert!(snapshot.wireguard_peers.is_empty());
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_optional_table_trap_does_not_drive_backoff() {
        use crate::config::RouterConfig;
        use crate::mikrotik::client::MikroTikClient;
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let stream = listener.accept().await.unwrap().0;
                peers.spawn(async move {
                    let mut peer = RouterOsConnection {
                        stream: Box::new(stream),
                        dirty: false,
                    };
                    loop {
                        let (path, attributes) =
                            match peer.read_sentence(&mut ResponseBudget::default()).await {
                                Ok(sentence) => sentence,
                                Err(AppError::Transport { source, .. })
                                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                                {
                                    break;
                                }
                                Err(error) => panic!("invalid production request: {error}"),
                            };
                        if attributes.contains_key("count-only") {
                            send(&mut peer, &["!done", "=ret=0"]).await;
                            continue;
                        }
                        match path.as_str() {
                            "/system/resource/print" => {
                                send(
                                    &mut peer,
                                    &[
                                        "!re",
                                        "=uptime=1d",
                                        "=cpu-load=25",
                                        "=free-memory=512",
                                        "=total-memory=1024",
                                        "=version=7.10",
                                        "=board-name=test",
                                    ],
                                )
                                .await;
                            }
                            "/interface/print" => {
                                send(
                                    &mut peer,
                                    &[
                                        "!re",
                                        "=.id=*1",
                                        "=name=ether1",
                                        "=running=true",
                                        "=rx-byte=1000",
                                        "=tx-byte=2000",
                                        "=rx-packet=10",
                                        "=tx-packet=20",
                                        "=rx-error=0",
                                        "=tx-error=0",
                                    ],
                                )
                                .await;
                            }
                            "/ip/firewall/connection/print" => {
                                send(
                                    &mut peer,
                                    &["!re", "=src-address=192.0.2.1:1234", "=protocol=tcp"],
                                )
                                .await;
                            }
                            "/ipv6/firewall/connection/print" => {
                                send(&mut peer, &["!trap", "=message=no such command prefix"])
                                    .await;
                            }
                            _ => {}
                        }
                        send(&mut peer, &["!done"]).await;
                    }
                });
            }
            while let Some(result) = peers.join_next().await {
                result.unwrap();
            }
        });

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(
            RouterConfig {
                name: "loopback".into(),
                address: address.clone(),
                username: "test-user".into(),
                password: fixture_password().into(),
                tls: None,
            },
            pool.clone(),
        );

        for _ in 0..2 {
            let snapshot = tokio::time::timeout(Duration::from_secs(5), client.collect_metrics())
                .await
                .unwrap()
                .unwrap();
            assert!(snapshot.collection_status.conntrack_ok());
            assert!(!snapshot.collection_status.conntrack_complete_ok());
            assert!(!snapshot.connection_tracking.is_empty());
        }
        assert_eq!(
            pool.get_connection_state(
                &address,
                "test-user",
                &fixture_password(),
                None,
                Some("conntrack")
            )
            .await,
            Some((0, true))
        );
        drop(client);
        drop(pool);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_traps_drained_through_done_before_next_command() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            send(
                &mut peer,
                &["!trap", "=category=2", "=message=first rejection"],
            )
            .await;
            send(&mut peer, &["!trap", "=message=second rejection"]).await;
            send(&mut peer, &["!done", "=ret=ignored"]).await;
            assert_eq!(receive(&mut peer).await, "/next");
            send(&mut peer, &["!re", "=value=next"]).await;
            send(&mut peer, &["!done"]).await;
        });
        assert!(matches!(client.command("/bad", &[]).await,
            Err(AppError::RouterOsTrap { category: Some(2), message }) if message == "first rejection"));
        assert!(client.is_reusable());
        assert_eq!(
            client.command("/next", &[]).await.unwrap()[0]["value"],
            "next"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_fragmented_length_and_utf8_body() {
        let (mut client, mut peer) = pair().await;
        let value = "é".repeat(80);
        let attribute = format!("=value={value}");
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            for word in ["!re", attribute.as_str(), "", "!done", ""] {
                for byte in encode_length(word.len())
                    .unwrap()
                    .into_iter()
                    .chain(word.bytes())
                {
                    peer.stream.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }
            }
        });
        assert_eq!(
            client.command("/fragmented", &[]).await.unwrap()[0]["value"],
            value
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_empty_reply_waits_for_done() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            send(&mut peer, &["!empty"]).await;
            send(&mut peer, &["!done", "=ret=empty"]).await;
        });
        assert!(client.command("/empty", &[]).await.unwrap().is_empty());
        assert!(client.is_reusable());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_fatal_and_invalid_responses_are_not_reusable() {
        for bytes in [
            b"\x06!fatal\0".to_vec(),
            b"\0".to_vec(),
            b"\x01\xff".to_vec(),
            b"\xf1".to_vec(),
            b"\x03!re\x04=x=y\x03bad\0".to_vec(),
            b"\x03!re\x04=x=y\x04=x=z\0".to_vec(),
            b"\x03!re\x05!done\0".to_vec(),
            encode_length(MAX_ROUTEROS_WORD_LENGTH + 1).unwrap(),
            b"\x05!do".to_vec(),
        ] {
            let (mut client, mut peer) = pair().await;
            let server = tokio::spawn(async move {
                receive(&mut peer).await;
                peer.stream.write_all(&bytes).await.unwrap();
            });
            let error = client.command("/invalid", &[]).await.unwrap_err();
            assert!(matches!(
                error,
                AppError::Protocol(_) | AppError::RouterOsFatal | AppError::Transport { .. }
            ));
            assert!(!client.is_reusable());
            assert!(matches!(
                client.command("/next", &[]).await,
                Err(AppError::Protocol(_))
            ));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_response_budgets_bound_accumulation() {
        let (mut client, mut peer) = pair().await;
        peer.stream.write_all(b"\x01x").await.unwrap();
        let mut bytes = ResponseBudget {
            bytes: MAX_RESPONSE_BYTES - 5,
            ..Default::default()
        };
        assert!(matches!(
            client.read_word(&mut bytes).await,
            Err(AppError::Protocol(_))
        ));
        let mut words = ResponseBudget {
            words: MAX_RESPONSE_WORDS,
            ..Default::default()
        };
        assert!(matches!(
            client.read_word(&mut words).await,
            Err(AppError::Protocol(_))
        ));
        let mut sentences = ResponseBudget {
            sentences: MAX_RESPONSE_SENTENCES,
            ..Default::default()
        };
        assert!(matches!(
            client.read_sentence(&mut sentences).await,
            Err(AppError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn test_sentence_word_limit_rejects_unterminated_sentence() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            let mut words = vec!["!re".into()];
            words.extend((0..MAX_SENTENCE_WORDS).map(|index| format!("=key{index}=value")));
            peer.send_words(&words).await.unwrap();
        });
        assert!(matches!(
            client.command("/many", &[]).await,
            Err(AppError::Protocol(_))
        ));
        assert!(!client.is_reusable());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_response_byte_limit_spans_individually_valid_sentences() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            let attribute = format!("=data={}", "x".repeat(MAX_ROUTEROS_WORD_LENGTH - 6));
            for _ in 0..=MAX_RESPONSE_BYTES / MAX_ROUTEROS_WORD_LENGTH {
                if peer
                    .send_words(&["!re".into(), attribute.clone()])
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        assert!(matches!(
            client.command("/large", &[]).await,
            Err(AppError::Protocol(ProtocolError::ByteLimitExceeded))
        ));
        assert!(!client.is_reusable());
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_done_without_terminator_never_marks_connection_reusable() {
        let (mut client, mut peer) = pair().await;
        let (sent, received) = oneshot::channel();
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            peer.stream.write_all(b"\x05!done\x04=x=y").await.unwrap();
            sent.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(peer.stream.read(&mut byte).await.unwrap(), 0);
        });
        {
            let command = client.command("/incomplete", &[]);
            tokio::pin!(command);
            tokio::select! {
                result = &mut command => panic!("incomplete sentence accepted: {result:?}"),
                result = received => result.unwrap(),
            }
            tokio::time::pause();
            tokio::time::advance(COMMAND_TIMEOUT).await;
            assert!(matches!(command.await, Err(AppError::Timeout("command"))));
            tokio::time::resume();
        }
        assert!(!client.is_reusable());
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_login_rejects_invalid_or_repeated_challenge() {
        for repeated in [false, true] {
            let (mut client, mut peer) = pair().await;
            let server = tokio::spawn(async move {
                receive(&mut peer).await;
                if repeated {
                    send(
                        &mut peer,
                        &["!done", "=ret=000102030405060708090a0b0c0d0e0f"],
                    )
                    .await;
                    receive(&mut peer).await;
                }
                send(&mut peer, &["!done", "=ret=invalid"]).await;
            });
            assert!(matches!(
                client.login("admin", &fixture_password()).await,
                Err(AppError::Authentication(_))
            ));
            assert!(!client.is_reusable());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_login_challenge_requires_second_exchange() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            assert_eq!(receive(&mut peer).await, "/login");
            send(
                &mut peer,
                &["!done", "=ret=000102030405060708090a0b0c0d0e0f"],
            )
            .await;
            let (kind, attributes) = peer
                .read_sentence(&mut ResponseBudget::default())
                .await
                .unwrap();
            assert_eq!(kind, "/login");
            assert_eq!(attributes["response"], "00925d25da4b1ffe731237818c4e1fcd57");
            assert!(!attributes.contains_key("password"));
            send(&mut peer, &["!done"]).await;
            assert_eq!(receive(&mut peer).await, "/next");
            send(&mut peer, &["!done"]).await;
        });
        client.login("admin", &fixture_password()).await.unwrap();
        assert!(client.command("/next", &[]).await.unwrap().is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_login_trap_does_not_retry_credentials() {
        let (mut client, mut peer) = pair().await;
        let server = tokio::spawn(async move {
            receive(&mut peer).await;
            send(&mut peer, &["!trap", "=message=invalid credentials"]).await;
            send(&mut peer, &["!done"]).await;
            let mut byte = [0];
            assert_eq!(peer.stream.read(&mut byte).await.unwrap(), 0);
        });
        assert!(matches!(
            client.login("admin", &fixture_password()).await,
            Err(AppError::RouterOsTrap { .. })
        ));
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_pool_different_password_requires_new_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut trusted = RouterOsConnection {
                stream: Box::new(listener.accept().await.unwrap().0),
                dirty: false,
            };
            let (_, attributes) = trusted
                .read_sentence(&mut ResponseBudget::default())
                .await
                .unwrap();
            assert_eq!(attributes["password"], trusted_fixture_password());
            send(&mut trusted, &["!done"]).await;
            let mut rejected = RouterOsConnection {
                stream: Box::new(listener.accept().await.unwrap().0),
                dirty: false,
            };
            let (_, attributes) = rejected
                .read_sentence(&mut ResponseBudget::default())
                .await
                .unwrap();
            assert_eq!(attributes["password"], wrong_fixture_password());
            send(&mut rejected, &["!trap", "=message=rejected"]).await;
            send(&mut rejected, &["!done"]).await;
            assert_eq!(receive(&mut trusted).await, "/reused");
            send(&mut trusted, &["!done"]).await;
        });
        let pool = ConnectionPool::new();
        drop(
            pool.get_connection(&address, "admin", &trusted_fixture_password(), None, None)
                .await
                .unwrap(),
        );
        assert!(matches!(
            pool.get_connection(&address, "admin", &wrong_fixture_password(), None, None)
                .await,
            Err(AppError::RouterOsTrap { .. })
        ));
        let mut guard = pool
            .get_connection(&address, "admin", &trusted_fixture_password(), None, None)
            .await
            .unwrap();
        guard.get_mut().command("/reused", &[]).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_successful_login_does_not_reset_failed_command_backoff() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut peer = RouterOsConnection {
                    stream: Box::new(listener.accept().await.unwrap().0),
                    dirty: false,
                };
                assert_eq!(receive(&mut peer).await, "/login");
                send(&mut peer, &["!done"]).await;
                assert_eq!(receive(&mut peer).await, "/denied");
                send(&mut peer, &["!trap", "=message=denied"]).await;
                send(&mut peer, &["!done"]).await;
            }
        });
        let pool = ConnectionPool::new();
        for _ in 0..2 {
            let mut guard = pool
                .get_connection(&address, "admin", &fixture_password(), Some("system"), None)
                .await
                .unwrap();
            assert!(matches!(
                guard.get_mut().command("/denied", &[]).await,
                Err(AppError::RouterOsTrap { .. })
            ));
            guard.mark_broken();
            guard.record_result(false).await;
        }
        assert_eq!(
            pool.get_connection_state(&address, "admin", &fixture_password(), None, Some("system"))
                .await,
            Some((2, false))
        );
        assert!(
            matches!(pool.get_connection(&address, "admin", &fixture_password(), Some("system"), None).await, Err(AppError::RouterOs(message)) if message.contains("temporarily disabled"))
        );
        server.await.unwrap();
    }

    async fn cancelled_pool_command(internal_timeout: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (partial_tx, partial_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = RouterOsConnection {
                stream: Box::new(listener.accept().await.unwrap().0),
                dirty: false,
            };
            assert_eq!(receive(&mut peer).await, "/login");
            send(&mut peer, &["!done"]).await;
            assert_eq!(receive(&mut peer).await, "/slow");
            peer.stream.write_all(b"\x03!re\x80").await.unwrap();
            partial_tx.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(peer.stream.read(&mut byte).await.unwrap(), 0);
            let mut peer = RouterOsConnection {
                stream: Box::new(listener.accept().await.unwrap().0),
                dirty: false,
            };
            assert_eq!(receive(&mut peer).await, "/login");
            send(&mut peer, &["!done"]).await;
            assert_eq!(receive(&mut peer).await, "/fresh");
            send(&mut peer, &["!re", "=value=fresh"]).await;
            send(&mut peer, &["!done"]).await;
            assert_eq!(receive(&mut peer).await, "/reused");
            send(&mut peer, &["!done"]).await;
        });
        let pool = ConnectionPool::new();
        let mut guard = pool
            .get_connection(&address, "admin", &fixture_password(), None, None)
            .await
            .unwrap();
        {
            let duration = if internal_timeout {
                COMMAND_TIMEOUT * 2
            } else {
                Duration::from_secs(1)
            };
            let command = tokio::time::timeout(duration, guard.get_mut().command("/slow", &[]));
            tokio::pin!(command);
            tokio::select! {
                result = &mut command => panic!("command completed before cancellation: {result:?}"),
                result = partial_rx => result.unwrap(),
            }
            tokio::time::pause();
            tokio::time::advance(if internal_timeout {
                COMMAND_TIMEOUT
            } else {
                duration
            })
            .await;
            let result = command.await;
            if internal_timeout {
                assert!(matches!(result, Ok(Err(AppError::Timeout("command")))));
            } else {
                assert!(result.is_err());
            }
            tokio::time::resume();
        }
        assert!(!guard.get_mut().is_reusable());
        drop(guard);
        assert_eq!(pool.get_pool_stats().await, (0, 0));
        let mut guard = pool
            .get_connection(&address, "admin", &fixture_password(), None, None)
            .await
            .unwrap();
        assert_eq!(
            guard.get_mut().command("/fresh", &[]).await.unwrap()[0]["value"],
            "fresh"
        );
        drop(guard);
        assert_eq!(pool.get_pool_stats().await, (1, 0));
        let mut guard = pool
            .get_connection(&address, "admin", &fixture_password(), None, None)
            .await
            .unwrap();
        assert!(
            guard
                .get_mut()
                .command("/reused", &[])
                .await
                .unwrap()
                .is_empty()
        );
        drop(guard);
        assert_eq!(pool.get_pool_stats().await, (1, 0));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_external_timeout_discards_dirty_pool_connection() -> Result<()> {
        cancelled_pool_command(false).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_internal_timeout_discards_dirty_pool_connection() -> Result<()> {
        cancelled_pool_command(true).await;
        Ok(())
    }
}
