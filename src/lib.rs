use std::{time::Duration, collections::HashMap};

use aes_gcm::{KeyInit, Aes256Gcm, aead::Aead, AeadInPlace, Aes128Gcm, AesGcm, aes::Aes128};
use futures_util::{StreamExt, stream::{SplitStream, SplitSink}, TryStreamExt, SinkExt};
use rand::Rng;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message,
    WebSocketStream, MaybeTlsStream};
use tokio::net::TcpStream;

// Concurrency stuff
use crossbeam_channel::{Sender, Receiver};
use tokio::sync::oneshot;

// Crypto stuff
use rsa::{RsaPrivateKey, Oaep, pkcs8::EncodePublicKey};
use base64::{Engine as _, engine::{general_purpose}};
use aes_gcm::aead::generic_array::GenericArray;

// Logging stuff
#[cfg(not(test))] 
use log::{warn, debug}; // Use log crate when building application
 
#[cfg(test)]
use std::{println as warn, println as debug}; // Workaround to use println! for logs.

/// Represents the state of the connection to a node
#[derive(Debug, Clone, Copy)]
pub enum ConnectionState {
    /// Underlying connection established, awaiting handshake
    Connected,
    /// Handshake complete, ready to send requests
    Ready,
    Disconnected,
}

#[derive(Debug)]
struct WebSocketRequest {
    /// Text to send to node
    text: String,
    /// Channel handler should send the response to
    response_channel: tokio::sync::oneshot::Sender<String>,
}

# [derive(Debug, Clone)]
struct NodeConnection {
    pub state: ConnectionState,
    /// Channel to send requests to handler
    request_sender: Sender<WebSocketRequest>,
}

impl NodeConnection {
    /// Dispatch request to handler and wait for response
    async fn request(&self, text: String) -> Result<String, Box<dyn std::error::Error>> {
        let (tx, rx): (tokio::sync::oneshot::Sender<String>, tokio::sync::oneshot::Receiver<String>) = oneshot::channel();
        self.request_sender.send(WebSocketRequest {
            text,
            response_channel: tx,
        })?;
        match tokio::time::timeout(Duration::from_secs(15), rx).await? {
            Ok(response) => {
                Ok(response)
            }
            Err(x) => {
                Err(format!("Error receiving response from channel, sender is probably dropped: {}", x).into())
            }
        }
    }


    /// Terminate handler thread
    async fn terminate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.request("terminate".to_string()).await?;
        Ok(())
    }


    /// Handle incoming messages
    async fn handler(request_receiver: Receiver<WebSocketRequest>, mut write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>, mut read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>, cipher: AesGcm<Aes128, sha1::digest::typenum::consts::U16>) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
        let mut current_request: Option<WebSocketRequest> = None;
        debug!("Starting handler loop");
        loop {
            // If no current pending request, make one
            match current_request {
                None => {
                    // If there is a request waiting, send it
                    match request_receiver.try_recv() {
                        Ok(request) => {
                            debug!("Checking for internal control requests...");
                            // Check for internal handler-targeted control requests
                            let text = request.text.clone();
        
                            if text == "terminate" {
                                debug!("Terminating handler");
                                return Ok(());
                            } else if text == "ping" {
                                debug!("Sending pong");
                                request.response_channel.send("pong".to_string())?;
                                current_request = None;
                            } else {
                                debug!("Sending request: {}", request.text);
                                let nonce = rand::thread_rng().gen::<[u8; 16]>();

                                let mut buffer: Vec<u8> = vec![0; 1024];
                                buffer.extend_from_slice(request.text.as_bytes());
                                let tag = match cipher.encrypt_in_place_detached(GenericArray::from_slice(&nonce), b"", &mut buffer) {
                                    Ok(tag) => {
                                        Ok(tag)
                                    }
                                    Err(_) => {
                                        Err("Failed to encrypt message")
                                    }
                                }?;

                                debug!("Tag length: {}", tag.len());

                                let ciphertext = general_purpose::STANDARD.encode(&buffer);
                                let tag = general_purpose::STANDARD.encode(&tag);
                                let nonce = general_purpose::STANDARD.encode(&nonce);

                                write.send(Message::Text(
                                    format!("{}|||{}|||{}", ciphertext, tag, nonce)
                                )).await?;
                                current_request = Some(request);
                            }          
                        }
                        Err(_) => {
                        }
                    }
                },
                Some(_) => {
                }
            }

            match read.try_next().await {
                Ok(Some(msg)) => {
                    let msg = msg.to_text()?;
                    debug!("Received message: {}", msg);

                    let parts: Vec<&str> = msg.split("|||").collect();
                    let ciphertext = general_purpose::STANDARD.decode(parts[0])?;
                    let tag = general_purpose::STANDARD.decode(parts[1])?;
                    let nonce = general_purpose::STANDARD.decode(parts[2])?;
                    let combined = [&ciphertext[..], &tag[..]].concat();
                    let slice = &combined[..];

                    let msg = match cipher.decrypt(GenericArray::from_slice(&nonce), slice) {
                        Ok(msg) => {
                            Ok(msg)
                        }
                        Err(x) => {
                            Err("Failed to decrypt message")
                        }
                    }?;

                    debug!("Received message: {}", String::from_utf8(msg.clone())?);
                    // TODO - Handle interrupt messages
                    if false {
                        //self.interrupt_handler(msg).await?;
                    }
                    else {
                        match current_request {
                            Some(request) => {
                                request.response_channel.send(String::from_utf8(msg)?)?;
                                current_request = None;
                            }
                            None => {
                                Err("Received message without request")?;
                            }
                        }
                    };

                    Ok(())
                },
                // No message available
                Ok(None) => {
                    Ok(())
                },
                // Failed checking for message
                Err(x) => {
                    warn!("Error checking for message: {}", x);
                    Err(x)
                }
            }?;
        };
    }

    async fn new(address: String, handshake_key: Option<RsaPrivateKey>) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = match handshake_key {
            Some(key) => key,
            None => RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?,
        };
        
        let public_key = private_key.to_public_key();
        let public_key_string = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

        debug!("Connecting to node at {}", address);
        let (ws_stream, _) = connect_async(&address).await?;
        let (mut write, mut read) = ws_stream.split();

        // Send our public key to the node
        write.send(Message::Text(public_key_string.clone())).await?;
        let response = read.next().await.unwrap()?.into_text().unwrap();
        let response: HashMap<String, String> = serde_json::from_str(&response)?;

        let session_key = &response["sessionKey"];
        let bytes = general_purpose::STANDARD.decode(session_key).unwrap();
        let session_key = private_key.decrypt(Oaep::new::<sha1::Sha1>(), &bytes).unwrap();
        let cipher: AesGcm<Aes128, sha1::digest::typenum::consts::U16> = aes_gcm::AesGcm::new(GenericArray::from_slice(&session_key));

        // Setup request channel for sending requests to the handler
        let (request_sender, request_receiver): (Sender<WebSocketRequest>, Receiver<WebSocketRequest>) = crossbeam_channel::unbounded();
        let connection = Self {
            request_sender,
            state: ConnectionState::Connected
        };
        debug!("Spawning handler thread");
        tokio::spawn(async {
            debug!("Inside handler thread");
            match NodeConnection::handler(request_receiver, write, read, cipher).await {
                Ok(_) => {
                    debug!("Handler thread terminated");
                }
                Err(x) => {
                    warn!("Handler thread terminated with error: {}", x);
                }
            }
        });
        Ok(connection)
    }
}

/// Represents a node in the network
#[derive(Debug, Clone)]
pub struct Node {
    connection: Option<NodeConnection>,
    /// Connection address
    pub address: String,
    handshake_key: Option<RsaPrivateKey>,
}

impl Node {
    /// Initiate connection to node
    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.connection = Some(NodeConnection::new(self.address.clone(), self.handshake_key.clone()).await?);
        Ok(())
    }

    /// Disconnect from node
    pub async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let to_return = match &self.connection {
            Some(x) => {
                x.terminate().await
            },
            None => {Ok(())}
        };

        self.connection = None;
        to_return
    }

    /// Get connection state
    pub async fn connection_state(&self) -> ConnectionState {
        match &self.connection {
            Some(x) => {x.state},
            None => {ConnectionState::Disconnected},
        }
    }

    /// Send request to node
    pub async fn request(&self, text: String) -> Result<String, Box<dyn std::error::Error>> {
        match &self.connection {
            Some(x) => {
                x.request(text).await
            },
            None => {
                Err("Not connected to node")?
            }
        }
    }

    /// Create new unconnected node instance
    pub async fn new(address: String, handshake_key: Option<RsaPrivateKey>) -> Self {
        Self {
            connection: None,
            address,
            handshake_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_ADDRESS: &str = "ws://murraxcoin.murraygrov.es:6969";

    // Fails if can't connect to node
    #[tokio::test]
    async fn can_connect() {
        NodeConnection::new(NODE_ADDRESS.to_string(), None).await.unwrap();
    }

    // Checks if request handler is handling requests
    #[tokio::test]
    async fn handler_listening() {
        let connection = NodeConnection::new(NODE_ADDRESS.to_string(), None).await.unwrap();
        let response = connection.request("ping".to_string()).await.unwrap();
        assert_eq!(response, "pong");
    }

    // Check if encryption/decryption works
    #[tokio::test]
    async fn encryption() {
        let connection = NodeConnection::new(NODE_ADDRESS.to_string(), None).await.unwrap();
        let response = connection.request("{\"type\": \"ping\"}".to_string()).await.unwrap();
        assert_eq!(response, "{\"type\": \"confirm\", \"action\": \"ping\"}");
    }
}
