use std::time::Duration;

use futures_util::{StreamExt, stream::{SplitStream, SplitSink}, TryStreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message,
    WebSocketStream, MaybeTlsStream};
use tokio::net::TcpStream;

// Concurrency stuff
use crossbeam_channel::{Sender, Receiver};
use tokio::sync::oneshot;

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
        Ok(tokio::time::timeout(Duration::from_secs(15), rx).await??)
    }


    /// Terminate handler thread
    async fn terminate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.request("terminate".to_string()).await?;
        Ok(())
    }


    /// Handle incoming messages
    async fn handler(request_receiver: Receiver<WebSocketRequest>, mut write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>, mut read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
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
                                return Ok(());
                            } else if text == "ping" {
                                debug!("Sending pong");
                                request.response_channel.send("pong".to_string())?;
                                current_request = None;
                            } else {
                                debug!("Sending request: {}", request.text);
                                write.send(Message::Text(
                                    request.text.clone()
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
                    let msg: String = match msg {
                        Message::Text(text) => {
                            Ok(text)
                        }
                        _ => {
                            Err("Invalid message type")
                        }
                    }?;

                    todo!("Decrypt message, then check if interrupt, if so handle, otherwise dispatch to requester");
                    /*
                    let msg = self.decrypt(msg)?;
                    if interrupt {
                        self.interrupt_handler(msg).await?;
                    }
                    else {
                        match current_request {
                            Some(request) => {
                                request.response_channel.send(msg.text)?;
                                current_request = None;
                            }
                            None => {
                                Err("Received message without request")?;
                            }
                        }
                    }
                    */
                },
                // No message available
                Ok(None) => {
                    Ok(())
                },
                // Failed checking for message
                Err(x) => {
                    Err(x)
                }
            }?;
        };
    }


    async fn new(address: String) -> Result<Self, Box<dyn std::error::Error>> {
        debug!("Connecting to node at {}", address);
        let (ws_stream, _) = connect_async(&address).await?;
        let (write, read) = ws_stream.split();

        // TODO: Send handshake and setup encryption

        // Setup request channel for sending requests to the handler
        let (request_sender, request_receiver): (Sender<WebSocketRequest>, Receiver<WebSocketRequest>) = crossbeam_channel::unbounded();
        let connection = Self {
            request_sender,
            state: ConnectionState::Connected
        };
        debug!("Spawning handler thread");
        tokio::spawn(async {
            debug!("Inside handler thread");
            NodeConnection::handler(request_receiver, write, read).await
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
}

impl Node {
    /// Initiate connection to node
    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.connection = Some(NodeConnection::new(self.address.clone()).await?);
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
    pub async fn new(address: String) -> Self {
        Self {
            connection: None,
            address,
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
        NodeConnection::new(NODE_ADDRESS.to_string()).await.unwrap();
    }

    // Checks if request handler is handling requests
    #[tokio::test]
    async fn handler_listening() {
        let connection = NodeConnection::new(NODE_ADDRESS.to_string()).await.unwrap();
        let response = connection.request("ping".to_string()).await.unwrap();
        assert_eq!(response, "pong");
    }
}
