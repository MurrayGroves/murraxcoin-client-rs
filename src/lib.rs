use std::{time::Duration, collections::HashMap};

use aes_gcm::{KeyInit, aead::Aead, AeadInPlace, AesGcm, aes::Aes128};
use futures_util::{StreamExt, stream::{SplitStream, SplitSink}, TryStreamExt, SinkExt};
use rand::Rng;
use serde_json::json;
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

mod mxc_types;

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
                        Err(_) => {
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

    /// Disconnect from node, returns Error if terminated ungracefully and thread may still be running
    pub async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Tell handler thread to terminate
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
    pub async fn request(&self, json: serde_json::Value) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
        match &self.connection {
            Some(x) => {
                let request = serde_json::to_string(&json)?;
                let response: HashMap<String, serde_json::Value> = serde_json::from_str(&x.request(request).await?)?;
                Ok(response)
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

        /// Get a list of all accounts that have been opened and their balance
    /// NOTE: This may take a while to complete if there are a lot of accounts
    pub async fn get_accounts(&self) -> Result<Vec<mxc_types::AccountBalance>, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "getAccounts",
        });

        let response = self.request(request).await?;
        // Check if response is valid
        match response.get("type") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() != "getAccounts" {
                    return Err("Error while getting accounts: Type mismatched".into());
                }
            }
            None => {
                return Err("Error while getting accounts: No field named `type` in response".into());
            }
        };

        match response.get("accounts") {
            Some(x) => {
                debug!("Accounts: {}", x);
                let accounts: &serde_json::Map<String, serde_json::Value> = x.as_object().ok_or("accounts field is not an object")?;
                let mut account_balances: Vec<mxc_types::AccountBalance> = Vec::new();
                for account in accounts {
                    account_balances.push(mxc_types::AccountBalance {
                        address: account.0.to_string().replace('"', "").trim().to_string(),
                        balance: account.1.to_string().replace('"', "").trim().parse::<f64>()?,
                    });
                }

                Ok(account_balances)
            }
            None => {
                Err("No field named `accounts` in response".into())
            }
        }
    }
}


/// Represents an mxc account that can be used in un-authenticated requests
#[derive(Debug)]
#[allow(dead_code)]
struct Account {
    address: String,
    node: Node,
}

#[allow(dead_code)]
impl Account {
    /// Create new account instance, node is optional and will be created with default settings if not provided
    async fn new(address: String, node: Option<Node>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok (Self {
            address,
            node: match node {
                Some(x) => {x},
                None => {
                    let mut node = Node::new("ws://murraxcoin.murraygrov.es:6969".to_string(), None).await;
                    node.connect().await?;
                    node
                }
            }
        })
    }

    /// Get balance of the account
    async fn balance(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // TODO - Handle empty accounts
        let request = json!({
            "type": "balance",
            "address": &self.address,
        });

        let response = self.node.request(request).await?;
        debug!("Response: {:?}", response);
        match response.get("balance") {
            Some(x) => {
                Ok(x.to_string().replace('"', "").trim().parse::<f64>()?)
            }
            None => {
                Err("No field named `balance` in response".into())
            }
        }
    }

    /// Check for a pending transaction
    async fn pending_send(&self) -> Result<Option<mxc_types::PendingSend>, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "pendingSend",
            "address": &self.address,
        });

        let response = self.node.request(request).await?;
        match response.get("link") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() == "" {
                    return Ok(None);
                } else {
                    return Ok(Some(mxc_types::PendingSend {
                        link: x.to_string().replace('"', "").trim().to_string(),
                        amount: response.get("sendAmount").unwrap().to_string().replace('"', "").trim().parse::<f64>()?,
                    }));
                }
            }
            None => {
                // Even if no pending sends are available, there should be an empty field named `link` in the response
                Err("Request errored out while checking for pending send".into())
            }
        }
    }

    /// Return ID of the last transaction from this account
    async fn get_previous(&self) -> Result<String, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "getPrevious",
            "address": &self.address,
        });

        let response = self.node.request(request).await?;

        // Check if response is valid
        match response.get("type") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() != "previous" {
                    return Err("Error while getting previous: Type mismatched".into());
                }
            }
            None => {
                return Err("Error while getting previous: No field named `type` in response".into());
            }
        };

        match response.get("link") {
            Some(x) => {
                if response.get("address").ok_or("no field address")?.to_string().replace('"', "").trim() != self.address {
                    return Err("Error while getting previous: Address mismatched".into());
                };

                Ok(
                    x.to_string().replace('"', "").trim().to_string()
                )
            }
            None => {
                Err("No field named `link` in response".into())
            }
        }
    }

    /// Get this account's representative
    async fn get_representative(&self) -> Result<String, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "getRepresentative",
            "address": &self.address,
        });

        let response = self.node.request(request).await?;
        // Check if response is valid
        match response.get("type") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() != "info" {
                    return Err("Error while getting representative: Type mismatched".into());
                }
            }
            None => {
                return Err("Error while getting representative: No field named `type` in response".into());
            }
        };

        match response.get("representative") {
            Some(x) => {
                Ok(x.to_string().replace('"', "").trim().to_string())
            }
            None => {
                Err("No field named `representative` in response".into())
            }
        }
    }

    /// Get a block belonging to this account with specified ID
    async fn get_block(&self, id: String) -> Result<mxc_types::Block, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "getBlock",
            "address": &self.address,
            "block": &id,
        });

        let response = self.node.request(request).await?;
        // Check if response is valid
        match response.get("type") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() != "getBlock" {
                    return Err("Error while getting block: Type mismatched".into());
                }
            }
            None => {
                return Err("Error while getting block: No field named `type` in response".into());
            }
        };

        match response.get("block") {
            Some(x) => {
                let block = x.to_string();
                let block = mxc_types::Block::from_str(&block)?;
                Ok(block)
            }
            None => {
                Err("No field named `block` in response".into())
            }
        }
    }

    /// Get the most recent block belonging to this account
    async fn get_head(&self) -> Result<mxc_types::Block, Box<dyn std::error::Error>> {
        let request = json!({
            "type": "getHead",
            "address": &self.address,
        });

        let response = self.node.request(request).await?;
        // Check if response is valid
        match response.get("type") {
            Some(x) => {
                if x.to_string().replace('"', "").trim() != "getHead" {
                    return Err("Error while getting head: Type mismatched".into());
                }
            }
            None => {
                return Err("Error while getting head: No field named `type` in response".into());
            }
        };

        match response.get("block") {
            Some(x) => {
                let block = x.to_string();
                let block = mxc_types::Block::from_str(&block)?;
                Ok(block)
            }
            None => {
                Err("No field named `block` in response".into())
            }
        }
    }
}

/// Represents an mxc account that can be used in authenticated requests (transactions)
#[derive(Debug)]
#[allow(dead_code)]
struct AuthenticatedAccount {
    pub address: String,
    account: Account,
    keypair: ed25519_dalek::Keypair,
}

#[allow(dead_code)]
impl AuthenticatedAccount {
    /// Create new authenticated account instance, node is optional and will be created with default settings if not provided
    async fn new(keypair: ed25519_dalek::Keypair, node: Option<Node>) -> Result<Self, Box<dyn std::error::Error>> {
        let public_key = keypair.public.to_bytes();
        let slice = &public_key[..];
        let checksum = adler32::adler32(slice)?;
        let checksum = checksum.to_be_bytes();
        let checksum = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &checksum);
        let address = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &public_key);
        let address = format!("mxc_{}{}", address, checksum).to_lowercase();
        Ok (Self {
            address: address.clone(),
            account: Account::new(address, node).await?,
            keypair,
        })
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

    // Check if address is generated properly
    #[tokio::test]
    async fn check_address() {
        // Don't worry, these are testing keys!
        let keys = [189, 135, 96, 146, 26, 200, 148, 57, 163, 9, 22, 245, 156, 134, 68, 70, 62, 41, 241, 175, 118, 81, 167, 50, 162, 77, 38, 33, 60, 20, 190, 210, 159, 8, 255, 78, 136, 102, 194, 145, 196, 157, 0, 188, 9, 125, 184, 21, 159, 138, 114, 244, 248, 108, 5, 214, 37, 179, 244, 163, 104, 83, 124, 200];
        let keypair = ed25519_dalek::Keypair::from_bytes(&keys).unwrap();

        let account = AuthenticatedAccount::new(keypair, None).await.unwrap();
        assert_eq!(account.address, "mxc_t4ep6tuim3bjdre5ac6as7nycwpyu4xu7bwalvrfwp2kg2ctpteab5sbbyq");
    }

    // Check if json requests work
    #[tokio::test]
    async fn check_json() {
        let mut node = Node::new(NODE_ADDRESS.to_string(), None).await;
        node.connect().await.unwrap();
        let response = node.request(json!({"type": "ping"})).await.unwrap();
        assert_eq!(response.get("type").unwrap(), "confirm");
    }

    // Check if balance works
    #[tokio::test]
    async fn balance() {
        // Address with one open transaction with a balance of 1
        let address = "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry";
        let account = Account::new(address.to_string(), None).await.unwrap();
        let balance = account.balance().await.unwrap();
        assert!(balance == 1.0)
    }

    // Check if get previous works
    #[tokio::test]
    async fn previous() {
        // Address with one transaction with id 7a2ea6be0881d9e591568dac52f1344b24ffc7d33ef4e1e9069edc78f158c3f8c94bfed463cf032057f6a36f83af22ba4f5f33f84718b0ac9d10184b83899f12
        let address = "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry";
        let account = Account::new(address.to_string(), None).await.unwrap();
        let previous = account.get_previous().await.unwrap();
        assert_eq!(previous, "7a2ea6be0881d9e591568dac52f1344b24ffc7d33ef4e1e9069edc78f158c3f8c94bfed463cf032057f6a36f83af22ba4f5f33f84718b0ac9d10184b83899f12")
    }

    // Check if get representative works
    #[tokio::test]
    async fn representative() {
        // Address with representative as itself
        let address = "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry";
        let account = Account::new(address.to_string(), None).await.unwrap();
        let rep = account.get_representative().await.unwrap();
        assert_eq!(rep, "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry")
    }

    /// Check if `getAccounts` returns some accounts
    #[tokio::test]
    async fn get_accounts() {
        let mut node = Node::new(NODE_ADDRESS.to_string(), None).await;
        node.connect().await.unwrap();
        let accounts = node.get_accounts().await.unwrap();
        assert!(accounts.len() > 5);
    }

    #[tokio::test]
    async fn get_block() {
        let address = "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry";
        let account = Account::new(address.to_string(), None).await.unwrap();
        let block = account.get_block("7a2ea6be0881d9e591568dac52f1344b24ffc7d33ef4e1e9069edc78f158c3f8c94bfed463cf032057f6a36f83af22ba4f5f33f84718b0ac9d10184b83899f12".to_string()).await.unwrap();
        let desired_block = mxc_types::Block::from_str(r#"{"type": "open", "previous": "00000000000000000000", "address": "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry", "link": "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i/143d40f87c3e2c4c204d5d760870144b76a21fb8b7051c7f7b100c078f1de2363019d9b6398405b6e5d19c5530d32bef54575952e6176d372361a378a148b0f2", "balance": 1.0, "representative": "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry", "id": "7a2ea6be0881d9e591568dac52f1344b24ffc7d33ef4e1e9069edc78f158c3f8c94bfed463cf032057f6a36f83af22ba4f5f33f84718b0ac9d10184b83899f12", "signature": "0xf611565ace11e29e098c18a646b0adae4d4c5beb38dff1acd9456d08c4c199a2a94734ec8493ac825fc423999a4f77a918448dfb5b46ce2e7457685fb1aec7a"}"#).unwrap();
        assert_eq!(block, desired_block)
    }

    #[tokio::test]
    async fn get_head() {
        let address = "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry";
        let account = Account::new(address.to_string(), None).await.unwrap();
        let block = account.get_head().await.unwrap();
        let desired_block = mxc_types::Block::from_str(r#"{"type": "open", "previous": "00000000000000000000", "address": "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry", "link": "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i/143d40f87c3e2c4c204d5d760870144b76a21fb8b7051c7f7b100c078f1de2363019d9b6398405b6e5d19c5530d32bef54575952e6176d372361a378a148b0f2", "balance": 1.0, "representative": "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry", "id": "7a2ea6be0881d9e591568dac52f1344b24ffc7d33ef4e1e9069edc78f158c3f8c94bfed463cf032057f6a36f83af22ba4f5f33f84718b0ac9d10184b83899f12", "signature": "0xf611565ace11e29e098c18a646b0adae4d4c5beb38dff1acd9456d08c4c199a2a94734ec8493ac825fc423999a4f77a918448dfb5b46ce2e7457685fb1aec7a"}"#).unwrap();
        assert_eq!(block, desired_block)
    }
}
