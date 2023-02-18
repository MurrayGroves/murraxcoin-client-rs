// Logging stuff
#[cfg(not(test))] 
use log::{warn, debug}; // Use log crate when building application
 
#[cfg(test)]
use std::{println as warn, println as debug}; // Workaround to use println! for logs.

// Transaction types

#[derive(Debug, PartialEq)]
pub struct Send {
    pub address: String,
    pub link: String,
    pub balance: f64,
    pub previous: String,
    pub representative: String,
    pub id: String,
    pub signature: String
}

#[derive(Debug, PartialEq)]
pub struct Receive {
    pub address: String,
    pub link: String,
    pub balance: f64,
    pub previous: String,
    pub representative: String,
    pub id: String,
    pub signature: String
}

#[derive(Debug, PartialEq)]
pub struct Open {
    pub address: String,
    pub link: String,
    pub balance: f64,
    pub previous: String,
    pub representative: String,
    pub id: String,
    pub signature: String
}

#[derive(Debug, PartialEq)]
pub struct Change {
    pub address: String,
    pub balance: f64,
    pub previous: String,
    pub representative: String,
    pub id: String,
    pub signature: String
}

#[derive(Debug, PartialEq)]
pub enum Block {
    Send(Send),
    Receive(Receive),
    Open(Open),
    Change(Change)
}

impl Block {
    pub fn from_str(s: &str) -> Result<Block, Box<dyn std::error::Error>> {
        let block: serde_json::Value = serde_json::from_str(s)?;
        let block_type = block["type"].as_str().unwrap();
        debug!("Block: {}", block);
        match block_type {
            "send" => {
                let send_block = Send {
                    address: block["address"].as_str().unwrap().to_string(),
                    link: block["link"].as_str().unwrap().to_string(),
                    balance: block["balance"].to_string().replace('"', "").trim().parse::<f64>().unwrap(),
                    previous: block["previous"].as_str().unwrap().to_string(),
                    representative: block["representative"].as_str().unwrap().to_string(),
                    id: block["id"].as_str().unwrap().to_string(),
                    signature: block["signature"].as_str().unwrap().to_string()
                };
                Ok(Block::Send(send_block))
            },
            "receive" => {
                let receive_block = Receive {
                    address: block["address"].as_str().unwrap().to_string(),
                    link: block["link"].as_str().unwrap().to_string(),
                    balance: block["balance"].to_string().replace('"', "").trim().parse::<f64>().unwrap(),
                    previous: block["previous"].as_str().unwrap().to_string(),
                    representative: block["representative"].as_str().unwrap().to_string(),
                    id: block["id"].as_str().unwrap().to_string(),
                    signature: block["signature"].as_str().unwrap().to_string()
                };
                Ok(Block::Receive(receive_block))
            },
            "open" => {
                let open_block = Open {
                    address: block["address"].as_str().unwrap().to_string(),
                    link: block["link"].as_str().unwrap().to_string(),
                    balance: block["balance"].to_string().replace('"', "").trim().parse::<f64>().unwrap(),
                    previous: block["previous"].as_str().unwrap().to_string(),
                    representative: block["representative"].as_str().unwrap().to_string(),
                    id: block["id"].as_str().unwrap().to_string(),
                    signature: block["signature"].as_str().unwrap().to_string()
                };
                Ok(Block::Open(open_block))
            },
            "change" => {
                let change_block = Change {
                    address: block["address"].as_str().unwrap().to_string(),
                    balance: block["balance"].to_string().replace('"', "").trim().parse::<f64>().unwrap(),
                    previous: block["previous"].as_str().unwrap().to_string(),
                    representative: block["representative"].as_str().unwrap().to_string(),
                    id: block["id"].as_str().unwrap().to_string(),
                    signature: block["signature"].as_str().unwrap().to_string()
                };
                Ok(Block::Change(change_block))
            },
            _ => Err("Invalid block type".into())
        }
    }
}

// Response types
pub struct PendingSend {
    pub amount: f64,
    pub link: String
}

pub struct AccountBalance {
    pub balance: f64,
    pub address: String
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_send() {
        let string = r#"{"type": "send", "address": "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i", "link": "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry", "balance": "935973.6979875462", "previous": "63faddc2d9c92dfa3d3e81e91ac8dc273c1776351a486b91b54403f0f35be9f11dfffc5342f2ba817f7616323b7ca0b0e2c68d1ff81f00138dbae4919d8d300c", "representative": "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i", "id": "143d40f87c3e2c4c204d5d760870144b76a21fb8b7051c7f7b100c078f1de2363019d9b6398405b6e5d19c5530d32bef54575952e6176d372361a378a148b0f2", "signature": "0xf05c0b913bda426ce6274aedf7c3fbcacbf067b35827b9753d195aa083b4e338aac99525288ea3e314adef19a1f8183ebd96967cdb406613be7a748ba844185"}"#;
        let block = Block::from_str(string).unwrap();
        let desired_block = Block::Send(Send {
            address: "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i".to_string(),
            link: "mxc_chjd6tbiokxpwucsbvhlfxe6paul5nnfik5ugotlrieepcqlve4a5iuq3ry".to_string(),
            balance: 935973.6979875462,
            previous: "63faddc2d9c92dfa3d3e81e91ac8dc273c1776351a486b91b54403f0f35be9f11dfffc5342f2ba817f7616323b7ca0b0e2c68d1ff81f00138dbae4919d8d300c".to_string(),
            representative: "mxc_f33eh3iqczypaxn7klhwqzpg4ssxx4wjirq4lmwfydvpvsjey6tae72bg2i".to_string(),
            id: "143d40f87c3e2c4c204d5d760870144b76a21fb8b7051c7f7b100c078f1de2363019d9b6398405b6e5d19c5530d32bef54575952e6176d372361a378a148b0f2".to_string(),
            signature: "0xf05c0b913bda426ce6274aedf7c3fbcacbf067b35827b9753d195aa083b4e338aac99525288ea3e314adef19a1f8183ebd96967cdb406613be7a748ba844185".to_string()
        });
        assert_eq!(block, desired_block)
    }

    #[test]
    fn from_str_open() {
        let string = r#"{"type": "open", "previous": "00000000000000000000", "address": "mxc_pp6nudgwnpacysurl2cezcl2ubaimukmuyarblo74drel4aqog5qbgobaea", "link": "mxc_q5j4bqj3ldhvgxy7cl3y6dgwd6mrr46k3jbp3hxytsslp6mhp57abrtrdoi/df127bb7bbbdc8a7cf19237e2163ab53687bdb31eea84e4c9cee9198184f2472720180c3d04ca0157e968b4fe272b7083bff3810df36e3f1b8622cdfa05ce3b4", "balance": 37.814789435244165, "representative": "mxc_pp6nudgwnpacysurl2cezcl2ubaimukmuyarblo74drel4aqog5qbgobaea", "id": "e7ef53a0f3ca77590fbc0b2eae246eb7cd43ed0dbe43231e5509dc0414fe332a46048ddd7b7c9cad1a54dbd448d5e5a0a3784770bb60c102597375af3e8e868a", "signature": "0xf942a6e4a0f4bd42196533165f4d6780a8b5ad7ce163e9d1d0cb54663487f90425b4b6855931ab77d49635dab6d1497c7cc81134072940ca26f6e6cb9428bab"}"#;
        let block = Block::from_str(string).unwrap();
        let desired_block = Block::Open(Open {
            previous: "00000000000000000000".to_string(),
            address: "mxc_pp6nudgwnpacysurl2cezcl2ubaimukmuyarblo74drel4aqog5qbgobaea".to_string(),
            link: "mxc_q5j4bqj3ldhvgxy7cl3y6dgwd6mrr46k3jbp3hxytsslp6mhp57abrtrdoi/df127bb7bbbdc8a7cf19237e2163ab53687bdb31eea84e4c9cee9198184f2472720180c3d04ca0157e968b4fe272b7083bff3810df36e3f1b8622cdfa05ce3b4".to_string(),
            balance: 37.814789435244165,
            representative: "mxc_pp6nudgwnpacysurl2cezcl2ubaimukmuyarblo74drel4aqog5qbgobaea".to_string(),
            id: "e7ef53a0f3ca77590fbc0b2eae246eb7cd43ed0dbe43231e5509dc0414fe332a46048ddd7b7c9cad1a54dbd448d5e5a0a3784770bb60c102597375af3e8e868a".to_string(),
            signature: "0xf942a6e4a0f4bd42196533165f4d6780a8b5ad7ce163e9d1d0cb54663487f90425b4b6855931ab77d49635dab6d1497c7cc81134072940ca26f6e6cb9428bab".to_string()
        });

        assert_eq!(block, desired_block)
    }

    #[test]
    fn from_str_receive() {
        let string = r#"{"type": "receive", "previous": "0d817907237cd8af3f0d0eee9927102ec8fb5d1912c5e8fc23f50767569a781255a407e26d8a3a001bc914b683832b6fe9fe7a06174f869913c08d054055ea1f", "address": "mxc_fflqj3xz3hfwhafdqwmlcrdaeyfz5lwef5a2jyrpf5xvlqwqiukaba6a6ta", "link": "mxc_z4zlpy23mdz3evqcyjv7qm37twutctao67efevmzxorzoljcyfgadhnrata/40647555dc21a22460864931a0cd28538b99b4882a53389dfc67ac344b24c72e948b2e236599a3adfa84aca34a97e84fa3364be8b5b5396970555ede05233234", "balance": 930.5015163018134, "representative": "mxc_fflqj3xz3hfwhafdqwmlcrdaeyfz5lwef5a2jyrpf5xvlqwqiukaba6a6ta", "id": "8efb28b012680c3353ad7f1cd8acec5e914bda0c79a8f32d96c2cc09a4bc16cb7dc30292a09435bdd82659eba2615b7d4fee775e3fad84889fed6473c3a7082d", "signature": "0xbe047c1989a1e0386717ff74aaad7940c8d01017f4a475ee95c6003783dd4b068d728831199fa7467bbcf1b6f40900034f159aab6618e5bf54b4b82523a722f"}"#;
        let block = Block::from_str(string).unwrap();
        let desired_block = Block::Receive( Receive {
            previous: "0d817907237cd8af3f0d0eee9927102ec8fb5d1912c5e8fc23f50767569a781255a407e26d8a3a001bc914b683832b6fe9fe7a06174f869913c08d054055ea1f".to_string(),
            address: "mxc_fflqj3xz3hfwhafdqwmlcrdaeyfz5lwef5a2jyrpf5xvlqwqiukaba6a6ta".to_string(),
            link: "mxc_z4zlpy23mdz3evqcyjv7qm37twutctao67efevmzxorzoljcyfgadhnrata/40647555dc21a22460864931a0cd28538b99b4882a53389dfc67ac344b24c72e948b2e236599a3adfa84aca34a97e84fa3364be8b5b5396970555ede05233234".to_string(),
            balance: 930.5015163018134,
            representative: "mxc_fflqj3xz3hfwhafdqwmlcrdaeyfz5lwef5a2jyrpf5xvlqwqiukaba6a6ta".to_string(),
            id: "8efb28b012680c3353ad7f1cd8acec5e914bda0c79a8f32d96c2cc09a4bc16cb7dc30292a09435bdd82659eba2615b7d4fee775e3fad84889fed6473c3a7082d".to_string(),
            signature: "0xbe047c1989a1e0386717ff74aaad7940c8d01017f4a475ee95c6003783dd4b068d728831199fa7467bbcf1b6f40900034f159aab6618e5bf54b4b82523a722f".to_string()
        });

        assert_eq!(block, desired_block)
    }
}