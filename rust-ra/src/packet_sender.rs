use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;

pub fn get_connection(interface: &NetworkInterface) -> Channel {
    match datalink::channel(&interface, Default::default()) {
        Ok(ether) => ether,
        Err(e) => {
            panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            )
        }
    }
}
