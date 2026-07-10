#[allow(clippy::module_inception)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/beemon.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/beemon.v1.serde.rs"));
}
pub use pb::*;
