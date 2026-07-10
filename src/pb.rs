pub mod pb {
    tonic::include_proto!("beemon.v1");
    include!(concat!(env!("OUT_DIR"), "/beemon.v1.serde.rs"));
}
