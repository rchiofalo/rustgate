fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = &[
        "proto/takmessage.proto",
        "proto/takcontrol.proto",
        "proto/cotevent.proto",
        "proto/detail.proto",
        "proto/contact.proto",
        "proto/group.proto",
        "proto/precisionlocation.proto",
        "proto/status.proto",
        "proto/takv.proto",
        "proto/track.proto",
    ];

    prost_build::compile_protos(protos, &["proto"])?;

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    Ok(())
}
