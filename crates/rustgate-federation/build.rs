fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only build gRPC proto types when the v2 feature is enabled.
    #[cfg(feature = "v2")]
    {
        // Compile the FederatedChannel gRPC service from fig.proto.
        // The extern_path maps the BinaryPayload package so the generated
        // code references our separately-compiled binarypayload module.
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .extern_path(".gov.tak.cop.proto.v1", "crate::v2::proto::binarypayload")
            .compile_protos(&["proto/figpb/fig.proto"], &["proto/figpb", "proto"])?;

        // Compile the BinaryPayload proto separately so it gets its own output file.
        // This is referenced by fig.proto's GeoEvent.bloads field.
        prost_build::compile_protos(&["proto/cotproto/binarypayload.proto"], &["proto"])?;

        // Trigger recompilation when proto files change
        println!("cargo:rerun-if-changed=proto/figpb/fig.proto");
        println!("cargo:rerun-if-changed=proto/cotproto/binarypayload.proto");
    }

    Ok(())
}
