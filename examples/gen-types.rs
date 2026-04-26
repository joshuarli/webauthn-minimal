use std::fs::File;
use std::io::Write;
use ts_rs::{Config, TS};
use webauthn_minimal::*;

fn main() {
    let mut output = File::create("examples/demo/ts/types.ts").expect("failed to create types.ts");
    let cfg = Config::default();

    let content = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        RPInfo::export_to_string(&cfg).expect("failed to export RPInfo"),
        UserInfo::export_to_string(&cfg).expect("failed to export UserInfo"),
        PubKeyCredParam::export_to_string(&cfg).expect("failed to export PubKeyCredParam"),
        AuthenticatorSelection::export_to_string(&cfg)
            .expect("failed to export AuthenticatorSelection"),
        PublicKeyCredentialCreationOptions::export_to_string(&cfg)
            .expect("failed to export PublicKeyCredentialCreationOptions"),
        AllowCredential::export_to_string(&cfg).expect("failed to export AllowCredential"),
        PublicKeyCredentialRequestOptions::export_to_string(&cfg)
            .expect("failed to export PublicKeyCredentialRequestOptions"),
    );

    output
        .write_all(content.as_bytes())
        .expect("failed to write types");
}
