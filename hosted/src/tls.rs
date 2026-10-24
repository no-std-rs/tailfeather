pub use tailfeather_reactor::native::tls::*;

#[cfg(test)]
mod tests {
    #[test]
    fn malformed_custom_ca_fails_before_a_node_starts() {
        let root = tempfile::tempdir().unwrap();
        let result = crate::Client::start(crate::Config {
            directory: root.path().join("unused"),
            control_url: "https://control.invalid".into(),
            hostname: "fixture".into(),
            auth_key: "fixture-only".into(),
            control_ca_der: vec![1, 2, 3],
            relay_only: false,
            ephemeral: true,
        });
        assert!(matches!(result,Err(error) if error.to_string()=="invalid control CA"));
        assert!(!root.path().join("unused").exists());
    }
}
