#[cfg(test)]
mod tests {
    use assert_cmd::Command;

    #[test]
    fn integration_test() {
        let mut cmd = Command::cargo_bin("odoh-client-rs").unwrap();
        let assert = cmd.args(&["google.com", "A"]).assert();
        assert.success();
    }
}
