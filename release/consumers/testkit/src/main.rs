fn main() {
    let report = tailfeather_testkit::replay::check_all();
    println!("{}", serde_json::to_string(&report).unwrap());
    assert!(report.passed());
}
