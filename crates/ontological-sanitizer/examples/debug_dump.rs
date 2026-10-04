use ontological_sanitizer::sanitize_prompt;
fn main() {
    for input in [
        "The user requests data.",
        "user requests data",
        "the user requests data",
        "User requests data.",
    ] {
        let sp = sanitize_prompt(input);
        println!("{input:?} -> {}", sp.to_sanitized_json());
    }
}
