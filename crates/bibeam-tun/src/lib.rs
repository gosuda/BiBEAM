#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert!(true, "crate compiles and tests run");
    }
}
