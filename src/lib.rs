pub mod css;
pub mod tokeniser;

#[cfg(test)]
mod tests {
    fn init() {
        let _ = env_logger::builder().is_test(true).init();
    }
}
