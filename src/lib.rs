pub mod parser;
pub mod css;

#[cfg(test)]
mod tests {
    use std::fs;

    use log::debug;

    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).init();
    }

    #[test]
    fn css() {
        init();
        let raw_css = fs::read_to_string("test/style.css").expect("pas de fichier, pas de chocolats");
        debug!("ok");
        let _ = parser::parse(raw_css.as_str());
    }
}
