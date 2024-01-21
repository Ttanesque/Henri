use log::debug;

use crate::tokeniser::CssToken;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CharStream {
    index: usize,
    chars: Vec<char>,
}

#[derive(Debug)]
pub(crate) struct TokenStream {
    index: usize,
    tokens: Vec<CssToken>,
}

pub(crate) trait StreamIterator<I> {
    fn next(&mut self);
    fn back(&mut self);
    fn peek(&self) -> Option<I>;
}

impl CharStream {
    pub(crate) fn new(chars_to_stream: String) -> CharStream {
        CharStream {
            index: 0,
            chars: chars_to_stream.chars().collect(),
        }
    }
}

impl TokenStream {
    pub fn new(tokens: Vec<CssToken>) -> TokenStream {
        TokenStream { index: 0, tokens }
    }
}

impl StreamIterator<char> for CharStream {
    fn next(&mut self) {
        if self.index < self.chars.len() {
            self.index += 1;
        }
    }

    fn back(&mut self) {
        if self.index > 0 {  
            self.index -= 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }
}

impl StreamIterator<CssToken> for TokenStream {
    fn next(&mut self) {
        self.index += 1;
    }

    fn back(&mut self) {
        self.index -= 1;
    }

    fn peek(&self) -> Option<CssToken> {
        self.tokens.get(self.index).cloned()
    }
}

#[cfg(test)]
pub mod test_utils {
    pub fn init_test_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}
