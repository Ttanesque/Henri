#[derive(Debug)]
pub(crate) struct CharStream {
    index: usize,
    chars: Vec<char>,
}

pub(crate) trait StreamIterator {
    fn next(&mut self);
    fn back(&mut self);
    fn peek(&self) -> Option<char>;
}

impl CharStream {
    pub(crate) fn new(chars_to_stream: String) -> CharStream {
        CharStream {
            index: 0,
            chars: chars_to_stream.chars().collect(),
        }
    }
}

impl StreamIterator for CharStream {
    fn next(&mut self) {
        self.index += 1;
    }

    fn back(&mut self) {
        self.index -= 1;
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }
}

#[cfg(test)]
pub mod test_utils {
    pub fn init_test_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}
