use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};

use log::debug;
use url::Url;

use crate::tokeniser::CssToken;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CharStream {
    index: usize,
    chars: Vec<char>,
    marks: VecDeque<usize>,
}

#[derive(Debug)]
pub(crate) struct TokenStream {
    index: usize,
    tokens: Vec<CssToken>,
    marks: VecDeque<usize>,
}

/// Interface for explore a stream<i> with all the functionnality needed for the parsing.
pub trait StreamIterator<I> {
    /// Go to the next object in the stream. If it's in the end make nothing.
    fn next(&mut self);
    /// Go back in the stream. If it's the start make nothing.
    fn back(&mut self);
    /// Return of a copy of the current object otherwise return None.
    fn peek(&self) -> Option<I>;
    /// Place a marker to go back in the stream.
    fn mark(&mut self);
    /// Go back to the last marker and unmark it. If not return false.
    fn unmark(&mut self) -> bool;
    /// Discard the latest mark push.
    fn discard_mark(&mut self);
}

impl CharStream {
    pub(crate) fn new(chars_to_stream: String) -> CharStream {
        CharStream {
            index: 0,
            chars: chars_to_stream.chars().collect(),
            marks: VecDeque::new(),
        }
    }
}

impl TokenStream {
    pub fn new(tokens: Vec<CssToken>) -> TokenStream {
        TokenStream {
            index: 0,
            tokens,
            marks: VecDeque::new(),
        }
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

    fn mark(&mut self) {
        self.marks.push_back(self.index)
    }

    fn unmark(&mut self) -> bool {
        if let Some(index) = self.marks.pop_front() {
            self.index = index;
            return true;
        }
        false
    }

    fn discard_mark(&mut self) {
        self.marks.pop_front();
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

    fn mark(&mut self) {
        debug!("Stream Marks");
        self.marks.push_back(self.index)
    }

    fn unmark(&mut self) -> bool {
        if let Some(index) = self.marks.pop_front() {
            debug!("Stream unmark");
            self.index = index;
            return true;
        }
        false
    }

    fn discard_mark(&mut self) {
        self.marks.pop_front();
    }
}

/// Error description for file download error.
#[derive(Debug)]
pub enum ReadFileError {
    /// Unsuported scheme
    SchemeError(String),
    /// Invalid path for a path from file scheme
    LocationParsingError(()),
    FileReadError(io::Error),
    RequestError(attohttpc::Error),
}

impl From<()> for ReadFileError {
    fn from(value: ()) -> Self {
        ReadFileError::LocationParsingError(value)
    }
}

impl From<io::Error> for ReadFileError {
    fn from(value: io::Error) -> Self {
        ReadFileError::FileReadError(value)
    }
}

impl From<attohttpc::Error> for ReadFileError {
    fn from(value: attohttpc::Error) -> Self {
        ReadFileError::RequestError(value)
    }
}

/// Get the data from a url, handle the file and http scheme
pub(crate) fn get_data(location: &Url) -> Result<String, ReadFileError> {
    match location.scheme() {
        "file" => {
            let path = location.to_file_path()?;
            let mut file = File::open(path)?;
            let mut buff = String::new();
            let _ = file.read_to_string(&mut buff);
            Ok(buff)
        }
        "http" | "https" => {
            let body = attohttpc::get(location.as_str()).send()?.text()?;
            Ok(body)
        }
        _ => Err(ReadFileError::SchemeError("no valid scheme".to_string())),
    }
}

#[cfg(test)]
pub mod test_utils {
    pub fn init_test_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}
