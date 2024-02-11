use std::{
    default,
    fs::File,
    io::{self, Read},
    path,
};

use url::Url;

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

pub trait StreamIterator<I> {
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

#[derive(Debug)]
pub enum ReadFileError {
    SchemeError(String),
    LocationParsingError(()),
    FileReadError(io::Error),
    RequestError(reqwest::Error),
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

impl From<reqwest::Error> for ReadFileError {
    fn from(value: reqwest::Error) -> Self {
        ReadFileError::RequestError(value)
    }
}

/// Get the data from a url
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
            let resp = reqwest::blocking::get(location.as_str())?;
            let body = resp.text()?;
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
