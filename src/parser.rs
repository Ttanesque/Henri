use crate::{
    tokeniser::{preprocessing, tokenization, CssToken},
    utils::{self, CharStream, StreamIterator, TokenStream},
};
use log::{self, debug, error, warn};
use url::Url;

pub struct Declaration {
    name: String,
    component_value: Vec<ComponentValue>,
    important: bool,
    original_text: Option<String>,
}

pub enum ComponentValue {
    PreservedToken(CssToken),
    Function {
        name: String,
        component_value: Vec<ComponentValue>,
    },
    SimpleBlock {
        associated_token: CssToken,
        value: Vec<ComponentValue>,
    },
}

pub enum Rule {
    AtRule {
        name: String,
        component_value: Vec<ComponentValue>,
    },
    BlockAtRule {
        name: String,
        component_value: Vec<ComponentValue>,
        declarations: Vec<Declaration>,
        child_rules: Vec<Rule>,
    },
    QualifiedRule {
        component_value: Vec<ComponentValue>,
        declarations: Vec<Declaration>,
        child_rules: Vec<Rule>,
    },
}

pub struct CssStyleSheet {
    type_sheet: String,
    location: String,
    parent: Option<Box<CssStyleSheet>>,
    // media:
    title: String,
    alternate: bool,
    disabled: bool,
    rules: Vec<Rule>,
    origin_clean: bool,
    constructed: bool,
    disallow_modification: bool,
    // constructor_document
    base_url: String,
}

impl CssStyleSheet {
    fn new(location: Url, rules: Vec<Rule>) -> CssStyleSheet {
        CssStyleSheet {
            type_sheet: "StyleSheet".to_string(),
            location: location.to_string(),
            parent: None,
            title: location.path().to_string(),
            alternate: false,
            disabled: false,
            rules: Vec::new(),
            origin_clean: false,
            constructed: false,
            disallow_modification: false,
            base_url: String::new(),
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    GetFileError(utils::ReadFileError),
    UnknowToken(CssToken),
    ParseError(String),
}

impl From<utils::ReadFileError> for ParseError {
    fn from(value: utils::ReadFileError) -> Self {
        ParseError::GetFileError(value)
    }
}

pub fn parse_stylesheet(url: Url) -> Result<CssStyleSheet, ParseError> {
    let datastream = utils::get_data(&url)?;
    let mut rules: Vec<Rule> = Vec::new();

    let mut token_stream = normalize(datastream);
    while let Some(token) = token_stream.peek() {
        match token {
            CssToken::WhitespaceToken | CssToken::CdcToken | CssToken::CdoToken => {
                token_stream.next();
            }
            _ => {
                if let Some(rule) = consume_qualified_rule(&mut token_stream, None, false) {
                    rules.push(rule);
                }
            }
        }
    }

    Ok(CssStyleSheet::new(url, rules))
}

pub fn consume_qualified_rule(
    tokens: &mut impl StreamIterator<CssToken>,
    stop_token: Option<CssToken>,
    nested: bool,
) -> Option<Rule> {
    let mut prelude: Vec<ComponentValue> = Vec::new();

    if let Some(token) = tokens.peek() {
        match token {
            CssToken::AcoladeClToken => {
                if nested {
                    warn!("parser error in consuming qualified rule Close Token encounter");
                    return None;
                }
                prelude.push(ComponentValue::PreservedToken(token));
            }
            CssToken::AcoladeOpToken => {}
            _ => {
                prelude.push(consume_component_value(tokens));
            }
        }
    }
    None
}

fn consume_component_value(
    tokens: &mut impl StreamIterator<CssToken>,
) -> Result<ComponentValue, ParseError> {
    if let Some(token) = tokens.peek() {
        match token {
            CssToken::AcoladeOpToken | CssToken::CrochetOpToken | CssToken::ParenthOpToken => {
                Err(ParseError::UnknowToken(token))
            }
            CssToken::FunctionToken(_) => consume_function(tokens),
            _ => {
                tokens.next();
                Ok(ComponentValue::PreservedToken(token))
            }
        }
    }
}

/// https://drafts.csswg.org/css-syntax/#consume-a-function
/// To consume a function from a token stream input:
/// Assert: The next token is a <function-token>.
///
/// Consume a token from input, and let function be a new function with its name equal the returned token’s value, and a value set to an empty list.
/// Process input:
/// * <eof-token> <)-token>
///     * Discard a token from input. Return function.
/// * anything else
///     * Consume a component value from input and append the result to function’s value.
fn consume_function(
    tokens: &mut impl StreamIterator<CssToken>,
) -> Result<ComponentValue, ParseError> {
    if let Some(CssToken::FunctionToken(name)) = tokens.peek() {
        let mut values: Vec<ComponentValue> = Vec::new();

        tokens.next();
        while let Some(token) = tokens.peek() {
            match token {
                CssToken::ParenthClToken => {
                    tokens.next();
                    break;
                }
                _ => {
                    let val = consume_component_value(tokens);
                    if val.is_ok() {
                        values.push(val.unwrap());
                    } else {
                        error!("error in function body parsing {:#?}", val.err())
                    }
                }
            }
        }
        return Ok(ComponentValue::Function {
            name,
            component_value: values,
        });
    }
    Err(ParseError::ParseError(String::from(
        "consuming function without function token ??",
    )))
}

/// https://drafts.csswg.org/css-syntax/#consume-a-simple-block
fn consume_simple_bloc(tokens: &mut impl StreamIterator<CssToken>) -> ComponentValue {
    todo!()
}

/// https://drafts.csswg.org/css-syntax/#normalize-into-a-token-stream
///
pub fn normalize(input: String) -> impl StreamIterator<CssToken> {
    let mut input_stream = CharStream::new(preprocessing(input));
    let mut tokens: Vec<CssToken> = Vec::new();

    while input_stream.peek().is_some() {
        match tokenization(&mut input_stream) {
            Err(err) => {
                log::error!("{}", err);
                break;
            }
            Ok(token) => tokens.push(token),
        }

        if tokens.len() > 1 && tokens.get(tokens.len() - 1) == tokens.get(tokens.len() - 2) {
            warn!("token already found {:#?}", tokens.get(tokens.len() - 1));
            break;
        }
        debug!("last token found {:#?}", tokens.get(tokens.len() - 1));
    }

    TokenStream::new(tokens)
}

#[cfg(test)]
mod parser_test {
    use std::{fs::File, io::Read};

    use crate::utils::test_utils::init_test_logger;

    use super::normalize;

    #[test]
    fn normalize_test() {
        init_test_logger();

        let mut file = File::open("./test/style.css").unwrap();
        let mut buffer = String::new();
        let _ = file.read_to_string(&mut buffer).unwrap();

        normalize(buffer);
        assert!(false);
    }
}
