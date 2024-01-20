
use log::{debug, error, warn};

use crate::utils::StreamIterator;

// https://drafts.csswg.org/css-syntax/#tokenization
#[derive(Debug, PartialEq)]
pub(crate) enum HashTokenFlag {
    Id,
    Unrestricted,
}

#[derive(Debug, PartialEq)]
pub(crate) enum NumericValue {
    Integer,
    Number,
}

#[derive(Debug, PartialEq)]
pub(crate) enum CssToken {
    IdentToken(String),
    FunctionToken(String),
    AtKeywordToken(String),
    HashToken {
        flag: HashTokenFlag,
        value: String,
    },
    StringToken(String),
    UrlToken(String),
    BadStringToken,
    BadUrlToken,
    DelimToken(char),
    NumberToken {
        sign: bool,
        val_type: NumericValue,
        value: String,
    },
    PercentageToken {
        sign: bool,
        value: String,
    },
    DimensionToken {
        unit: String,
        sign: bool,
        val_type: NumericValue,
        value: String,
    },
    // UnicodeRangeToken,
    WhitespaceToken,
    CdoToken,
    CdcToken,
    ColonToken,
    SemicolonToken,
    CommaToken,
    CrochetOpToken,
    CrochetClToken,
    ParenthOpToken,
    ParenthClToken,
    AcoladeOpToken,
    AcoladeClToken,
}

/// Preprocess the CSS see the [spec](https://drafts.csswg.org/css-syntax/#input-preprocessing).
///
/// * Replace any U+000D CARRIAGE RETURN (CR) code points, U+000C FORM FEED (FF) code points, or pairs
///   of U+000D CARRIAGE RETURN (CR) followed by U+000A LINE FEED (LF) in input by a single U+000A LINE FEED (LF) code point.
/// * Replace any U+0000 NULL or surrogate code points in input with U+FFFD REPLACEMENT CHARACTER (�).
#[allow(dead_code)]
pub(crate) fn preprocessing(input: String) -> String {
    //
    let mut preprocess_input = input.replace("\r\n", "\n");
    preprocess_input = preprocess_input.replace("\r", "\n");
    preprocess_input = preprocess_input.replace("\x0c", "\n");
    preprocess_input.replace("\x00", "�")
}

// https://drafts.csswg.org/css-syntax/#consume-token
#[allow(dead_code)]
pub(crate) fn tokenization(stream: &mut dyn StreamIterator) -> Result<CssToken, String> {
    while let Some(current_input) = stream.peek() {
        match current_input {
            '\n' | '\t' | ' ' => {
                consume_whitespaces(stream);
                return Ok(CssToken::WhitespaceToken);
            }
            '"' | '\'' => {
                stream.next();
                return Ok(consume_string_token(stream, current_input));
            }
            '#' => {
                if is_indent_code_point(current_input) || start_valid_escape(stream) {
                    let mut flag = HashTokenFlag::Unrestricted;
                    if start_ident_sequence(stream) {
                        flag = HashTokenFlag::Id;
                    }
                    return Ok(CssToken::HashToken {
                        flag,
                        value: consume_ident_sequence(stream),
                    });
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            '\\' => {
                stream.next();
                if let Some(next_char) = stream.peek() {
                    if next_char != '\n' {
                        // ident like token
                        stream.back();
                        return Ok(consume_ident_like_token(stream));
                    } else {
                        return Ok(CssToken::DelimToken(current_input));
                    }
                }
            }
            '+' => {
                if start_number(stream) {
                    return Ok(consume_numeric_token(stream));
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            '-' => {
                if start_number(stream) {
                    return Ok(consume_numeric_token(stream));
                } else if next_2_char_is(stream, '\u{002D}', '\u{003E}') {
                    stream.next();
                    stream.next();
                    return Ok(CssToken::CdcToken);
                } else if start_ident_sequence(stream) {
                    return Ok(consume_ident_like_token(stream));
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            '0'..='9' => {
                return Ok(consume_numeric_token(stream));
            }
            '@' => {
                stream.next();
                if start_ident_sequence(stream) {
                    return Ok(CssToken::AtKeywordToken(consume_ident_sequence(stream)));
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            '.' => {
                if start_number(stream) {
                    return Ok(consume_numeric_token(stream));
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            '<' => {
                stream.next();
                if next_2_char_is(stream, '\u{0021}', '\u{002D}') {
                    stream.next();
                    stream.next();
                    if next_char_is_x(stream, '\u{002D}') {
                        return Ok(CssToken::CdoToken);
                    } else {
                        stream.back();
                        stream.back();
                    }
                } else {
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
            'U' | 'u' => {
                warn!("Unicode not supported");
                return Ok(consume_ident_like_token(stream));
            }
            '(' => {
                stream.next();
                return Ok(CssToken::ParenthOpToken);
            }
            ')' => {
                stream.next();
                return Ok(CssToken::ParenthClToken);
            }
            '[' => {
                stream.next();
                return Ok(CssToken::CrochetOpToken);
            }
            ']' => {
                stream.next();
                return Ok(CssToken::CrochetClToken);
            }
            '{' => {
                stream.next();
                return Ok(CssToken::AcoladeOpToken);
            }
            '}' => {
                stream.next();
                return Ok(CssToken::AcoladeClToken);
            }
            ',' => {
                stream.next();
                return Ok(CssToken::CommaToken);
            }
            ':' => {
                stream.next();
                return Ok(CssToken::ColonToken);
            }
            ';' => {
                stream.next();
                return Ok(CssToken::SemicolonToken);
            }
            _ => {
                if is_ident_start_code_point(current_input) {
                    return Ok(consume_ident_like_token(stream));
                } else {
                    stream.next();
                    return Ok(CssToken::DelimToken(current_input));
                }
            }
        }
    }

    Err("No token".to_string())
}

/// Take the input stream and consume all of the whitespace.
fn consume_whitespaces(it: &mut dyn StreamIterator) {
    while let Some(wp) = it.peek() {
        if is_whitespace(wp) {
            it.next();
        } else {
            break;
        }
    }
}

/// https://drafts.csswg.org/css-syntax/#consume-ident-like-token
fn consume_ident_like_token(it: &mut dyn StreamIterator) -> CssToken {
    let string = consume_ident_sequence(it);

    it.next();

    if matches!(string.to_lowercase().as_str(), "url") {
        if let Some(current_char) = it.peek() {
            if current_char == '(' {
                it.next();
                consume_whitespaces(it);
                if next_char_is_quote(it) {
                    return CssToken::FunctionToken(string);
                } else {
                    return consume_url_token(it);
                }
            }
        }
    } else if let Some(current_char) = it.peek() {
        if current_char == '(' {
            it.next();
            return CssToken::FunctionToken(string);
        }
    }

    return CssToken::IdentToken(string);
}

/// https://drafts.csswg.org/css-syntax/#consume-a-numeric-token
fn consume_numeric_token(it: &mut dyn StreamIterator) -> CssToken {
    let number = consume_number(it);
    let CssToken::NumberToken {
        sign,
        val_type,
        value,
    } = number
    else {
        error!("Unknow error a number consuming go wrong {:#?}", number);
        todo!()
    };

    if start_ident_sequence(it) {
        let unit = consume_ident_sequence(it);
        debug!("{:?}", unit);
        return CssToken::DimensionToken {
            unit,
            sign,
            val_type,
            value,
        };
    } else if char_is_x(it, '%') {
        return CssToken::PercentageToken { sign, value };
    } else {
        return CssToken::NumberToken {
            sign,
            val_type,
            value,
        };
    }
}

/// Consume a String token with is ending_char.
/// https://drafts.csswg.org/css-syntax/#consume-string-token
fn consume_string_token(it: &mut dyn StreamIterator, ending_char: char) -> CssToken {
    let mut string = String::new();
    while let Some(curr_input) = it.peek() {
        it.next();
        if ending_char == curr_input {
            it.next();
            break;
        }
        match curr_input {
            '\n' | '\t' | ' ' => {
                it.back();
                return CssToken::BadStringToken;
            }
            '\\' => {
                it.next();
                if let Some(next_char) = it.peek() {
                    if next_char != '\n' {
                        string.push(curr_input);
                        string.push(next_char);
                    }
                }
            }
            _ => string.push(curr_input),
        }
    }

    CssToken::StringToken(string)
}

/// https://drafts.csswg.org/css-syntax/#consume-a-url-token
fn consume_url_token(it: &mut dyn StreamIterator) -> CssToken {
    let mut url = String::new();
    consume_whitespaces(it);
    while let Some(current_char) = it.peek() {
        match current_char {
            ')' => {
                it.next();
                return CssToken::UrlToken(url);
            }
            '\n' | '\t' | ' ' => {
                consume_whitespaces(it);
            }
            '\''
            | '"'
            | '('
            | '\u{000B}'
            | '\u{007F}'
            | '\u{0000}'..='\u{0008}'
            | '\u{000E}'..='\u{001F}' => {
                consume_remnants_bad_url(it);
                return CssToken::BadUrlToken;
            }
            '\\' => {
                if start_valid_escape(it) {
                    url.push(consume_escaped_code_point(it));
                    it.next();
                } else {
                    consume_remnants_bad_url(it);
                    return CssToken::BadUrlToken;
                }
            }
            _ => {
                url.push(current_char);
                it.next();
            }
        }
    }

    CssToken::UrlToken(url)
}

// https://drafts.csswg.org/css-syntax/#consume-an-ident-sequence
fn consume_ident_sequence(it: &mut dyn StreamIterator) -> String {
    let mut result = String::new();

    while let Some(current_char) = it.peek() {
        match current_char {
            '_'
            | '-'
            | '\u{00B7}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{203F}'
            | '\u{2040}'
            | 'a'..='z'
            | 'A'..='Z'
            | '0'..='9'
            | '\u{00C0}'..='\u{00D6}'
            | '\u{00D8}'..='\u{00F6}'
            | '\u{00F8}'..='\u{037D}'
            | '\u{037F}'..='\u{1FFF}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D2FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}' => {
                it.next();
                result.push(current_char);
            }
            '\\' => {
                if start_valid_escape(it) {
                    it.next();
                    result.push(consume_escaped_code_point(it));
                }
            }
            _ => {
                if current_char > '\u{10000}' {
                    result.push(current_char);
                    it.next();
                } else {
                    it.back();
                    return result;
                }
            }
        }
    }
    result
}

/// https://drafts.csswg.org/css-syntax/#consume-a-number
fn consume_number(it: &mut dyn StreamIterator) -> CssToken {
    let mut type_num = false; // false integer, true number
    let mut sign = true; // tue +, false -; default true
    let mut number = String::new();

    while let Some(current_char) = it.peek() {
        match current_char {
            '+' => {
                it.next();
            }
            '-' => {
                sign = false;
                it.next();
            }
            '0'..='9' => {
                number.push(current_char);
                it.next();
            }
            '.' => {
                it.next();
                if let Some(next_char) = it.peek() {
                    if is_digit(next_char) {
                        number.push(current_char);
                        number.push_str(consume_digit(it).as_str());
                        type_num = true;
                    } else {
                        it.back();
                        break;
                    }
                } else {
                    it.back();
                    break;
                }
            }
            'e' | 'E' => {
                // ! Erreur possible besoins de vérifier les 2 char mais 1 seul de fais
                debug!("{:?}", it.peek());
                if next_char_is(it, |x| matches!(x, '+' | '-' | '0'..='9')) {
                    debug!("e detecter");
                    number.push(current_char.to_ascii_lowercase());
                    number.push_str(consume_digit(it).as_mut_str());
                } else {
                    debug!("e sans digit {:?}", it.peek());
                    break;
                }
            }
            _ => break,
        }
    }

    if type_num {
        CssToken::NumberToken {
            sign,
            value: number,
            val_type: NumericValue::Number,
        }
    } else {
        CssToken::NumberToken {
            sign,
            value: number,
            val_type: NumericValue::Integer,
        }
    }
}

/// https://drafts.csswg.org/css-syntax/#consume-an-escaped-code-point
fn consume_escaped_code_point(it: &mut dyn StreamIterator) -> char {
    if let Some(current_char) = it.peek() {
        if is_hex_digit(current_char) {
            let mut hex_value = String::new();
            hex_value.push(current_char);
            it.next();
            let mut count = 0;
            while let Some(next_char) = it.peek() {
                if !is_hex_digit(next_char) && count < 5 {
                    break;
                }
                hex_value.push(next_char);
                it.next();
                count += 1;
            }

            // already check that the char is in the hexrange
            let value = u32::from_str_radix(&hex_value, 16).unwrap();

            if value == 0 || is_a_surrogate_hex(value) || is_max_allowed_code_point_hex(value) {
                return '\u{FFFD}';
            } else {
                return char::from_u32(value).unwrap();
            }
        } else {
            return current_char;
        }
    } else {
        // EOF parsing error
        return '\u{FFFD}';
    }
}

/// https://drafts.csswg.org/css-syntax/#starts-with-a-valid-escape
fn start_valid_escape(it: &mut dyn StreamIterator) -> bool {
    if let Some(first_char) = it.peek() {
        if first_char != '\\' {
            return false;
        }
        it.next();
        if let Some(second_char) = it.peek() {
            it.back(); // reset to is origin place for future
            return second_char != '\u{000A}';
        }
    }

    false
}

/// https://drafts.csswg.org/css-syntax/#check-if-three-code-points-would-start-a-number
fn start_number(it: &mut dyn StreamIterator) -> bool {
    if let Some(current_char) = it.peek() {
        match current_char {
            '+' | '-' => {
                it.next();
                if let Some(next_char) = it.peek() {
                    if is_digit(next_char) {
                        it.back();
                        return true;
                    } else if next_char == '.' {
                        it.next();
                        if let Some(third_char) = it.peek() {
                            it.back();
                            it.back();
                            return is_digit(third_char);
                        }
                        it.back();
                    }
                    it.back();
                }
                it.back();
            }
            '.' => {
                it.next();
                if let Some(next_char) = it.peek() {
                    if is_digit(current_char) {
                        it.back();
                        return is_digit(next_char);
                    }
                    it.back();
                }
            }
            _ => return is_digit(current_char),
        }
    }

    false
}

/// https://drafts.csswg.org/css-syntax/#check-if-three-code-points-would-start-an-ident-sequence
fn start_ident_sequence(it: &mut dyn StreamIterator) -> bool {
    if let Some(first_code) = it.peek() {
        match first_code {
            '\u{002D}' => {
                it.next();
                if let Some(second_char) = it.peek() {
                    if is_ident_start_code_point(second_char)
                        || second_char == '\u{002D}'
                        || start_valid_escape(it)
                    {
                        it.back();
                        return true;
                    }
                }
                it.back();
                return false;
            }
            '\\' => {
                return start_valid_escape(it);
            }
            _ => {
                return is_ident_start_code_point(first_code);
            }
        }
    }

    false
}

/// https://drafts.csswg.org/css-syntax/#consume-the-remnants-of-a-bad-url
fn consume_remnants_bad_url(it: &mut dyn StreamIterator) {
    while let Some(current_char) = it.peek() {
        match current_char {
            ')' => {
                it.next();
                break;
            }
            '\\' => {
                consume_escaped_code_point(it);
                it.next();
            }
            _ => {
                it.next();
            }
        }
    }
}

// --- utils ---

/// Consume a chunk of digit.
fn consume_digit(it: &mut dyn StreamIterator) -> String {
    let mut result = String::new();

    while let Some(current_char) = it.peek() {
        if is_digit(current_char) {
            result.push(current_char);
            it.next();
        } else {
            break;
        }
    }

    result
}

#[inline]
fn next_2_char_is(it: &mut dyn StreamIterator, first: char, second: char) -> bool {
    if let Some(first_char) = it.peek() {
        if first_char == first {
            it.next();
            if let Some(second_char) = it.peek() {
                if second_char == second {
                    it.back();
                    return true;
                }
            }
            it.back();
        }
    }
    false
}

#[inline]
fn next_char_is(it: &mut dyn StreamIterator, f: fn(char) -> bool) -> bool {
    it.next();
    debug!("before {:?}", it.peek());
    if let Some(next_char) = it.peek() {
        it.back();
        debug!("after {:?}", it.peek());
        return f(next_char);
    }
    debug!("{:?}", it.peek());
    it.back();
    debug!("{:?}", it.peek());
    false
}

/// check if char is x
#[inline]
fn char_is_x(it: &mut dyn StreamIterator, x: char) -> bool {
    if let Some(current) = it.peek() {
        return current == x;
    }
    false
}

/// Check if the next char is x
#[inline]
fn next_char_is_x(it: &mut dyn StreamIterator, x: char) -> bool {
    it.next();
    if let Some(next_char) = it.peek() {
        debug!("next_char {} is {}", next_char, x);
        it.back();
        return next_char == x;
    }
    it.back();
    false
}

/// Check if a char is string gard ' or ".
#[inline]
fn next_char_is_quote(it: &mut dyn StreamIterator) -> bool {
    next_char_in(it, &['"', '\''])
}

/// Check if the next char is in the given array.
#[inline]
fn next_char_in(it: &mut dyn StreamIterator, x: &[char]) -> bool {
    it.next();
    if let Some(next_char) = it.peek() {
        return x.contains(&next_char);
    }
    it.back();
    false
}

#[inline]
fn is_whitespace(char_check: char) -> bool {
    matches!(char_check, '\n' | '\t' | ' ')
}

/// Check if a char is a digit
#[inline]
fn is_digit(char_check: char) -> bool {
    matches!(char_check, '0'..='9')
}

#[inline]
fn is_hex_digit(char_check: char) -> bool {
    matches!(char_check, '0'..='9' | 'a'..='z' | 'A'..='Z')
}

#[inline]
fn is_letter(char_check: char) -> bool {
    matches!(char_check, 'a'..='z' | 'A'..='Z')
}

#[inline]
fn is_non_ascii_ident(char_check: char) -> bool {
    matches!(char_check,
    '\u{00B7}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{203F}'
            | '\u{2040}'
            | '\u{00C0}'..='\u{00D6}'
            | '\u{00D8}'..='\u{00F6}'
            | '\u{00F8}'..='\u{037D}'
            | '\u{037F}'..='\u{1FFF}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D2FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}')
        || char_check > '\u{10000}'
}

/// https://drafts.csswg.org/css-syntax/#ident-start-code-point
#[inline]
fn is_ident_start_code_point(char_check: char) -> bool {
    is_letter(char_check) || is_non_ascii_ident(char_check) || char_check == '_'
}

/// https://drafts.csswg.org/css-syntax/#ident-code-point
#[inline]
fn is_indent_code_point(char_check: char) -> bool {
    is_ident_start_code_point(char_check) || is_digit(char_check) || char_check == '\u{002D}'
}

// --- hex ---

/// https://infra.spec.whatwg.org/#surrogate
#[inline]
fn is_a_surrogate_hex(char_value: u32) -> bool {
    is_a_leading_surrogate_hex(char_value) || is_a_trailing_surrogate_hex(char_value)
}

/// https://infra.spec.whatwg.org/#leading-surrogate
#[inline]
fn is_a_leading_surrogate_hex(char_value: u32) -> bool {
    char_value >= 0xD800 && char_value <= 0xDBFF
}

/// https://infra.spec.whatwg.org/#trailing-surrogate
#[inline]
fn is_a_trailing_surrogate_hex(char_value: u32) -> bool {
    char_value >= 0xDC00 && char_value <= 0xDFFF
}

/// https://drafts.csswg.org/css-syntax/#maximum-allowed-code-point
#[inline]
fn is_max_allowed_code_point_hex(char_value: u32) -> bool {
    char_value > 0x10FFFF
}

#[cfg(test)]
mod tests {
    use crate::{
        tokeniser::{
            consume_digit, consume_number, consume_numeric_token, preprocessing, start_number,
            CssToken, NumericValue,
        },
        utils::{test_utils, CharStream, StreamIterator},
    };

    #[test]
    fn test_preprocessing() {
        test_utils::init_test_logger();

        assert_eq!(
            "Hello\nWorld",
            preprocessing("Hello\x0CWorld".to_string()),
            "Preprocessing for form feed"
        );
        assert_eq!(
            "Hello\nWorld",
            preprocessing("Hello\rWorld".to_string()),
            "Preprocessing for Carriage return"
        );
        assert_eq!(
            "Hello\nWorld",
            preprocessing("Hello\r\nWorld".to_string()),
            "Preprocessing for Carriage return + End of line"
        );
        assert_eq!(
            "Hello\n\nWorld",
            preprocessing("Hello\r\n\nWorld".to_string())
        );
    }

    #[test]
    fn test_number() {
        test_utils::init_test_logger();

        // number consume by chunk
        {
            let mut stream = CharStream::new("54".to_string());
            assert_eq!("54", consume_digit(&mut stream), "Consuming only 2 digit 54");

            let mut stream = CharStream::new("12s".to_string());
            assert_eq!("12", consume_digit(&mut stream), "Consume 2 digit and stop 12s");
        }

        // number detection
        {
            let mut stream = CharStream::new("-1.2".to_string());
            assert!(start_number(&mut stream), "Start number -1.2");

            let mut stream = CharStream::new("24".to_string());
            assert!(start_number(&mut stream), "Start number 24");

            let mut stream = CharStream::new("+34".to_string());
            assert!(start_number(&mut stream), "Start number +34");

            let mut stream = CharStream::new("a4".to_string());
            assert!(!start_number(&mut stream), "Start number a4");
        }

        // consume number
        {
            let nb = String::from("12%");
            let mut stream = CharStream::new(nb);
            assert_eq!(
                CssToken::NumberToken {
                    sign: true,
                    val_type: NumericValue::Integer,
                    value: "12".to_string()
                },
                consume_number(&mut stream)
            );
            assert_eq!(Some('%'), stream.peek());

            let nb = String::from("1.4%");
            let mut stream = CharStream::new(nb);
            assert_eq!(
                CssToken::NumberToken {
                    sign: true,
                    val_type: NumericValue::Number,
                    value: "1.4".to_string()
                },
                consume_number(&mut stream)
            );
            assert_eq!(Some('%'), stream.peek());
        }

        // numeric token production number token
        {
            let nb_token = String::from("-1.4");
            let mut stream = CharStream::new(nb_token);
            assert_eq!(
                CssToken::NumberToken {
                    sign: false,
                    val_type: NumericValue::Number,
                    value: "1.4".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let nb_token = String::from("14");
            let mut stream = CharStream::new(nb_token);
            assert_eq!(
                CssToken::NumberToken {
                    sign: true,
                    val_type: NumericValue::Integer,
                    value: "14".to_string()
                },
                consume_numeric_token(&mut stream)
            );
        }
        // numeric token production percentage token
        {
            let nb_token = String::from("14%");
            let mut stream = CharStream::new(nb_token);
            assert_eq!(
                CssToken::PercentageToken {
                    sign: true,
                    value: "14".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let nb_token = String::from("1.4%");
            let mut stream = CharStream::new(nb_token);
            assert_eq!(
                CssToken::PercentageToken {
                    sign: true,
                    value: "1.4".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let nb_token = String::from("-1.4%");
            let mut stream = CharStream::new(nb_token);
            assert_eq!(
                CssToken::PercentageToken {
                    sign: false,
                    value: "1.4".to_string()
                },
                consume_numeric_token(&mut stream)
            );
        }

        // numeric token production dimension token
        {
            let dim_token = String::from("42px");
            let mut stream = CharStream::new(dim_token);
            assert_eq!(
                CssToken::DimensionToken {
                    unit: "px".to_string(),
                    sign: true,
                    val_type: NumericValue::Integer,
                    value: "42".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let dim_token = String::from("4.2px");
            let mut stream = CharStream::new(dim_token);
            assert_eq!(
                CssToken::DimensionToken {
                    unit: "px".to_string(),
                    sign: true,
                    val_type: NumericValue::Number,
                    value: "4.2".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let dim_token = String::from("4.2rem");
            let mut stream = CharStream::new(dim_token);
            assert_eq!(
                CssToken::DimensionToken {
                    unit: "rem".to_string(),
                    sign: true,
                    val_type: NumericValue::Number,
                    value: "4.2".to_string()
                },
                consume_numeric_token(&mut stream)
            );

            let dim_token = String::from("4.2em");
            let mut stream = CharStream::new(dim_token);
            assert_eq!(
                CssToken::DimensionToken {
                    unit: "em".to_string(),
                    sign: true,
                    val_type: NumericValue::Number,
                    value: "4.2".to_string()
                },
                consume_numeric_token(&mut stream)
            );
        }
    }
}
