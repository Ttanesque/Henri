use std::{char, iter::Peekable, str::Chars};

use log::{error, warn};

// https://drafts.csswg.org/css-syntax/#tokenization
#[derive(Debug)]
pub(crate) enum HashTokenFlag {
    Id,
    Unrestricted,
}

#[derive(Debug)]
pub(crate) enum NumericValue {
    Integer,
    Number,
}

#[derive(Debug)]
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
pub(crate) fn tokenization(input: String) -> Result<Vec<CssToken>, String> {
    let mut tokens = Vec::new();

    let mut it = input.chars().peekable();
    while let Some(&current_input) = it.peek() {
        match current_input {
            '\n' | '\t' | ' ' => {
                consume_whitespaces(&mut it);
                tokens.push(CssToken::WhitespaceToken);
            }
            '"' | '\'' => {
                it.next();
                tokens.push(consume_string_token(&mut it, current_input));
            }
            '#' => {
                if is_indent_code_point(current_input) || start_valid_escape(&mut it) {
                    let mut flag = HashTokenFlag::Unrestricted;
                    if start_ident_sequence(&mut it) {
                        flag = HashTokenFlag::Id;
                    }
                    tokens.push(CssToken::HashToken {
                        flag,
                        value: consume_ident_sequence(&mut it),
                    });
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            '\\' => {
                it.next();
                if let Some(&next_char) = it.peek() {
                    if next_char != '\n' {
                        // ident like token
                        it.next_back();
                        tokens.push(consume_ident_like_token(&mut it));
                    } else {
                        tokens.push(CssToken::DelimToken(current_input));
                    }
                }
            }
            '+' => {
                if start_number(&mut it) {
                    tokens.push(consume_numeric_token(&mut it));
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            '-' => {
                if start_number(&mut it) {
                    tokens.push(consume_numeric_token(&mut it));
                } else if next_2_char_is(&mut it, '\u{002D}', '\u{003E}') {
                    it.next();
                    it.next();
                    tokens.push(CssToken::CdcToken);
                } else if start_ident_sequence(&mut it) {
                    tokens.push(consume_ident_like_token(&mut it));
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            '0'..='9' => {
                tokens.push(consume_numeric_token(&mut it));
            }
            '@' => {
                it.next();
                if start_ident_sequence(&mut it) {
                    tokens.push(CssToken::AtKeywordToken(consume_ident_sequence(&mut it)));
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            '.' => {
                if start_number(&mut it) {
                    tokens.push(consume_numeric_token(&mut it));
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            '<' => {
                it.next();
                if next_2_char_is(&mut it, '\u{0021}', '\u{002D}') {
                    it.next();
                    it.next();
                    if next_char_is_x(&mut it, '\u{002D}') {
                        tokens.push(CssToken::CdoToken);
                    } else {
                        it.next_back();
                        it.next_back();
                    }
                } else {
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
            'U' | 'u' => {
                warn!("Unicode not supported");
                tokens.push(consume_ident_like_token(&mut it));
            }
            '(' => {
                it.next();
                tokens.push(CssToken::ParenthOpToken);
            }
            ')' => {
                it.next();
                tokens.push(CssToken::ParenthClToken);
            }
            '[' => {
                it.next();
                tokens.push(CssToken::CrochetOpToken);
            }
            ']' => {
                it.next();
                tokens.push(CssToken::CrochetClToken);
            }
            '{' => {
                it.next();
                tokens.push(CssToken::AcoladeOpToken);
            }
            '}' => {
                it.next();
                tokens.push(CssToken::AcoladeClToken);
            }
            ',' => {
                it.next();
                tokens.push(CssToken::CommaToken);
            }
            ':' => {
                it.next();
                tokens.push(CssToken::ColonToken);
            }
            ';' => {
                it.next();
                tokens.push(CssToken::SemicolonToken);
            }
            _ => {
                if is_ident_start_code_point(current_input) {
                    tokens.push(consume_ident_like_token(&mut it));
                } else {
                    it.next();
                    tokens.push(CssToken::DelimToken(current_input));
                }
            }
        }
    }

    Ok(tokens)
}

/// Take the input stream and consume all of the whitespace.
fn consume_whitespaces(it: &mut Peekable<Chars<'_>>) {
    while let Some(&wp) = it.peek() {
        if is_whitespace(wp) {
            it.next();
        } else {
            break;
        }
    }
}

/// https://drafts.csswg.org/css-syntax/#consume-ident-like-token
fn consume_ident_like_token(it: &mut Peekable<Chars<'_>>) -> CssToken {
    let string = consume_ident_sequence(it);

    it.next();

    if matches!(string.to_lowercase().as_str(), "url") {
        if let Some(&current_char) = it.peek() {
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
    } else if let Some(&current_char) = it.peek() {
        if current_char == '(' {
            it.next();
            return CssToken::FunctionToken(string);
        }
    }

    return CssToken::IdentToken(string);
}

/// https://drafts.csswg.org/css-syntax/#consume-a-numeric-token
fn consume_numeric_token(it: &mut Peekable<Chars<'_>>) -> CssToken {
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
        return CssToken::DimensionToken {
            unit,
            sign,
            val_type,
            value,
        };
    } else if next_char_is_x(it, '%') {
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
fn consume_string_token(it: &mut Peekable<Chars<'_>>, ending_char: char) -> CssToken {
    let mut string = String::new();
    while let Some(&curr_input) = it.peek() {
        it.next();
        if ending_char == curr_input {
            it.next();
            break;
        }
        match curr_input {
            '\n' | '\t' | ' ' => {
                it.next_back();
                return CssToken::BadStringToken;
            }
            '\\' => {
                it.next();
                if let Some(&next_char) = it.peek() {
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
fn consume_url_token(it: &mut Peekable<Chars<'_>>) -> CssToken {
    let mut url = String::new();
    consume_whitespaces(it);
    while let Some(&current_char) = it.peek() {
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
fn consume_ident_sequence(it: &mut Peekable<Chars<'_>>) -> String {
    let mut result = String::new();

    while let Some(&current_char) = it.peek() {
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
                    it.next_back();
                    return result;
                }
            }
        }
    }
    result
}

/// https://drafts.csswg.org/css-syntax/#consume-a-number
fn consume_number(it: &mut Peekable<Chars<'_>>) -> CssToken {
    let mut type_num = false; // false integer, true number
    let mut sign = true; // tue +, false -; default true
    let mut number = String::new();

    while let Some(&current_char) = it.peek() {
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
                if let Some(&next_char) = it.peek() {
                    if is_digit(next_char) {
                        number.push(current_char);
                        number.push_str(consume_digit(it).as_str());
                        type_num = true;
                    } else {
                        it.next_back();
                        break;
                    }
                } else {
                    it.next_back();
                    break;
                }
            }
            'e' | 'E' => {
                // ! Erreur possible besoins de vérifier les 2 char mais 1 seul de fais
                if next_char_is(it, |x| matches!(x, '+' | '-' | '0'..='9')) {
                    number.push(current_char.to_ascii_lowercase());
                    number.push_str(consume_digit(it).as_mut_str());
                } else {
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
fn consume_escaped_code_point(it: &mut Peekable<Chars<'_>>) -> char {
    if let Some(&current_char) = it.peek() {
        if is_hex_digit(current_char) {
            let mut hex_value = String::new();
            hex_value.push(current_char);
            it.next();
            let mut count = 0;
            while let Some(&next_char) = it.peek() {
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
fn start_valid_escape(it: &mut Peekable<Chars<'_>>) -> bool {
    if let Some(&first_char) = it.peek() {
        if first_char != '\\' {
            return false;
        }
        it.next();
        if let Some(&second_char) = it.peek() {
            it.next_back(); // reset to is origin place for future
            return second_char != '\u{000A}';
        }
    }

    false
}


/// https://drafts.csswg.org/css-syntax/#check-if-three-code-points-would-start-a-number
fn start_number(it: &mut Peekable<Chars<'_>>) -> bool {
    if let Some(&current_char) = it.peek() {
        match current_char {
            '+' | '-' => {
                it.next();
                if let Some(&next_char) = it.peek() {
                    if next_char == '.' {
                        it.next();
                        if let Some(&third_char) = it.peek() {
                            it.next_back();
                            it.next_back();
                            return is_digit(third_char);
                        }
                        it.next_back();
                    }
                    it.next_back();
                }
                it.next_back();
            }
            '.' => {
                it.next();
                if let Some(&next_char) = it.peek() {
                    if is_digit(current_char) {
                        it.next_back();
                        return is_digit(next_char);
                    }
                    it.next_back();
                }
            }
            _ => return is_digit(current_char),
        }
    }

    false
}

/// https://drafts.csswg.org/css-syntax/#check-if-three-code-points-would-start-an-ident-sequence
fn start_ident_sequence(it: &mut Peekable<Chars<'_>>) -> bool {
    if let Some(&first_code) = it.peek() {
        match first_code {
            '\u{002D}' => {
                it.next();
                if let Some(&second_char) = it.peek() {
                    if is_ident_start_code_point(second_char)
                        || second_char == '\u{002D}'
                        || start_valid_escape(it)
                    {
                        it.next_back();
                        return true;
                    }
                }
                it.next_back();
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
fn consume_remnants_bad_url(it: &mut Peekable<Chars<'_>>) {
    while let Some(&current_char) = it.peek() {
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
fn consume_digit(it: &mut Peekable<Chars<'_>>) -> String {
    let mut result = String::new();

    while let Some(&current_char) = it.peek() {
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
fn next_2_char_is(it: &mut Peekable<Chars<'_>>, first: char, second: char) -> bool {
    if let Some(&first_char) = it.peek() {
        if first_char == first {
            it.next();
            if let Some(&second_char) = it.peek() {
                if second_char == second {
                    it.next_back();
                    return true;
                }
            }
            it.next_back();
        }
    }
    false
}

#[inline]
fn next_char_is(it: &mut Peekable<Chars<'_>>, f: fn(char) -> bool) -> bool {
    it.next();
    if let Some(&next_char) = it.peek() {
        return f(next_char);
    }
    it.next_back();
    false
}

/// Check if the next char is x
#[inline]
fn next_char_is_x(it: &mut Peekable<Chars<'_>>, x: char) -> bool {
    it.next();
    if let Some(&next_char) = it.peek() {
        return next_char == x;
    }
    it.next_back();
    false
}

/// Check if a char is string gard ' or ".
#[inline]
fn next_char_is_quote(it: &mut Peekable<Chars<'_>>) -> bool {
    next_char_in(it, &['"', '\''])
}

/// Check if the next char is in the given array.
#[inline]
fn next_char_in(it: &mut Peekable<Chars<'_>>, x: &[char]) -> bool {
    it.next();
    if let Some(next_char) = it.peek() {
        return x.contains(next_char);
    }
    it.next_back();
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
    use crate::{utils, tokeniser::{preprocessing, consume_digit, is_digit}};

    #[test]
    fn test_preprocessing() {
        utils::init_test_logger();

        assert_eq!("Hello\nWorld", preprocessing("Hello\x0CWorld".to_string()), "Preprocessing for form feed");
        assert_eq!("Hello\nWorld", preprocessing("Hello\rWorld".to_string()), "Preprocessing for Carriage return");
        assert_eq!("Hello\nWorld", preprocessing("Hello\r\nWorld".to_string()), "Preprocessing for Carriage return + End of line");
        assert_eq!("Hello\n\nWorld", preprocessing("Hello\r\n\nWorld".to_string()));
    }

    #[test]
    fn test_utils_digit() {

        let nb_54 = String::from("54");
        let mut it_54 = nb_54.chars().peekable();
        assert_eq!("54", consume_digit(&mut it_54), "Consuming only 2 digit");
        
        let nb_12 = String::from("12a2");
        let mut it_mul = nb_12.chars().peekable();
        assert_eq!("12", consume_digit(&mut it_mul), "Consume 2 digit and stop");
    }
}