use log::{debug, error, trace, warn};

// Types
#[derive(Debug, Clone)]
enum GrammarCSS {
    Parent,
    MonoRules,
    Variables,
    Bloc,
    Selecteur,
    DirectNeightbour,
    Neightbour,
    DirectChild,
    Child,
    List,
    Tag,
    Class,
    Id,
    Attr,
    PseudoClass,
    PseudoElement,
}

#[derive(Debug, Clone)]
struct ParseCssNode {
    children: Vec<ParseCssNode>,
    entry: GrammarCSS,
}

impl ParseCssNode {
    pub fn new() -> ParseCssNode {
        ParseCssNode {
            children: Vec::new(),
            entry: GrammarCSS::Parent,
        }
    }
}

#[derive(Debug, Clone)]
enum LexCssItem {
    WhiteSpace(char), // \n \r \t " "
    Operator(char),   // . # : :: @ > = < - / *
    End(char),        // ;
    Parent(char),     // ( ) [ ] { }
    Word(String),
    Number(u64),
    Comment(String), // /* ... */
}

fn lex(input: String) -> Result<Vec<LexCssItem>, String> {
    let mut result = Vec::new();
    let mut it = input.chars().peekable();

    while let Some(&c) = it.peek() {
        match c {
            '/' => {
            
            }
            '\n' | '\r' | '\t' | ' ' => {
                result.push(LexCssItem::WhiteSpace(c));
                it.next();
            }
            '.' | '#' | ':' | '@' | '>' | '=' | '<' | '-' => {
                result.push(LexCssItem::Operator(c));
                it.next();
            }
            _ => {
                return Err(format!("Caractère inconnue {}", c));
            }
        }
    }

    Ok(result)
}
