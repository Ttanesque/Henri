use log::{debug, error, trace, warn};
use pest::{iterators::Pairs, Parser};
use pest_derive::Parser;

use crate::css::CSS;

#[derive(Parser)]
#[grammar = "css.pest"]
pub struct CSSParser;

pub fn parse(input: &str) -> Result<CSS, String> {
    debug!("Initialisation de la structure CSS");
    let mut css_res = CSS::new();
    let file;

    debug!("Début de l'analyse syntaxique");
    match CSSParser::parse(Rule::file, input) {
        Ok(mut p_ress) => {
            trace!("{:#?}", p_ress);
            file = p_ress.next().unwrap(); // si le parsing est passé alors file est présent et à
                                           // des enfants
        }
        Err(err) => {
            error!("{}", err);
            return Err(err.to_string());
        }
    }

    for line in file.into_inner() {
        match line.as_rule() {
            Rule::charset => {
                let charset_value = line.into_inner().next().unwrap().into_inner().as_str();
                css_res.charset = charset_value.to_string();
                debug!("charset : {}", css_res.charset);
            }
            Rule::variable => {
                if let Some((name, vale)) = parse_variable(line.clone().into_inner()) {
                    css_res.variable.insert(name.to_string(), vale.to_string());
                    debug!("variable : {} = {}", name, vale);
                } else {
                    warn!("la lecture de la variable a échoué {}", line);
                }
            }
            Rule::EOI => (),
            _ => {
                warn!("paire non implémenter {}", line);
            }
        }
    }

    Ok(css_res)
}

fn parse_variable(var_token: Pairs<'_, Rule>) -> Option<(&str, &str)> {
    let mut name = None;
    let mut val = None;
    for token in var_token {
        match token.as_rule() {
            Rule::var_name => name = Some(token.as_str()),
            Rule::var_val => val = Some(token.as_str()),
            _ => warn!("token inattendu {}", token),
        }
    }

    if name.is_none() || val.is_none() {
        return None;
    }

    Some((name?, val?))
}
