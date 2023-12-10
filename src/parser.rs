use log::{debug, error, trace, warn};
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;

use crate::css::{CSSCombinator, CSSword, CSS};

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
            Rule::mono_rule => {
                // un mono rule est de la forme monorule[mono_start[nom var], mono_value[value]]
                // on peut donc faire 2 unwrap + inner d'affiler
                let mut iter = line.into_inner();
                let mono_key = iter.next().unwrap().into_inner().as_str();
                let mono_value = iter.next().unwrap().into_inner().next().unwrap().as_str();
                css_res
                    .mono_rules
                    .insert(mono_key.to_string(), mono_value.to_string());
                debug!("mono_rule trouvé : {} {}", mono_key, mono_value);
            }
            Rule::variable => {
                if let Ok((name, vale)) = parse_variable(line.clone().into_inner()) {
                    css_res.variable.insert(name.to_string(), vale.to_string());
                    debug!("variable : {} = {}", name, vale);
                } else {
                    warn!("la lecture de la variable a échoué {}", line);
                }
            }
            Rule::rule => {
                // une rule est composé de un selecteur et un block donc pas de problème pour
                // unwrap.
                let mut iter = line.into_inner();
                let _selec = parse_selecteur(iter.next().unwrap().into_inner());
                debug!("version parser : {}", _selec);
                let _block = iter.next().unwrap();
            }
            Rule::EOI => (),
            _ => {
                warn!("paire non implémenter {}", line);
            }
        }
    }

    Ok(css_res)
}

fn parse_selecteur(selecteur_token: Pairs<'_, Rule>) -> CSSCombinator {
    
    let mut parse_selec: CSSCombinator = CSSCombinator::None;

    debug!("selecteur a parser {}", selecteur_token);

    for token in selecteur_token {
        debug!("{}", token);
        match token.as_rule() {
            Rule::selecteur_combinator => {
                if matches!(parse_selec, CSSCombinator::None) {
                    warn!("Un opérateur de combinaison est présent mais il n'existe pas de sélecteur précédent {}", token.as_str());
                } else {
                    let mut iter_tok = token.into_inner();
                    // un combinator est de la forme : selecteur_combinator, [selecteur_op(operateur), selecteur...]
                    // on peut donc unwrap le premier et passer le reste à parser.
                    
                    let op = iter_tok.next().unwrap().into_inner().next().unwrap().as_rule();
                    let left_selec = parse_selecteur(iter_tok);

                    if matches!(left_selec, CSSCombinator::None) {
                        warn!("la seconde partie du combinator n'est pas présent");
                    } else {
                        parse_selec = combinator_builder(op, parse_selec, left_selec);
                    }
                }
            }
            Rule::selecteur_atomic => {
                parse_selec = CSSCombinator::Unit(parse_selector_atomique(token.into_inner()));
            }
            _ => {
                warn!("token {:#?} inconnu pour un selecteur", token.as_rule());
                break;
            }
        }
        debug!("result {}", parse_selec);
    }

    parse_selec
}


/// A partir de 2 Sélecteur et d'un opétateur renvoie le sélecteur correspondant
fn combinator_builder(op_token: Rule, right: CSSCombinator, left: CSSCombinator) -> CSSCombinator {
    match op_token {
        Rule::list => CSSCombinator::List(vec![right, left]),
        Rule::wp => CSSCombinator::Child((Box::new(right), Box::new(left))),
        Rule::sup => CSSCombinator::DirectChild((Box::new(right), Box::new(left))),
        Rule::neightbour => CSSCombinator::Neightbour((Box::new(right), Box::new(left))),
        Rule::direct_neightbour => CSSCombinator::DirectNeightbour((Box::new(right), Box::new(left))),
        _ => {
            warn!("Combinator Builder Token inattendue {:#?}", op_token);
            // la première partie est non vide
            if !matches!(right, CSSCombinator::None) {
                return right;
            }
            return CSSCombinator::None;
        }
    }
}

/// Parse les sélecteurs atomique càd les sélecteurs qui ne sont pas > + ~ , \whitespace
fn parse_selector_atomique(selecteur_token: Pairs<'_, Rule>) -> CSSword {
    let mut selecteur: CSSword = CSSword::new();
    for selec in selecteur_token {
        match selec.as_rule() {
            Rule::balise => selecteur.tag = Some(selec.as_str().to_string()),
            Rule::id => selecteur.id = Some(extract_1st_token_as_string(selec)),
            Rule::class => selecteur.class.push(extract_1st_token_as_string(selec)),
            Rule::ps_class => selecteur.psd_class.push(extract_1st_token_as_string(selec)),
            Rule::ps_elmnt => selecteur.psd_elt.push(extract_1st_token_as_string(selec)),
            _ => warn!(
                "Token {:#?} inconnu pour un selecteur atomic",
                selec.as_rule()
            ),
        }
    }

    selecteur
}

/// Tente de parser une variable css prend une liste sortie d'un token variable
/// (variable [(var_name, [name, separator]), var_val]) et en resort un couple : nom, valeur.
fn parse_variable(var_token: Pairs<'_, Rule>) -> Result<(String, String), &str> {
    let mut name = None;
    let mut val = None;
    for token in var_token {
        match token.as_rule() {
            Rule::var_name => name = Some(extract_1st_token_as_string(token)),
            Rule::var_val => val = Some(token.as_str().to_string()),
            _ => warn!("token inattendu {}", token),
        }
    }

    if name.is_none() || val.is_none() {
        return Err("Les 2 valeurs requises sont inconnues.");
    }

    // déja vérifier si l'un des 2 est none
    Ok((name.unwrap(), val.unwrap()))
}

/// Extrait le premier token interne et le renvoie en String. Considère que le token est toujours
/// présent sinon panic (les token sont censé être maîtriser).
fn extract_1st_token_as_string(token: Pair<'_, Rule>) -> String {
    token.into_inner().next().unwrap().as_str().to_string()
}

#[cfg(test)]
mod tests {
    use pest::Parser;

    use crate::parser::parse_variable;

    use super::{CSSParser, Rule};

    #[test]
    fn variable() {
        if let Ok(mut token) = CSSParser::parse(Rule::variable, "--ok: zz;") {
            assert_eq!(
                parse_variable(token.next().unwrap().into_inner()),
                Ok(("ok".to_string(), "zz".to_string()))
            );
        } else {
            assert_eq!(false, true, "problème de parsing dans le text");
        }
    }
}
