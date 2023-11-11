use log::{debug, error, trace, warn};
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;

use crate::css::{CSSCombinator, CSSword, CssSelecteurType, CSS};

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
                let _selecteurs: Option<_> = parse_selectors(iter.next().unwrap());
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

/// Parse les sélecteurs.
/// TODO: optimiser avec de la curryfication
fn parse_selectors(selecteurs: Pair<'_, Rule>) -> Option<CssSelecteurType> {
    debug!("{}", selecteurs.as_str());
    debug!("{}", selecteurs);

    let mut selecteur_list: Vec<CSSCombinator> = Vec::new();
    let mut curr_selec: CSSCombinator = CSSCombinator::None;
    let mut combinator: Option<Rule> = None;

    for selecteur in selecteurs.into_inner() {
        let tok = selecteur.as_rule();
        debug!("{:?}", tok);
        match tok {
            Rule::balise => {
                let name = selecteur.as_str().to_string();

                if matches!(curr_selec, CSSCombinator::None) {
                    curr_selec = CSSCombinator::Unit(CSSword::from_balise(name));
                } else {
                    if let CSSCombinator::Unit(ref mut selec) = curr_selec {
                        selec.tag = Some(name);
                    } else {
                        warn!("le selecteur en cours de construction est inexistant");
                    };
                }
            }
            Rule::id => {
                // id est de format #word et produit en token class("#class", [word("class", [])])
                // on a donc juste besoin d'accéder au second token.
                let name = extract_1st_token_as_string(selecteur);

                if matches!(curr_selec, CSSCombinator::None) {
                    curr_selec = CSSCombinator::Unit(CSSword::from_id(name));
                } else {
                    if let CSSCombinator::Unit(ref mut selec) = curr_selec {
                        selec.id = Some(name)
                    } else {
                        warn!("le selecteur en cours de construction est inexistant");
                    }
                }
            }
            Rule::class => {
                // class est de format .word et produit en token class(".class", [word("class", [])])
                // on a donc juste besoin d'accéder au second token.
                let name = extract_1st_token_as_string(selecteur);

                if matches!(curr_selec, CSSCombinator::None) {
                    curr_selec = CSSCombinator::Unit(CSSword::from_class(name));
                } else {
                    if let CSSCombinator::Unit(ref mut selec) = curr_selec {
                        selec.class.push(name);
                    } else {
                        warn!("le selecteur en cours de construction est inexistant");
                    }
                }
            }
            Rule::ps_class => {
                let name = extract_1st_token_as_string(selecteur);

                if matches!(curr_selec, CSSCombinator::None) {
                    warn!("utilisation d'une pseudo class sans selecteur précédent");
                } else {
                    if let CSSCombinator::Unit(ref mut selec) = curr_selec {
                        selec.psd_class.push(name);
                    } else {
                        warn!("le selecteur en cours de construction est inexistant");
                    }
                }
            }
            Rule::ps_elmnt => {
                let name = extract_1st_token_as_string(selecteur);

                if matches!(curr_selec, CSSCombinator::None) {
                    warn!("utilisation d'une pseudo élément sans selecteur précédent");
                } else {
                    if let CSSCombinator::Unit(ref mut selec) = curr_selec {
                        selec.psd_elt.push(name);
                    } else {
                        warn!("le selecteur en cours de construction est inexistant");
                    }
                }
            }
            Rule::selecteur_combinateur => {
                // on réécris dessus sans check les combinateurs ont la prio sur les espaces qui sont peut-être juste du formattage
                combinator = Some(selecteur.into_inner().next().unwrap().as_rule());
                selecteur_list.push(curr_selec);
                curr_selec = CSSCombinator::None;
            }
            Rule::wp => {
                if combinator.is_none() {
                    combinator = Some(Rule::wp);
                    selecteur_list.push(curr_selec);
                    curr_selec = CSSCombinator::None;
                } // sinon on l'ignore
            }
            _ => warn!("Token {} inconnu pour un selecteur", selecteur.as_str()),
        }
        if combinator.is_some()
            && !matches!(curr_selec, CSSCombinator::None)
            && !(matches!(tok, Rule::selecteur_combinateur) && matches!(tok, Rule::wp))
        {
            // combinator est check précédemment curr_selec = CSSCombinator::None;
            match combinator.unwrap() {
                Rule::wp => {
                    let old = selecteur_list.pop();
                    if old.is_some() {
                        let tmp =
                            CSSCombinator::Child((Box::new(old.unwrap()), Box::new(curr_selec)));
                        selecteur_list.push(tmp);
                    }
                }
                Rule::sup => {
                    let old = selecteur_list.pop();
                    if old.is_some() {
                        let tmp = CSSCombinator::DirectChild((
                            Box::new(old.unwrap()),
                            Box::new(curr_selec),
                        ));
                        selecteur_list.push(tmp);
                    }
                }
                Rule::direct_neightbour => {
                    let old = selecteur_list.pop();
                    if old.is_some() {
                        let tmp = CSSCombinator::DirectNeightbour((
                            Box::new(old.unwrap()),
                            Box::new(curr_selec),
                        ));
                        selecteur_list.push(tmp);
                    }
                }
                Rule::neightbour => {
                    let old = selecteur_list.pop();
                    if old.is_some() {
                        let tmp = CSSCombinator::Neightbour((
                            Box::new(old.unwrap()),
                            Box::new(curr_selec),
                        ));
                        selecteur_list.push(tmp);
                    }
                }
                Rule::list => (), // liste on fais rien le selecteur a déjà été poussé
                _ => warn!("combinateur {:?} inconnu", Some(combinator)),
            }
            curr_selec = CSSCombinator::None;
            combinator = None
        }
    }

    if !matches!(curr_selec, CSSCombinator::None) {
        selecteur_list.push(curr_selec);
    }

    debug!("{:#?}", selecteur_list);

    Some(CssSelecteurType::Selecteur(selecteur_list))
}

/// Tente de parser une variable css prend une liste sortie d'un token variable (variable [var_name, var_val]) et en resort un couple
fn parse_variable(var_token: Pairs<'_, Rule>) -> Result<(&str, &str), &str> {
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
