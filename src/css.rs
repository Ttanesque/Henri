use std::{collections::HashMap, fmt::Display};

pub type Combinator = (Box<CSSCombinator>, Box<CSSCombinator>);
pub type StrPair = (String, String);

#[derive(Debug)]
pub enum CSSCombinator {
    None,
    Unit(CSSword),
    DirectNeightbour(Combinator),
    Neightbour(Combinator),
    DirectChild(Combinator),
    Child(Combinator),
    List(Vec<CSSCombinator>),
}

#[derive(Debug)]
pub struct CSSword {
    pub tag: Option<String>,
    pub class: Vec<String>,
    pub id: Option<String>,
    pub attr: Option<String>,
    pub psd_class: Vec<String>,
    pub psd_elt: Vec<String>,
}

#[derive(Debug)]
pub enum CssSelecteurType {
    MediaQuery,
    Selecteur(Vec<CSSCombinator>),
}

#[derive(Debug)]
pub struct CssBlock {
    pub selecteur: CssSelecteurType,
    pub rules: Vec<StrPair>,
}

#[derive(Debug)]
pub struct CSS {
    pub mono_rules: HashMap<String, String>,
    pub variable: HashMap<String, String>,
    pub bloc: Vec<CssBlock>,
}

impl CSS {
    pub fn new() -> CSS {
        CSS {
            mono_rules: HashMap::new(),
            variable: HashMap::new(),
            bloc: Vec::new(),
        }
    }
}

impl CSSword {
    pub fn new() -> CSSword {
        CSSword {
            tag: None,
            class: Vec::new(),
            id: None,
            attr: None,
            psd_class: Vec::new(),
            psd_elt: Vec::new(),
        }
    }

    pub fn from_balise(tag_name: String) -> CSSword {
        CSSword {
            tag: Some(tag_name),
            class: Vec::new(),
            id: None,
            attr: None,
            psd_elt: Vec::new(),
            psd_class: Vec::new(),
        }
    }

    pub fn from_class(class_name: String) -> CSSword {
        CSSword {
            tag: None,
            class: vec![class_name],
            id: None,
            attr: None,
            psd_class: Vec::new(),
            psd_elt: Vec::new(),
        }
    }

    pub fn from_id(id_name: String) -> CSSword {
        CSSword {
            tag: None,
            class: Vec::new(),
            id: Some(id_name),
            attr: None,
            psd_class: Vec::new(),
            psd_elt: Vec::new(),
        }
    }
}

impl Display for CSSword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();

        // ajout du tag pas de préfix
        let tag = self.tag.clone().unwrap_or("".to_string());
        result.push_str(tag.as_str());
        result.push(' ');

        // id à un préfix on dois check
        let id = self.id.clone().unwrap_or("".to_string());
        if id != "" {
            result.push_str(format!("#{} ", id).as_str());
        }

        // pareil pour les attr
        let attr = self.attr.clone().unwrap_or("".to_string());
        if attr != "" {
            result.push_str(format!("[{}] ", attr).as_str());
        }

        // ajout de listes
        let class = self.class.join(".");
        if class != "" {
            result.push_str(format!(".{} ", class).as_str());
        }

        let psd_class = self.psd_class.join(":");
        if psd_class != "" {
            result.push_str(format!(":{} ", psd_class).as_str());
        }

        let psd_elt = self.psd_elt.join("::");
        if psd_elt != "" {
            result.push_str(format!("::{} ", psd_elt).as_str());
        }

        // nettoie les espaces
        let words: Vec<_> = result.split_whitespace().collect();

        write!(f, "{}", words.join(" "))
    }
}

impl Display for CSSCombinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CSSCombinator::Unit(selec) => write!(f, "{}", selec),
            CSSCombinator::DirectNeightbour((left, right)) => write!(f, "{} + {}", left, right),
            CSSCombinator::Neightbour((left, right)) => write!(f, "{} ~ {}", left, right),
            CSSCombinator::DirectChild((left, right)) => write!(f, "{} > {}", left, right),
            CSSCombinator::Child((left, right)) => write!(f, "{} {}", left, right),
            CSSCombinator::List(list) => {
                let mut formatted_list = String::new();
                for i in list {
                    formatted_list.push_str(format!("{},", i).as_str());
                }

                write!(f, "{}", formatted_list)
            }
            CSSCombinator::None => write!(f, ""),
        }
    }
}
