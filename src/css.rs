use std::collections::HashMap;

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
