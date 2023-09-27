use std::collections::HashMap;

#[derive(Debug)]
pub enum CssBlock {
    MediaQuery,
    Selecteur,
}

#[derive(Debug)]
pub enum MediaQuery {
    AnyHover,
    anyPointer,
    aspect_ratio,
    color,
    color_gamut,
    color_index,
    device_aspect_ratio,
    device_height,
    device_width,
    display_mode,
    dynamic_range,
    forced_colors,
    grid,
    height,
    hover,
    inverted_colors,
    monochrome,
    orientation,
    overflow_block,
    overflow_inline,
    pointer,
    prefers_color_scheme,
    prefers_contrast,
    prefers_reduced_motion,
    resolution,
    scripting,
    update_frequency,
    video_dynamic_range,
    width,
}

#[derive(Debug)]
pub struct CSS {
    pub charset: String,
    pub variable: HashMap<String, String>,
    pub bloc: Vec<CssBlock>,
}

impl CSS {
    pub fn new() -> CSS {
        CSS {
            charset: "utf-8".to_string(),
            variable: HashMap::new(),
            bloc: Vec::new(),
        }
    }
}
