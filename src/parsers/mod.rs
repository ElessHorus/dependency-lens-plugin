//! One parser per manifest ecosystem. Each submodule exposes `parse(text) -> Vec<Dependency>`.

pub mod cargo;
pub mod csharp;
pub mod dart;
pub mod go;
pub mod json_spans;
pub mod maven;
pub mod npm;
pub mod php;
pub mod python;
pub mod ruby;
pub mod spans;
mod xml_text;
