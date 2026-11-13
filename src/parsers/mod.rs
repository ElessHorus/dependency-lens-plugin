//! One parser per manifest ecosystem. Each submodule exposes `parse(text) -> Vec<Dependency>`.

pub mod cargo;
pub mod python;
