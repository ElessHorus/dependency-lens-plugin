//! Dependency Lens: an OpenIDEA plugin.

pub mod model;
pub mod text;

use openidea_plugin::{Error, Invocation, NotificationLevel, Plugin, host, register_plugin};

#[derive(Default)]
pub struct Main {
    greetings: u32,
}

impl Plugin for Main {
    fn run_command(
        &mut self,
        id: &str,
        ctx: &Invocation,
        _arg: Option<&str>,
    ) -> Result<Option<String>, Error> {
        match id {
            "say-hello" => {
                // Instance state lasts until the plugin is idle for a while;
                // keep what must survive in `host::storage`.
                self.greetings += 1;
                let body = format!("Hello #{} from Dependency Lens!", self.greetings);
                host::notify(NotificationLevel::Info, "Dependency Lens", &body);
                Ok(None)
            }
            "line-count" => {
                let editor = ctx.editor().ok_or("no file is open")?;
                let text = editor.document()?.text;
                Ok(Some(format!(
                    "{} lines in {}",
                    text.lines().count(),
                    editor.path()
                )))
            }
            _ => Err(format!("unknown command {id}").into()),
        }
    }
}

register_plugin!(Main);

#[cfg(test)]
mod tests {
    use super::*;
    use openidea_plugin::mock::MockHost;

    #[test]
    fn says_hello() {
        let host = MockHost::install();
        let mut plugin = Main::default();
        plugin
            .run_command("say-hello", &host.invocation(), None)
            .unwrap();
        plugin
            .run_command("say-hello", &host.invocation(), None)
            .unwrap();
        assert_eq!(
            host.notifications()[1].body,
            "Hello #2 from Dependency Lens!"
        );
    }

    // Proves that the parser crates compile and run on wasm32-wasip2.
    #[test]
    fn wasm_smoke() {
        assert!(taplo::parser::parse("a = 1").errors.is_empty());
        assert!(quick_xml::Reader::from_str("<a/>").read_event().is_ok());
        assert!(semver::Version::parse("1.2.3").is_ok());
    }

    #[test]
    fn counts_lines() {
        let host = MockHost::install();
        host.open_editor("/project/src/main.rs", "rust", "fn main() {\n}\n", &[]);
        let out = Main::default()
            .run_command("line-count", &host.invocation(), None)
            .unwrap();
        assert_eq!(out.as_deref(), Some("2 lines in /project/src/main.rs"));
    }
}
