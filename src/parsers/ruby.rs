//! Parser for RubyGems manifests (`Gemfile`).
//!
//! The reader does not evaluate Ruby. It scans each line once into tokens, so a
//! declaration that spans lines is read only up to its first line.

use crate::model::{Dependency, Span};

/// Operators that may start a requirement. The empty string means no operator.
const OPERATORS: [&str; 8] = ["", "=", "!=", ">", "<", ">=", "<=", "~>"];

/// Operators whose version pins a gem. `!=`, `<` and `<=` never pin.
const PIN_OPERATORS: [&str; 5] = ["", "=", "~>", ">=", ">"];

/// Option keys, and block methods, whose value names a source other than the registry.
const SOURCE_OPTION_KEYS: [&str; 7] = [
    "git",
    "github",
    "gitlab",
    "bitbucket",
    "gist",
    "path",
    "source",
];

/// Option keys whose value lists the groups of a gem.
const GROUP_OPTION_KEYS: [&str; 2] = ["group", "groups"];

/// Group names whose gems are development dependencies.
const DEVELOPMENT_GROUPS: [&str; 2] = ["development", "test"];

/// The kind of one token of a Gemfile line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind<'a> {
    /// An identifier or keyword such as `gem`, `do` or `git`.
    Word(&'a str),
    /// A symbol such as `:test`, without its colon.
    Symbol(&'a str),
    /// The text inside a `'...'` or `"..."` string.
    Str(&'a str),
    /// Any other byte, such as `,`, `(`, `:` or `|`.
    Punct(u8),
}

/// One token with its byte range inside the line. A string range includes its quotes.
#[derive(Clone, Copy)]
struct Token<'a> {
    kind: Kind<'a>,
    start: usize,
    end: usize,
}

/// The version of the first pin constraint of a gem.
struct Pin<'a> {
    version: &'a str,
    /// Byte offset of `version` inside the line.
    start: usize,
}

/// A requirement string such as `~> 7.0.4`.
struct Requirement<'a> {
    operator: &'a str,
    /// Version text, without the operator and without the spaces before it.
    version: &'a str,
    /// Byte offset of `version` inside the requirement string.
    version_offset: usize,
}

/// The scope that one open `do` block gives to the gems inside it.
#[derive(Clone, Copy)]
struct OpenBlock {
    /// The block is a development or test group.
    is_development: bool,
    /// The block is a `path`, `git` or `source` block. Its gems do not come from the registry.
    has_custom_source: bool,
}

/// Parses the gems of a `Gemfile`.
///
/// Returns the gems with a pin constraint, in document order. A gem inside a
/// development or test group, or with a development group option, has `dev`.
/// A gem inside a `path`, `git` or `source` block is skipped, like a gem with a source option.
pub fn parse(text: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    // One token buffer serves every line, so no line allocates on its own.
    let mut tokens = Vec::new();
    let mut open_blocks: Vec<OpenBlock> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let Ok(line_number) = u32::try_from(index) else {
            break;
        };
        tokenize(line, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        if is_gem_line(&tokens) {
            // A gem line never opens a block, so the stack is read but not changed.
            // A source block applies to every gem inside it, however deeply nested.
            if !open_blocks.iter().any(|block| block.has_custom_source) {
                let in_dev_block = open_blocks.iter().any(|block| block.is_development);
                dependencies.extend(parse_gem(&tokens, line_number, in_dev_block));
            }
        } else if is_lone_end(&tokens) {
            // An `end` with no open block is ignored.
            open_blocks.pop();
        } else if opens_block(&tokens) {
            open_blocks.push(OpenBlock {
                is_development: opens_development_group(&tokens),
                has_custom_source: opens_custom_source(&tokens),
            });
        }
    }
    dependencies
}

/// Splits one line into tokens, stopping at the first `#` outside a string.
///
/// Clears `tokens` first. An unterminated string ends the line.
fn tokenize<'a>(line: &'a str, tokens: &mut Vec<Token<'a>>) {
    tokens.clear();
    let bytes = line.as_bytes();
    let mut cursor = 0;
    while let Some(&byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if byte == b'#' {
            break;
        }
        let start = cursor;
        let (kind, end) = if matches!(byte, b'\'' | b'"') {
            let Some(closing) = closing_quote(bytes, cursor, byte) else {
                break;
            };
            (Kind::Str(&line[cursor + 1..closing]), closing + 1)
        } else if is_word_byte(byte) {
            let end = scan_while(bytes, cursor, is_word_byte);
            (Kind::Word(&line[cursor..end]), end)
        } else if byte == b':' && starts_symbol(bytes, cursor) {
            let end = scan_while(bytes, cursor + 1, is_word_byte);
            (Kind::Symbol(&line[cursor + 1..end]), end)
        } else {
            (Kind::Punct(byte), cursor + 1)
        };
        tokens.push(Token { kind, start, end });
        cursor = end;
    }
}

/// Returns the index of the quote that closes the string opened at `opening`.
///
/// A backslash skips the next byte, so an escaped quote does not close the string.
fn closing_quote(bytes: &[u8], opening: usize, quote: u8) -> Option<usize> {
    let mut cursor = opening + 1;
    while let Some(&byte) = bytes.get(cursor) {
        if byte == b'\\' {
            cursor += 2;
        } else if byte == quote {
            return Some(cursor);
        } else {
            cursor += 1;
        }
    }
    None
}

/// Returns `true` when the colon at `cursor` starts a symbol.
///
/// A colon right after a word is a label separator, as in `group:test`.
fn starts_symbol(bytes: &[u8], cursor: usize) -> bool {
    let follows_word = cursor > 0
        && bytes
            .get(cursor - 1)
            .is_some_and(|&previous| is_word_byte(previous));
    !follows_word
        && bytes
            .get(cursor + 1)
            .is_some_and(|&next| is_word_byte(next))
}

/// Returns the index of the first byte from `from` that fails `keep`, or the length of `bytes`.
fn scan_while(bytes: &[u8], from: usize, keep: impl Fn(u8) -> bool) -> usize {
    bytes.get(from..).map_or(from, |rest| {
        from + rest.iter().take_while(|&&byte| keep(byte)).count()
    })
}

/// Returns `true` for bytes that may appear in an identifier, a keyword or a symbol.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Returns `true` when the line starts with the keyword `gem`.
fn is_gem_line(tokens: &[Token<'_>]) -> bool {
    matches!(
        tokens.first(),
        Some(Token {
            kind: Kind::Word("gem"),
            ..
        })
    )
}

/// Returns `true` when the line is only `end`.
fn is_lone_end(tokens: &[Token<'_>]) -> bool {
    matches!(
        tokens,
        [Token {
            kind: Kind::Word("end"),
            ..
        }]
    )
}

/// Returns `true` when the line ends with `do` or `do |...|`.
fn opens_block(tokens: &[Token<'_>]) -> bool {
    // The `do` of `do |params|` sits before the opening pipe of the parameters.
    let keyword_end = match tokens.last() {
        Some(last) if is_punct(last, b'|') => {
            let body = &tokens[..tokens.len() - 1];
            match body.iter().rposition(|token| is_punct(token, b'|')) {
                Some(opening_pipe) => opening_pipe,
                None => return false,
            }
        }
        _ => tokens.len(),
    };
    keyword_end
        .checked_sub(1)
        .and_then(|keyword_index| tokens.get(keyword_index))
        .is_some_and(|token| token.kind == Kind::Word("do"))
}

/// Returns `true` when the block starts with a source method such as `path` or `git`.
fn opens_custom_source(tokens: &[Token<'_>]) -> bool {
    matches!(
        tokens.first(),
        Some(Token { kind: Kind::Word(method), .. }) if SOURCE_OPTION_KEYS.contains(method)
    )
}

/// Returns `true` for a `group` block whose list names a development or test group.
fn opens_development_group(tokens: &[Token<'_>]) -> bool {
    matches!(
        tokens.first(),
        Some(Token {
            kind: Kind::Word("group"),
            ..
        })
    ) && tokens
        .iter()
        .any(|token| token_text(token).is_some_and(|name| DEVELOPMENT_GROUPS.contains(&name)))
}

/// Reads one `gem` declaration. Returns `None` when the gem is skipped.
///
/// `in_dev_block` tells whether an open block is a development group.
fn parse_gem(tokens: &[Token<'_>], line_number: u32, in_dev_block: bool) -> Option<Dependency> {
    let mut cursor = 1;
    if punct_at(tokens, cursor, b'(') {
        cursor += 1;
    }
    let name_token = tokens.get(cursor)?;
    let Kind::Str(name) = name_token.kind else {
        return None;
    };
    if name.is_empty() {
        return None;
    }
    let name_span = span(
        line_number,
        name_token.start + 1,
        name_token.end.saturating_sub(1),
    )?;

    // Each constraint is a `,` followed by a quoted requirement. The first token
    // that breaks this pattern ends the list. It starts the options.
    let mut requirement_count = 0;
    let mut pin = None;
    let mut index = cursor + 1;
    while punct_at(tokens, index, b',') {
        let Some(requirement_token) = tokens.get(index + 1) else {
            break;
        };
        let Kind::Str(content) = requirement_token.kind else {
            break;
        };
        let Some(requirement) = parse_requirement(content) else {
            break;
        };
        requirement_count += 1;
        if pin.is_none() && PIN_OPERATORS.contains(&requirement.operator) {
            pin = Some(Pin {
                version: requirement.version,
                start: requirement_token.start + 1 + requirement.version_offset,
            });
        }
        index += 2;
    }

    let mut is_group_dev = false;
    for option_index in index..tokens.len() {
        let Some(key) = option_key(tokens, option_index) else {
            continue;
        };
        if SOURCE_OPTION_KEYS.contains(&key) {
            return None;
        }
        if GROUP_OPTION_KEYS.contains(&key) {
            is_group_dev |= lists_development_group(tokens, option_index + 1);
        }
    }

    let pin = pin?;
    Some(Dependency {
        name: name.to_owned(),
        version: pin.version.to_owned(),
        name_span,
        version_span: span(line_number, pin.start, pin.start + pin.version.len())?,
        dev: in_dev_block || is_group_dev,
        optional: false,
        has_additional_version_constraints: requirement_count > 1,
    })
}

/// Parses a requirement string such as `>= 1.0` or `~>1.0`.
///
/// Returns `None` for interpolation, for an unknown operator, and for a version
/// that does not start with a digit or holds more than one word.
fn parse_requirement(content: &str) -> Option<Requirement<'_>> {
    if content.contains("#{") {
        return None;
    }
    let operator_len = content
        .bytes()
        .take_while(|&byte| matches!(byte, b'=' | b'!' | b'<' | b'>' | b'~'))
        .count();
    let operator = content.get(..operator_len)?;
    if !OPERATORS.contains(&operator) {
        return None;
    }
    let version_and_rest = content.get(operator_len..)?.trim_start();
    let version = version_and_rest.trim_end();
    if version.contains(char::is_whitespace)
        || !version.starts_with(|character: char| character.is_ascii_digit())
    {
        return None;
    }
    Some(Requirement {
        operator,
        version,
        version_offset: content.len() - version_and_rest.len(),
    })
}

/// Returns the key of an option at `index`, for `key: value` and `:key => value`.
fn option_key<'a>(tokens: &[Token<'a>], index: usize) -> Option<&'a str> {
    let token = tokens.get(index)?;
    match token.kind {
        Kind::Word(key) if punct_at(tokens, index + 1, b':') => Some(key),
        Kind::Symbol(key)
            if punct_at(tokens, index + 1, b'=') && punct_at(tokens, index + 2, b'>') =>
        {
            Some(key)
        }
        _ => None,
    }
}

/// Returns `true` when the values of a group option, from `value_start`, name a development group.
///
/// The values end at the next option key, so `groups: [...], platforms: ...` stops at `platforms`.
fn lists_development_group(tokens: &[Token<'_>], value_start: usize) -> bool {
    (value_start..tokens.len())
        .take_while(|&index| option_key(tokens, index).is_none())
        .filter_map(|index| tokens.get(index))
        .any(|token| token_text(token).is_some_and(|name| DEVELOPMENT_GROUPS.contains(&name)))
}

/// Returns the text of a word, symbol or string token.
fn token_text<'a>(token: &Token<'a>) -> Option<&'a str> {
    match token.kind {
        Kind::Word(text) | Kind::Symbol(text) | Kind::Str(text) => Some(text),
        Kind::Punct(_) => None,
    }
}

/// Returns `true` when the token at `index` is the punctuation `byte`.
fn punct_at(tokens: &[Token<'_>], index: usize, byte: u8) -> bool {
    tokens.get(index).is_some_and(|token| is_punct(token, byte))
}

/// Returns `true` when `token` is the punctuation `byte`.
fn is_punct(token: &Token<'_>, byte: u8) -> bool {
    token.kind == Kind::Punct(byte)
}

/// Builds a span on one line from byte offsets.
fn span(line_number: u32, start: usize, end: usize) -> Option<Span> {
    Some(Span {
        line: line_number,
        line_start: u32::try_from(start).ok()?,
        line_end: u32::try_from(end).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/ruby/Gemfile");

    /// Returns the fields that the exact-list test compares.
    fn summary(dependencies: &[Dependency]) -> Vec<(&str, &str, bool, bool)> {
        dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                    dependency.has_additional_version_constraints,
                )
            })
            .collect()
    }

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn returns_exact_gems_in_document_order() {
        assert_eq!(
            summary(&parse(FIXTURE)),
            [
                ("rails", "7.0.4", false, false),
                ("pg", "0.18", false, true),
                ("rack", "2.2.4", false, false),
                ("sidekiq", "7.1", false, true),
                ("rspec-rails", "6.0", true, false),
                ("debug", "1.0.0", true, false),
                ("prod_only", "1.2.3", false, false),
                ("deep", "4.5.6", false, false),
                ("after_nested", "7.8.9", false, false),
                ("dev_by_option", "2.0", true, false),
                ("dev_by_groups", "3.0", true, false),
                ("paren", "5.0", false, false),
                ("cafe", "9.9.9", false, false),
            ]
        );
    }

    #[test]
    fn skipped_gems_are_absent() {
        let dependencies = parse(FIXTURE);
        for name in [
            "puma",
            "bootsnap",
            "from_git",
            "from_github",
            "local",
            "not_a_pin",
            "upper",
            "tzinfo-data",
        ] {
            assert!(
                dependencies
                    .iter()
                    .all(|dependency| dependency.name != name),
                "{name} must be skipped"
            );
        }
    }

    #[test]
    fn spans_read_back_the_exact_text() {
        let dependencies = parse(FIXTURE);
        let rails = find(&dependencies, "rails");
        assert_eq!(
            text_of_span(FIXTURE, rails.name_span).as_deref(),
            Some("rails")
        );
        assert_eq!(
            text_of_span(FIXTURE, rails.version_span).as_deref(),
            Some("7.0.4")
        );
        let pg = find(&dependencies, "pg");
        assert_eq!(
            text_of_span(FIXTURE, pg.version_span).as_deref(),
            Some("0.18")
        );
        let rack = find(&dependencies, "rack");
        assert_eq!(
            text_of_span(FIXTURE, rack.version_span).as_deref(),
            Some("2.2.4")
        );
        let paren = find(&dependencies, "paren");
        assert_eq!(
            text_of_span(FIXTURE, paren.name_span).as_deref(),
            Some("paren")
        );
        assert_eq!(
            text_of_span(FIXTURE, paren.version_span).as_deref(),
            Some("5.0")
        );
        let cafe = find(&dependencies, "cafe");
        assert_eq!(
            text_of_span(FIXTURE, cafe.version_span).as_deref(),
            Some("9.9.9")
        );
    }

    #[test]
    fn nested_group_gem_sits_on_its_own_line() {
        let dependencies = parse(FIXTURE);
        let deep = find(&dependencies, "deep");
        let line_number = FIXTURE
            .lines()
            .position(|line| line.contains("gem 'deep'"))
            .unwrap();
        assert_eq!(deep.name_span.line as usize, line_number);
        assert_eq!(
            text_of_span(FIXTURE, deep.name_span).as_deref(),
            Some("deep")
        );
    }

    #[test]
    fn nested_group_end_keeps_the_outer_development_group_open() {
        let manifest = "group :test do\n  group :nested do\n  end\n  gem 'inner', '1.0'\nend\n";
        let dependencies = parse(manifest);
        assert!(find(&dependencies, "inner").dev);
    }

    #[test]
    fn crlf_text_gives_identical_dependencies() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        assert_eq!(parse(&crlf_text), parse(FIXTURE));
    }

    #[test]
    fn tab_indented_gem_line_has_exact_spans() {
        let manifest = "group :test do\n\tgem \"tabbed\", '~> 1.2'\nend\n";
        let dependencies = parse(manifest);
        let tabbed = find(&dependencies, "tabbed");
        assert!(tabbed.dev);
        assert_eq!(
            text_of_span(manifest, tabbed.name_span).as_deref(),
            Some("tabbed")
        );
        assert_eq!(
            text_of_span(manifest, tabbed.version_span).as_deref(),
            Some("1.2")
        );
    }

    #[test]
    fn pin_without_space_after_operator() {
        let dependencies = parse("gem 'a', '~>1.0'\n");
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].version, "1.0");
        assert_eq!(
            text_of_span("gem 'a', '~>1.0'\n", dependencies[0].version_span).as_deref(),
            Some("1.0")
        );
        assert!(!dependencies[0].has_additional_version_constraints);
    }

    #[test]
    fn first_pin_wins_and_bounds_mark_additional_constraints() {
        let lower_then_upper = parse("gem 'b', \">=1.0\", \"<2\"\n");
        assert_eq!(lower_then_upper.len(), 1);
        assert_eq!(lower_then_upper[0].version, "1.0");
        assert!(lower_then_upper[0].has_additional_version_constraints);

        let upper_then_lower = parse("gem 'c', '< 2', '>= 1.5'\n");
        assert_eq!(upper_then_lower.len(), 1);
        assert_eq!(upper_then_lower[0].version, "1.5");
        assert!(upper_then_lower[0].has_additional_version_constraints);
    }

    #[test]
    fn interpolated_and_non_numeric_requirements_are_not_returned() {
        assert!(parse("gem 'd', \"#{v}\"\n").is_empty());
        assert!(parse("gem 'e', 'abc'\n").is_empty());
    }

    #[test]
    fn unbalanced_blocks_do_not_panic_and_keep_gems_read() {
        let stray_end = parse("end\ngem 'f', '1.0'\n");
        assert_eq!(summary(&stray_end), [("f", "1.0", false, false)]);
        let unterminated = parse("group :x do\ngem 'g', '2.0'\n");
        assert_eq!(summary(&unterminated), [("g", "2.0", false, false)]);
    }

    #[test]
    fn empty_and_random_text_return_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("lorem ipsum 123 = > ?\n{ } ) \"unclosed\n").is_empty());
    }

    #[test]
    fn gem_inside_a_comment_is_ignored() {
        assert!(parse("# gem 'x', '1.0'\n").is_empty());
    }

    #[test]
    fn words_that_only_start_with_gem_are_not_gem_lines() {
        assert!(parse("gemfile 'x', '1.0'\n").is_empty());
        assert!(parse("gems 'x', '1.0'\n").is_empty());
    }

    #[test]
    fn source_options_in_hash_rocket_spelling_skip_the_gem() {
        let manifest = "gem 'i', '1.0', :git => 'x'\ngem 'j', '1.0', :path => '../j'\n";
        assert!(parse(manifest).is_empty());
    }

    #[test]
    fn group_option_marks_the_gem_as_development() {
        let dependencies = parse("gem 'k', '1.0', :group => :test\n");
        assert!(dependencies[0].dev);
    }

    #[test]
    fn do_block_with_parameters_opens_a_group() {
        let manifest = "group :test do |t|\ngem 'h', '1.0'\nend\ngem 'l', '2.0'\n";
        let dependencies = parse(manifest);
        assert!(find(&dependencies, "h").dev);
        assert!(!find(&dependencies, "l").dev);
    }

    #[test]
    fn gems_inside_a_non_registry_block_are_skipped() {
        for opener in [
            "path '../components/internal-review-gem' do",
            "path('../components/internal-review-gem') do",
            "git 'https://example.com/x.git' do",
            "github 'x/y' do",
            "source 'https://gems.example.com' do",
            "git 'https://example.com/x.git', branch: 'main' do |repo|",
        ] {
            let manifest = format!("{opener}\n  gem 'internal-review-gem', '1.0.0'\nend\n");
            assert!(parse(&manifest).is_empty(), "{opener} must hide its gems");
        }
    }

    #[test]
    fn non_registry_scope_covers_nested_blocks_and_ends_with_its_block() {
        let manifest = "\
path '../local' do
  group :test do
    gem 'inner', '1.0'
  end
  gem 'after_group', '2.0'
end
gem 'outside', '3.0'
";
        assert_eq!(
            summary(&parse(manifest)),
            [("outside", "3.0", false, false)]
        );
    }

    #[test]
    fn registry_blocks_nested_in_a_non_registry_block_stay_skipped() {
        let manifest = "git 'x' do\n  platforms :ruby do\n    gem 'inner', '1.0'\n  end\nend\n";
        assert!(parse(manifest).is_empty());
    }

    #[test]
    fn non_registry_block_inside_a_group_skips_only_its_gems() {
        let manifest = "\
group :test do
  path '../local' do
    gem 'hidden', '1.0'
  end
  gem 'visible', '2.0'
end
";
        assert_eq!(summary(&parse(manifest)), [("visible", "2.0", true, false)]);
    }
}
