//! Maven version numbers, compared like Maven's `ComparableVersion` (3.9).
//!
//! OSV orders the `ECOSYSTEM` ranges of Maven advisories with this rule, so the fix plan must use it.
//! A version is a nested list of items: numbers and qualifiers. A `-`, and a qualifier that
//! follows a number, open a sub-list. That is why `1.0-1` is newer than `1.0` and `1.0-alpha` is older.
//!
//! The order is not total, as in Maven: `1.2.3.jbossorg-1 > 1.2.3 > 1.2.3-beta1 > 1.2.3.jbossorg-1`
//! is a cycle. Sort with a function that cannot panic on a cycle, never with `slice::sort_by`.

use std::cmp::Ordering;

/// The longest version text that is parsed, in bytes. A longer text is not a real version.
const MAX_TEXT_LEN: usize = 256;

/// A number of a version. Digits that do not fit `u64` stay as text and still compare right.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Number {
    Small(u64),
    /// The digits without leading zeros. The length comes first, so the derived order is numeric.
    Big(usize, String),
}

/// A qualifier of a version, such as `alpha` or `sp`.
///
/// The variant order is the rule: a known qualifier sorts by its rank, and an unknown one sorts after
/// every known one, as text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Qualifier {
    Known(u8),
    Unknown(String),
}

/// The qualifier of a plain release. A qualifier below it is a prerelease.
const RELEASE: Qualifier = Qualifier::Known(5);

/// One item of a version list.
#[derive(Clone, Debug)]
enum Item {
    Number(Number),
    Qualifier(Qualifier),
    List(Vec<Item>),
}

impl Item {
    const ZERO: Item = Item::Number(Number::Small(0));

    /// Returns `true` for an item that Maven drops at the end of a list: `0`, a release qualifier or an empty list.
    fn is_null(&self) -> bool {
        match self {
            Item::Number(number) => *number == Number::Small(0),
            Item::Qualifier(qualifier) => *qualifier == RELEASE,
            Item::List(items) => items.is_empty(),
        }
    }

    /// Compares with the missing item at the same position of a shorter list.
    fn compare_to_missing(&self) -> Ordering {
        match self {
            Item::Number(_) if self.is_null() => Ordering::Equal,
            Item::Number(_) => Ordering::Greater,
            Item::Qualifier(qualifier) => qualifier.cmp(&RELEASE),
            // All the items count, not only the first one (Maven 3.9, MNG-6964): `1-0.1` is newer than `1`.
            Item::List(items) => items
                .iter()
                .map(Item::compare_to_missing)
                .find(|ordering| ordering.is_ne())
                .unwrap_or(Ordering::Equal),
        }
    }

    /// Compares with `other`, the item at the same position of the other list.
    fn compare_to(&self, other: &Item) -> Ordering {
        match (self, other) {
            (Item::Number(left), Item::Number(right)) => left.cmp(right),
            (Item::Qualifier(left), Item::Qualifier(right)) => left.cmp(right),
            (Item::List(left), Item::List(right)) => compare_lists(left, right),
            // A number is newer than a qualifier or a sub-list, and a sub-list is newer than a qualifier.
            (Item::Number(_), _) | (Item::List(_), Item::Qualifier(_)) => Ordering::Greater,
            (Item::Qualifier(_), _) | (Item::List(_), Item::Number(_)) => Ordering::Less,
        }
    }
}

/// Compares two lists item by item. The shorter list ends with missing items.
fn compare_lists(left: &[Item], right: &[Item]) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        let ordering = match (left.get(index), right.get(index)) {
            (Some(left_item), Some(right_item)) => left_item.compare_to(right_item),
            (Some(left_item), None) => left_item.compare_to_missing(),
            (None, Some(right_item)) => right_item.compare_to_missing().reverse(),
            (None, None) => unreachable!("the index is below the longer length"),
        };
        if ordering.is_ne() {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Removes the null items at the end of `items`, looking through the sub-lists that stay.
fn normalize(items: &mut Vec<Item>) {
    let mut index = items.len();
    while index > 0 {
        index -= 1;
        if items[index].is_null() {
            items.remove(index);
        } else if !matches!(items[index], Item::List(_)) {
            break;
        }
    }
}

/// Reads a number item from digits.
fn number_of(digits: &str) -> Number {
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Number::Small(0);
    }
    significant.parse::<u64>().map_or_else(
        |_| Number::Big(significant.len(), significant.to_owned()),
        Number::Small,
    )
}

/// Reads a qualifier item. A one-letter `a`, `b` or `m` before a digit is `alpha`, `beta` or `milestone`.
fn qualifier_of(text: &str, is_followed_by_digit: bool) -> Qualifier {
    let name = match text {
        "a" if is_followed_by_digit => "alpha",
        "b" if is_followed_by_digit => "beta",
        "m" if is_followed_by_digit => "milestone",
        other => other,
    };
    match name {
        "alpha" => Qualifier::Known(0),
        "beta" => Qualifier::Known(1),
        "milestone" => Qualifier::Known(2),
        "rc" | "cr" => Qualifier::Known(3),
        "snapshot" => Qualifier::Known(4),
        "" | "ga" | "final" | "release" => RELEASE,
        "sp" => Qualifier::Known(6),
        unknown => Qualifier::Unknown(unknown.to_owned()),
    }
}

/// Reads the item of a part that ends at a separator or at the end of the text.
fn item_of(is_digit: bool, text: &str) -> Item {
    if is_digit {
        Item::Number(number_of(text))
    } else {
        Item::Qualifier(qualifier_of(text, false))
    }
}

/// The nested lists that `parse` fills, from the outermost one to the innermost open one.
#[derive(Default)]
struct ListBuilder {
    /// The innermost open list. It receives the next items.
    current: Vec<Item>,
    /// The lists that enclose `current`. Each sub-list joins its parent only when the text ends.
    ancestors: Vec<Vec<Item>>,
}

impl ListBuilder {
    fn push(&mut self, item: Item) {
        self.current.push(item);
    }

    fn has_items(&self) -> bool {
        !self.current.is_empty()
    }

    /// Opens a sub-list: `current` joins `ancestors` and a new empty list receives the next items.
    fn open_sublist(&mut self) {
        self.ancestors.push(std::mem::take(&mut self.current));
    }

    /// Closes the lists from the innermost one: each is normalized, then joins its parent.
    fn finish(mut self) -> Vec<Item> {
        while let Some(mut parent) = self.ancestors.pop() {
            normalize(&mut self.current);
            parent.push(Item::List(self.current));
            self.current = parent;
        }
        normalize(&mut self.current);
        self.current
    }
}

/// A parsed Maven version such as `2.15.0`, `9.0.0.M1` or `2.2.11.RELEASE`.
#[derive(Clone, Debug)]
pub struct MavenVersion {
    items: Vec<Item>,
    /// The lowercased text. `items` has dropped the zeros at its end, and `release` reads them back from here.
    text: String,
}

impl MavenVersion {
    /// Parses `text`. Returns `None` for empty text and for text over 256 bytes.
    ///
    /// Any other text is a Maven version: Maven has no syntax error.
    pub fn parse(text: &str) -> Option<MavenVersion> {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_TEXT_LEN {
            return None;
        }
        let lowered = trimmed.to_ascii_lowercase();
        let mut lists = ListBuilder::default();
        // `is_digit` tells the kind of the part that starts at `start`: digits or letters.
        let mut is_digit = false;
        let mut start = 0;
        for (index, byte) in lowered.bytes().enumerate() {
            let is_part_open = index > start;
            match byte {
                b'.' | b'-' => {
                    lists.push(if is_part_open {
                        item_of(is_digit, &lowered[start..index])
                    } else {
                        Item::ZERO
                    });
                    start = index + 1;
                    if byte == b'-' {
                        lists.open_sublist();
                    }
                }
                b'0'..=b'9' => {
                    let is_qualifier_before_digit = !is_digit && is_part_open;
                    if is_qualifier_before_digit {
                        // `1.0.0.X1` sorts like `1.0.0-X1`: a qualifier before a digit opens a sub-list.
                        if lists.has_items() {
                            lists.open_sublist();
                        }
                        lists.push(Item::Qualifier(qualifier_of(&lowered[start..index], true)));
                        start = index;
                        lists.open_sublist();
                    }
                    is_digit = true;
                }
                _ => {
                    let is_number_before_letter = is_digit && is_part_open;
                    if is_number_before_letter {
                        lists.push(Item::Number(number_of(&lowered[start..index])));
                        start = index;
                        lists.open_sublist();
                    }
                    is_digit = false;
                }
            }
        }
        if start < lowered.len() {
            if !is_digit && lists.has_items() {
                lists.open_sublist();
            }
            lists.push(item_of(is_digit, &lowered[start..]));
        }
        Some(MavenVersion {
            items: lists.finish(),
            text: lowered,
        })
    }

    /// Returns `true` when the first qualifier is below the release one, such as `alpha`, `M1` or `SNAPSHOT`.
    pub fn is_prerelease(&self) -> bool {
        let first_non_number = self
            .items
            .iter()
            .find(|item| !matches!(item, Item::Number(_)));
        // A qualifier after a number opens a sub-list, so the qualifier can be the first item of it.
        let first_qualifier_candidate = match first_non_number {
            Some(Item::List(sublist)) => sublist.first(),
            other => other,
        };
        matches!(first_qualifier_candidate, Some(Item::Qualifier(qualifier)) if *qualifier < RELEASE)
    }

    /// Returns the leading numbers as written, such as `[9, 0, 0]` for `9.0.0.M1`.
    ///
    /// It reads the text again, so that `parse` keeps no second list. As in `parse`, an empty segment
    /// is a zero, except the one after the last `.`: a qualifier or the end of the text follows it.
    pub fn release(&self) -> Vec<u64> {
        let numbers_end = self
            .text
            .find(|character: char| !(character.is_ascii_digit() || character == '.'))
            .unwrap_or(self.text.len());
        let mut segments = self.text[..numbers_end].split('.').peekable();
        let mut numbers = Vec::new();
        while let Some(segment) = segments.next() {
            let is_last = segments.peek().is_none();
            match segment {
                "" if is_last => break,
                "" => numbers.push(0),
                digits => match digits.parse() {
                    Ok(number) => numbers.push(number),
                    Err(_) => break,
                },
            }
        }
        numbers
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_lists(&self.items, &other.items)
    }
}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MavenVersion {}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> MavenVersion {
        MavenVersion::parse(text).unwrap_or_else(|| panic!("`{text}` should parse"))
    }

    /// Asserts that every version of `chain` is strictly less than the next one.
    fn assert_ascending(chain: &[&str]) {
        for pair in chain.windows(2) {
            assert_eq!(
                version(pair[0]).cmp(&version(pair[1])),
                Ordering::Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn qualifiers_sort_in_the_maven_order() {
        assert_ascending(&[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ]);
    }

    #[test]
    fn equal_spellings_are_equal() {
        for spelling in ["1.0", "1.0.0", "1-ga", "1.0-final", "1.0.RELEASE", "1.ga"] {
            assert_eq!(version(spelling), version("1"), "{spelling}");
        }
    }

    #[test]
    fn real_shapes_order_as_maven_does() {
        assert_ascending(&["9.0.0.M1", "9.0.0", "9.0.1"]);
        assert_eq!(version("2.2.11.RELEASE"), version("2.2.11"));
        assert_ascending(&["2.2.11.RELEASE", "2.2.12"]);
        assert_ascending(&["2.5.7", "2.5.7.SR0", "2.5.8"]);
        assert_ascending(&["1.0", "1.0-1"]);
        assert_ascending(&["1.0-SNAPSHOT", "1.0"]);
        assert_ascending(&["2.14.1", "2.15.0"]);
    }

    #[test]
    fn case_does_not_matter() {
        assert_eq!(version("9.0.0.M1"), version("9.0.0.m1"));
    }

    #[test]
    fn parse_rejects_empty_and_oversized_text() {
        assert!(MavenVersion::parse("").is_none());
        assert!(MavenVersion::parse("  ").is_none());
        assert!(MavenVersion::parse(&"1.".repeat(129)).is_none());
        assert!(MavenVersion::parse(&"1.".repeat(128)).is_some());
    }

    #[test]
    fn an_overflowing_integer_compares_as_digits() {
        assert!(version("99999999999999999999999") > version("99999999999999999999998"));
        assert!(version("99999999999999999999999") > version("18446744073709551615"));
        assert_eq!(version("00012"), version("12"));
    }

    #[test]
    fn prerelease_follows_the_qualifier() {
        for text in [
            "1.0-alpha",
            "1.0-beta1",
            "1.0.M1",
            "1.0-rc1",
            "1.0-SNAPSHOT",
        ] {
            assert!(version(text).is_prerelease(), "{text}");
        }
        for text in ["1.0", "1.0.RELEASE", "1.0-sp1", "2.5.7.SR0"] {
            assert!(!version(text).is_prerelease(), "{text}");
        }
    }

    #[test]
    fn release_gives_the_leading_integers() {
        assert_eq!(version("2.15.0").release(), [2, 15, 0]);
        assert_eq!(version("9.0.0.M1").release(), [9, 0, 0]);
    }

    #[test]
    fn odd_separators_and_non_ascii_text_parse_without_panic() {
        for text in [
            "-1", "1..2", "1--2", "1-", "1.", ".", "-", "é1", "1é", "1-é",
        ] {
            assert!(MavenVersion::parse(text).is_some(), "{text}");
        }
    }

    #[test]
    fn a_sublist_is_compared_with_a_missing_item_by_all_its_items() {
        // Maven 3.9 (MNG-6964): `1-0.1` holds a `0` first, but its `1` still makes it newer than `1`.
        assert_ascending(&["1", "1-0.1"]);
        assert_ascending(&["1.0-0.0.1", "1.0-1"]);
        assert_eq!(version("1-0.0"), version("1"));
    }

    #[test]
    fn release_stops_at_the_first_qualifier_hyphen_or_overflow() {
        assert_eq!(version("1.0-1").release(), [1, 0]);
        assert_eq!(version("2.5.7.SR0").release(), [2, 5, 7]);
        assert!(version("alpha1").release().is_empty());
        assert_eq!(version("1.99999999999999999999.3").release(), [1]);
    }

    #[test]
    fn release_reads_an_empty_segment_as_zero_like_the_parser() {
        assert_eq!(version(".1").release(), [0, 1]);
        assert_eq!(version("1..2").release(), [1, 0, 2]);
        assert_eq!(version("1.0.").release(), [1, 0]);
        assert_eq!(version("9.0.0.M1").release(), [9, 0, 0]);
    }
}
