// SPDX-License-Identifier: GPL-3.0-or-later

//! Tokenizer for `.ovpn` text: comments, quoting, and `<tag>` inline blocks.
//!
//! The lexer only decides *shape*. It deliberately knows nothing about which directives or tags
//! are acceptable — that judgement lives in `directive.rs`, so the allowlist has exactly one home.

use zeroize::Zeroizing;

use super::error::ValidationError;
use super::{MAX_ARGS, MAX_INLINE_BLOCKS, MAX_INLINE_BYTES, MAX_LINE_BYTES};

/// A directive line: a name and its already-unquoted arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDirective {
    pub line: usize,
    pub name: String,
    pub args: Vec<String>,
}

/// A `<tag>…</tag>` block. The body is verbatim and may be key material, so it is zeroized on
/// drop and never rendered by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct RawBlock {
    pub line: usize,
    pub tag: String,
    pub body: Zeroizing<String>,
}

impl std::fmt::Debug for RawBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawBlock")
            .field("line", &self.line)
            .field("tag", &self.tag)
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Directive(RawDirective),
    Block(RawBlock),
}

/// Lex a whole profile. `first_line` is the 1-based number of the first line of `input`, so that
/// nested bodies report absolute line numbers.
pub fn lex(input: &str, first_line: usize) -> Result<Vec<Item>, ValidationError> {
    let mut items: Vec<Item> = Vec::new();
    let mut open: Option<(usize, String, Vec<String>)> = None;
    let mut blocks = 0usize;

    for (offset, raw_line) in input.lines().enumerate() {
        let line = first_line + offset;
        if raw_line.contains('\0') {
            return Err(ValidationError::NulByte { line });
        }

        if let Some((start, tag, mut body)) = open.take() {
            match close_tag(raw_line) {
                Some(closing) if closing == tag => {
                    blocks += 1;
                    if blocks > MAX_INLINE_BLOCKS {
                        return Err(ValidationError::TooManyInlineBlocks {
                            max: MAX_INLINE_BLOCKS,
                        });
                    }
                    items.push(Item::Block(finish_block(start, tag, &body)?));
                }
                _ => {
                    body.push(raw_line.to_owned());
                    let used: usize = body.iter().map(|l| l.len() + 1).sum();
                    if used > MAX_INLINE_BYTES {
                        return Err(ValidationError::InlineBlockTooLarge {
                            line: start,
                            tag,
                            max: MAX_INLINE_BYTES,
                        });
                    }
                    open = Some((start, tag, body));
                }
            }
            continue;
        }

        let trimmed = raw_line.trim();
        if trimmed.is_empty() || is_comment(trimmed) {
            continue;
        }
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(ValidationError::LineTooLong {
                line,
                max: MAX_LINE_BYTES,
            });
        }

        if let Some(tag) = open_tag(trimmed, line)? {
            open = Some((line, tag, Vec::new()));
            continue;
        }

        let tokens = tokenize(raw_line, line)?;
        let Some((name, args)) = tokens.split_first() else {
            continue;
        };
        if args.len() > MAX_ARGS {
            return Err(ValidationError::TooManyArguments {
                line,
                max: MAX_ARGS,
            });
        }
        items.push(Item::Directive(RawDirective {
            line,
            name: name.to_ascii_lowercase(),
            args: args.to_vec(),
        }));
    }

    if let Some((start, tag, _)) = open {
        return Err(ValidationError::UnterminatedInlineBlock { line: start, tag });
    }
    Ok(items)
}

fn finish_block(line: usize, tag: String, body: &[String]) -> Result<RawBlock, ValidationError> {
    let mut text = body.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    Ok(RawBlock {
        line,
        tag,
        body: Zeroizing::new(text),
    })
}

fn is_comment(trimmed: &str) -> bool {
    trimmed.starts_with('#') || trimmed.starts_with(';')
}

/// Recognise `<tag>`. A malformed angle-bracket line is reported as a rejected tag rather than
/// silently falling through to directive parsing, which is where the `<auth-user-pass>` bypass
/// would otherwise reappear.
fn open_tag(trimmed: &str, line: usize) -> Result<Option<String>, ValidationError> {
    if !trimmed.starts_with('<') {
        return Ok(None);
    }
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .unwrap_or("");
    if let Some(closing) = inner.strip_prefix('/') {
        return Err(ValidationError::UnexpectedInlineClose {
            line,
            tag: closing.to_ascii_lowercase(),
        });
    }
    let tag = inner.to_ascii_lowercase();
    if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(ValidationError::ForbiddenInlineTag {
            line,
            tag: trimmed.to_owned(),
        });
    }
    Ok(Some(tag))
}

fn close_tag(raw_line: &str) -> Option<String> {
    let trimmed = raw_line.trim();
    trimmed
        .strip_prefix("</")
        .and_then(|rest| rest.strip_suffix('>'))
        .map(str::to_ascii_lowercase)
}

/// Split one line into tokens using OpenVPN's own rules: `#`/`;` start a comment anywhere outside
/// quotes, single quotes are literal, double quotes and bare text honour backslash escapes.
fn tokenize(line: &str, line_no: usize) -> Result<Vec<String>, ValidationError> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in line.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if !in_single => escaped = true,
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            '#' | ';' if !in_single && !in_double => break,
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }

    if in_single || in_double || escaped {
        return Err(ValidationError::UnterminatedQuote { line: line_no });
    }
    if has_token {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn directives(input: &str) -> Vec<RawDirective> {
        lex(input, 1)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| match i {
                Item::Directive(d) => Some(d),
                Item::Block(_) => None,
            })
            .collect()
    }

    #[test]
    fn splits_directive_name_and_arguments() {
        // Arrange
        let input = "remote vpn.example.com 1194 udp\n";

        // Act
        let got = directives(input);

        // Assert
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "remote");
        assert_eq!(got[0].args, vec!["vpn.example.com", "1194", "udp"]);
        assert_eq!(got[0].line, 1);
    }

    #[test]
    fn lowercases_directive_names_but_not_arguments() {
        // Arrange / Act
        let got = directives("REMOTE Vpn.Example.COM 1194\n");

        // Assert
        assert_eq!(got[0].name, "remote");
        assert_eq!(got[0].args[0], "Vpn.Example.COM");
    }

    #[test]
    fn skips_hash_and_semicolon_comments_and_blank_lines() {
        // Arrange
        let input = "# a comment\n\n; another\nclient\n";

        // Act
        let got = directives(input);

        // Assert
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "client");
        assert_eq!(got[0].line, 4);
    }

    #[test]
    fn strips_trailing_comment_outside_quotes() {
        // Arrange / Act
        let got = directives("verb 3 # noisy\n");

        // Assert
        assert_eq!(got[0].args, vec!["3"]);
    }

    #[test]
    fn keeps_hash_inside_quotes() {
        // Arrange / Act
        let got = directives("static-challenge \"PIN #1\" 1\n");

        // Assert
        assert_eq!(got[0].args, vec!["PIN #1", "1"]);
    }

    #[test]
    fn preserves_quoted_empty_argument() {
        // Arrange / Act
        let got = directives("static-challenge \"\" 1\n");

        // Assert
        assert_eq!(got[0].args, vec!["", "1"]);
    }

    #[test]
    fn rejects_unterminated_quote() {
        // Arrange / Act
        let err = lex("static-challenge \"oops\n", 1).unwrap_err();

        // Assert
        assert_eq!(err, ValidationError::UnterminatedQuote { line: 1 });
    }

    #[test]
    fn captures_inline_block_body_verbatim() {
        // Arrange
        let input = "<ca>\nLINE-A\nLINE-B\n</ca>\n";

        // Act
        let items = lex(input, 1).unwrap_or_default();

        // Assert
        let Some(Item::Block(block)) = items.first() else {
            panic!("expected a block");
        };
        assert_eq!(block.tag, "ca");
        assert_eq!(block.body.as_str(), "LINE-A\nLINE-B\n");
        assert_eq!(block.line, 1);
    }

    #[test]
    fn debug_of_block_does_not_render_body() {
        // Arrange
        let block = RawBlock {
            line: 1,
            tag: "key".into(),
            body: Zeroizing::new("SECRET-MATERIAL".into()),
        };

        // Act
        let rendered = format!("{block:?}");

        // Assert
        assert!(!rendered.contains("SECRET-MATERIAL"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn rejects_unterminated_inline_block() {
        // Arrange / Act
        let err = lex("<ca>\nDATA\n", 1).unwrap_err();

        // Assert
        assert_eq!(
            err,
            ValidationError::UnterminatedInlineBlock {
                line: 1,
                tag: "ca".into()
            }
        );
    }

    #[test]
    fn rejects_closing_tag_without_opening() {
        // Arrange / Act
        let err = lex("</ca>\n", 1).unwrap_err();

        // Assert
        assert_eq!(
            err,
            ValidationError::UnexpectedInlineClose {
                line: 1,
                tag: "ca".into()
            }
        );
    }

    #[test]
    fn rejects_nul_byte() {
        // Arrange / Act
        let err = lex("remote a\0b 1194\n", 1).unwrap_err();

        // Assert
        assert_eq!(err, ValidationError::NulByte { line: 1 });
    }

    #[test]
    fn rejects_over_long_line() {
        // Arrange
        let input = format!("remote {} 1194\n", "a".repeat(MAX_LINE_BYTES));

        // Act
        let err = lex(&input, 1).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::LineTooLong { line: 1, .. }));
    }

    #[test]
    fn rejects_too_many_arguments() {
        // Arrange
        let input = format!("remote {}\n", "a ".repeat(MAX_ARGS + 2));

        // Act
        let err = lex(&input, 1).unwrap_err();

        // Assert
        assert!(matches!(err, ValidationError::TooManyArguments { .. }));
    }

    #[test]
    fn reports_absolute_line_numbers_with_an_offset() {
        // Arrange / Act
        let got = lex("client\n", 40).unwrap_or_default();

        // Assert
        let Some(Item::Directive(d)) = got.first() else {
            panic!("expected a directive");
        };
        assert_eq!(d.line, 40);
    }
}
