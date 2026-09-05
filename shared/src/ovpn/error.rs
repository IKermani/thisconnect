// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation failures for `.ovpn` import.
//!
//! Every variant carries enough context for the UI to point at the offending line, because a
//! rejected profile the user cannot fix is indistinguishable from a broken importer.

use thiserror::Error;

/// A profile rejection. Rejections are fatal: there is no "warn and continue" mode, since the
/// output of this parser is handed to a privileged process.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("profile is {size} bytes, maximum is {max}")]
    FileTooLarge { size: usize, max: usize },

    #[error("profile has more than {max} directives")]
    TooManyDirectives { max: usize },

    #[error("profile has more than {max} inline blocks")]
    TooManyInlineBlocks { max: usize },

    #[error("line {line}: longer than {max} bytes")]
    LineTooLong { line: usize, max: usize },

    #[error("line {line}: NUL byte in profile")]
    NulByte { line: usize },

    #[error("line {line}: unterminated quote")]
    UnterminatedQuote { line: usize },

    #[error("line {line}: more than {max} arguments")]
    TooManyArguments { line: usize, max: usize },

    #[error("line {line}: inline block <{tag}> is never closed")]
    UnterminatedInlineBlock { line: usize, tag: String },

    #[error("line {line}: closing </{tag}> without a matching opening tag")]
    UnexpectedInlineClose { line: usize, tag: String },

    #[error("line {line}: inline block <{tag}> may not be nested here")]
    NestedInlineBlock { line: usize, tag: String },

    #[error("line {line}: inline block <{tag}> exceeds {max} bytes")]
    InlineBlockTooLarge {
        line: usize,
        tag: String,
        max: usize,
    },

    #[error("line {line}: inline block <{tag}> is not permitted inline material")]
    ForbiddenInlineTag { line: usize, tag: String },

    #[error("line {line}: inline block <{tag}> appears more than once")]
    DuplicateInlineTag { line: usize, tag: String },

    #[error("line {line}: directive `{directive}` is refused: {reason}")]
    ForbiddenDirective {
        line: usize,
        directive: String,
        reason: String,
    },

    #[error("line {line}: directive `{directive}` is not in the allowlist")]
    UnknownDirective { line: usize, directive: String },

    #[error("line {line}: directive `{directive}`: {detail}")]
    InvalidArgument {
        line: usize,
        directive: String,
        detail: String,
    },

    #[error(
        "line {line}: directive `{directive}` has an argument with a forbidden character: {detail}"
    )]
    UnsafeArgument {
        line: usize,
        directive: String,
        detail: String,
    },

    #[error("profile contains no directives")]
    EmptyProfile,

    #[error("profile declares no `remote` server")]
    MissingRemote,
}

impl ValidationError {
    /// 1-based line the rejection points at, when the rejection is line-scoped.
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::LineTooLong { line, .. }
            | Self::NulByte { line }
            | Self::UnterminatedQuote { line }
            | Self::TooManyArguments { line, .. }
            | Self::UnterminatedInlineBlock { line, .. }
            | Self::UnexpectedInlineClose { line, .. }
            | Self::NestedInlineBlock { line, .. }
            | Self::InlineBlockTooLarge { line, .. }
            | Self::ForbiddenInlineTag { line, .. }
            | Self::DuplicateInlineTag { line, .. }
            | Self::ForbiddenDirective { line, .. }
            | Self::UnknownDirective { line, .. }
            | Self::InvalidArgument { line, .. }
            | Self::UnsafeArgument { line, .. } => Some(*line),
            _ => None,
        }
    }

    /// Directive or inline tag named by the rejection, for the UI message.
    pub fn directive(&self) -> Option<&str> {
        match self {
            Self::ForbiddenDirective { directive, .. }
            | Self::UnknownDirective { directive, .. }
            | Self::InvalidArgument { directive, .. }
            | Self::UnsafeArgument { directive, .. } => Some(directive),
            Self::UnterminatedInlineBlock { tag, .. }
            | Self::UnexpectedInlineClose { tag, .. }
            | Self::NestedInlineBlock { tag, .. }
            | Self::InlineBlockTooLarge { tag, .. }
            | Self::ForbiddenInlineTag { tag, .. }
            | Self::DuplicateInlineTag { tag, .. } => Some(tag),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn reports_line_and_directive_for_a_forbidden_directive() {
        // Arrange
        let err = ValidationError::ForbiddenDirective {
            line: 12,
            directive: "plugin".into(),
            reason: "code loading".into(),
        };

        // Act / Assert
        assert_eq!(err.line(), Some(12));
        assert_eq!(err.directive(), Some("plugin"));
        assert!(err.to_string().contains("plugin"));
    }

    #[test]
    fn reports_tag_for_an_inline_rejection() {
        // Arrange
        let err = ValidationError::ForbiddenInlineTag {
            line: 3,
            tag: "auth-user-pass".into(),
        };

        // Act / Assert
        assert_eq!(err.directive(), Some("auth-user-pass"));
        assert_eq!(err.line(), Some(3));
    }

    #[test]
    fn file_level_rejections_have_no_line() {
        // Arrange
        let err = ValidationError::FileTooLarge { size: 10, max: 5 };

        // Act / Assert
        assert_eq!(err.line(), None);
        assert_eq!(err.directive(), None);
    }
}
