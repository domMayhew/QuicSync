//! Git ignore policy evaluation for filesystem traversal.

use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

use ignore::{
    Match,
    gitignore::{Gitignore, GitignoreBuilder},
};

use crate::{
    config::SourceConfig,
    error::{ErrorCode, QuicSyncError},
    filesystem::paths::PROTECTED_COMPONENTS,
    protocol::messages::{PolicyRuleFile, canonical_policy_digest},
    types::{Digest, EntryKind, RelativePath},
};

/// Whether an entry belongs to the source-managed path set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoreDecision {
    /// The path is managed and may be indexed, transferred, updated, or deleted.
    Managed,
    /// The path is excluded by the source's ignore policy and must be left alone.
    Ignored,
    /// The path is QuicSync or Git administrative state and is always excluded.
    Protected,
}

/// Ignore rules accumulated by the active filesystem traversal.
#[derive(Clone, Debug)]
pub struct IgnorePolicy {
    rules: Vec<PolicyRuleFile>,
    scoped: Vec<ScopedRuleSet>,
    digest: Digest,
}

#[derive(Clone, Debug)]
struct ScopedRuleSet {
    scope: Option<RelativePath>,
    matcher: Gitignore,
}

impl IgnorePolicy {
    /// Creates an empty policy for traversal.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            scoped: Vec::new(),
            digest: canonical_policy_digest(&[]),
        }
    }

    /// Creates a traversal policy with the source configuration's root-scoped exclusions.
    pub fn for_source_config(config: &SourceConfig) -> Result<Self, QuicSyncError> {
        Self::with_configured_exclusions(config.global_exclusions())
    }

    /// Creates a traversal policy with configured root-scoped exclusions.
    pub fn with_configured_exclusions(
        configured_exclusions: &[String],
    ) -> Result<Self, QuicSyncError> {
        let mut policy = Self::empty();
        if !configured_exclusions.is_empty() {
            let contents = configured_exclusions.join("\n").into_bytes();
            policy.add_ignore_contents(None, contents)?;
        }
        Ok(policy)
    }

    /// Reconstructs a policy from known rule files.
    pub fn from_rule_files(rules: Vec<PolicyRuleFile>) -> Result<Self, QuicSyncError> {
        let mut policy = Self::empty();
        for rule in rules {
            policy.add_rule_file(rule)?;
        }
        Ok(policy)
    }

    /// Adds a `.gitignore` file discovered by the active filesystem traversal.
    ///
    /// `scope` is the directory containing the ignore file. `None` denotes the root.
    pub fn add_ignore_contents(
        &mut self,
        scope: Option<RelativePath>,
        contents: Vec<u8>,
    ) -> Result<(), QuicSyncError> {
        self.add_rule_file(rule_file(scope, contents))
    }

    /// Adds a validated policy rule file to the current traversal state.
    pub fn add_rule_file(&mut self, rule: PolicyRuleFile) -> Result<(), QuicSyncError> {
        let actual = digest(&rule.contents);
        if rule.digest != actual {
            return Err(QuicSyncError::new(
                ErrorCode::IntegrityMismatch,
                None,
                "ignore-policy rule digest does not match its contents",
            ));
        }
        let matcher = build_matcher(&rule)?;
        self.scoped.push(ScopedRuleSet {
            scope: rule.scope.clone(),
            matcher,
        });
        self.rules.push(rule);
        self.digest = canonical_policy_digest(&self.rules);
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn rule_files(&self) -> &[PolicyRuleFile] {
        &self.rules
    }

    pub(crate) fn checkpoint(&self) -> usize {
        self.scoped.len()
    }

    /// Discard a completed directory's rules so siblings retain only inherited policy.
    pub(crate) fn restore(&mut self, checkpoint: usize) {
        self.scoped.truncate(checkpoint);
        self.rules.truncate(checkpoint);
        self.digest = canonical_policy_digest(&self.rules);
    }

    pub fn decision(&self, path: &RelativePath, kind: EntryKind) -> IgnoreDecision {
        if is_protected(path) {
            return IgnoreDecision::Protected;
        }

        let is_dir = kind == EntryKind::Directory;
        let mut ignored = false;
        for rules in &self.scoped {
            let Some(scoped_path) = scoped_path(path, rules.scope.as_ref()) else {
                continue;
            };
            match rules
                .matcher
                .matched_path_or_any_parents(scoped_path, is_dir)
            {
                Match::None => {}
                Match::Ignore(_) => ignored = true,
                Match::Whitelist(_) => ignored = false,
            }
        }

        if ignored {
            IgnoreDecision::Ignored
        } else {
            IgnoreDecision::Managed
        }
    }

    pub fn manages(&self, path: &RelativePath, kind: EntryKind) -> bool {
        self.decision(path, kind) == IgnoreDecision::Managed
    }
}

fn build_matcher(rule: &PolicyRuleFile) -> Result<Gitignore, QuicSyncError> {
    let root = relative_to_path(rule.scope.as_ref());
    let mut builder = GitignoreBuilder::new(root);
    let contents = std::str::from_utf8(&rule.contents).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::InvalidConfiguration,
            None,
            format!("ignore-policy rule file is not valid UTF-8: {error}"),
        )
    })?;
    let from = rule
        .scope
        .as_ref()
        .map(|scope| relative_to_path(Some(scope)).join(".gitignore"));
    for line in contents.lines() {
        builder.add_line(from.clone(), line).map_err(|error| {
            QuicSyncError::new(
                ErrorCode::InvalidConfiguration,
                None,
                format!("invalid ignore-policy rule: {error}"),
            )
        })?;
    }
    builder.build().map_err(|error| {
        QuicSyncError::new(
            ErrorCode::InvalidConfiguration,
            None,
            format!("cannot build ignore-policy matcher: {error}"),
        )
    })
}

fn rule_file(scope: Option<RelativePath>, contents: Vec<u8>) -> PolicyRuleFile {
    PolicyRuleFile {
        scope,
        digest: digest(&contents),
        contents,
    }
}

fn digest(contents: &[u8]) -> Digest {
    Digest::from_bytes(*blake3::hash(contents).as_bytes())
}

fn scoped_path(path: &RelativePath, scope: Option<&RelativePath>) -> Option<PathBuf> {
    let components = path.components();
    let scoped = match scope {
        None => components,
        Some(scope) => components.strip_prefix(scope.components())?,
    };
    if scoped.is_empty() {
        return None;
    }
    Some(components_to_path(scoped))
}

fn relative_to_path(path: Option<&RelativePath>) -> PathBuf {
    path.map_or_else(PathBuf::new, |path| components_to_path(path.components()))
}

fn components_to_path(components: &[Vec<u8>]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(OsString::from_vec(component.clone()));
    }
    path
}

fn is_protected(path: &RelativePath) -> bool {
    path.components()
        .iter()
        .any(|component| PROTECTED_COMPONENTS.contains(&component.as_slice()))
}
