//! The release-ordering lint (GitLab CI): a product's server must
//! deploy only after every client it serves is published.
//!
//! The version gate sends clients looking for the server's version the
//! moment the server deploys, so their packages, release manifests and
//! repository indexes — and the web console — must already be out. GitLab's
//! `needs:` overrides stage order, so the order is enforced where it's
//! declared: every **server deploy job** must reach every **client job**
//! (the CI template's publish job, the web console's deploy, any other a
//! product names) through explicit, non-optional `needs`, directly or
//! through needs of needs. Stage order doesn't count: a job a rule leaves
//! out of a pipeline is skipped silently by stage order, while a
//! non-optional `needs` on it fails the pipeline's creation (fail closed).
//! A rule's `needs` replaces the job's when the rule matches, so a job's
//! needs are those every one of its runnable rules leaves it with.
//!
//! Also refused, as each lets a server deploy past a failed client:
//!
//! - a client job allowed to fail (`allow_failure` true or exit codes, in
//!   the job or any rule, or a manual job's default outside rules);
//! - a client job that triggers a pipeline without `strategy: depend` or
//!   `mirror` (it succeeds as soon as the child pipeline is created);
//! - a server job that runs `when: always` or `when: on_failure`, in the job
//!   or any rule (it runs past failed needs) — and a job between a server
//!   and a client that does is no path at all;
//! - a need on a client job that's `optional: true`, or names only some of
//!   its `parallel: matrix` jobs.
//!
//! **What's read, as GitLab reads it.** YAML as GitLab's parser (Psych,
//! YAML 1.1) takes it: `yes`/`on`/`true` and `no`/`off`/`false` booleans in
//! any case, `!!str`/`!!bool` tags, a duplicate key's last value, `<<` merge
//! keys in document order (a merge overwrites the keys before it; within a
//! list of merged mappings the first wins); other tags are refused. Then
//! the CI file, its local includes (`include: path`, `include: {local: …}`,
//! globs as GitLab matches them — `*` within a directory, `**` across
//! them — over the repository's tracked files, nested, with `inputs:`),
//! and any further files given (an included template, such as seaworthy's
//! `ci/gitlab/seaworthy.yml`), merged as GitLab merges them: includes
//! first, in order, then the including file, mappings deep-merged, arrays
//! and scalars replaced. A `spec: inputs` header's values fill every whole
//! or partial `$[[ inputs.… ]]` of the parsed configuration (a whole value
//! keeps its type). A further file stands for an include whose inputs the
//! lint can't see, so its required inputs (those without a default, such
//! as a template's images and runner tags, which never decide an order)
//! read as empty there. Then `extends`, then `!reference`. An include with
//! `rules:` is refused (the lint can't tell when it applies); includes from
//! other projects, URLs, GitLab templates and components can't be read
//! offline: they're reported, and a job defined only there is unknown.
//! GitLab's limits bound every walk (150 includes, 11 levels of `extends`,
//! 10 of `!reference`), and so do a file's size, nesting depth and node
//! count (nested aliases expand).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::DistError;

/// The most files one configuration includes (GitLab's limit).
const MAX_INCLUDES: usize = 150;
/// The deepest `extends` chain (GitLab's limit).
const MAX_EXTENDS_DEPTH: usize = 11;
/// The deepest `!reference` chain (GitLab's limit).
const MAX_REFERENCE_DEPTH: usize = 10;
/// The largest CI file read.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// The most nodes one file may expand to, aliases included (a file of
/// nested aliases otherwise grows exponentially).
const MAX_NODES: usize = 1_000_000;
/// The deepest nesting read, aliases expanded (every later walk recurses).
const MAX_DEPTH: usize = 128;
/// The most files a glob is matched against (a repository's tracked files).
const MAX_LISTED_FILES: usize = 200_000;

/// Top-level keys that configure the pipeline rather than name a job.
const GLOBAL_KEYS: [&str; 11] = [
    "default",
    "include",
    "stages",
    "variables",
    "workflow",
    "image",
    "services",
    "cache",
    "before_script",
    "after_script",
    "spec",
];

/// The tag handle `!!` resolves to.
const CORE_SCHEMA: &str = "tag:yaml.org,2002:";

/// A YAML node, as GitLab reads it: scalars keep whether they were plain
/// (`true` is a boolean only unquoted), `!reference` stays a reference.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A scalar: its text, and whether it was plain (unquoted, or tagged
    /// with a non-string core type).
    Scalar(String, bool),
    /// A sequence.
    Seq(Vec<Node>),
    /// A mapping, in order, each key once.
    Map(Vec<(String, Node)>),
    /// `!reference [job, key, …]`.
    Reference(Vec<String>),
}

impl Node {
    fn null() -> Self {
        Self::Scalar(String::new(), true)
    }

    /// The scalar's text.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Scalar(text, _) => Some(text),
            _ => None,
        }
    }

    /// A plain boolean, as GitLab's YAML 1.1 parser reads one: `true`,
    /// `yes`, `on` (and `false`, `no`, `off`) in any case.
    #[must_use]
    pub fn boolean(&self) -> Option<bool> {
        match self {
            Self::Scalar(text, true) => match text.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" => Some(true),
                "false" | "no" | "off" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Self::Scalar(text, true) if text.is_empty() || text == "~" || text.eq_ignore_ascii_case("null"))
    }

    /// A mapping's value for `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// A node with its size (in nodes) and depth, as the builder tracks them.
#[derive(Clone)]
struct Sized {
    node: Node,
    size: usize,
    depth: usize,
}

enum Frame {
    Seq(Vec<Node>, bool),
    /// Entries `(key, the key was plain, value)`, and a key awaiting its
    /// value.
    Map(Vec<(String, bool, Node)>, Option<(String, bool)>),
}

struct Open {
    frame: Frame,
    anchor: usize,
    /// The children's total size, and their greatest depth.
    size: usize,
    depth: usize,
}

/// One YAML stream's documents, built from yaml-rust2's events.
#[derive(Default)]
struct Builder {
    documents: Vec<Node>,
    stack: Vec<Open>,
    anchors: BTreeMap<usize, Sized>,
    /// Nodes built so far, each alias counting what it copies.
    nodes: usize,
    error: Option<String>,
}

impl Builder {
    fn fail(&mut self, why: String) {
        self.error.get_or_insert(why);
    }

    /// Counts `added` nodes against the budget.
    fn count(&mut self, added: usize) -> bool {
        self.nodes = self.nodes.saturating_add(added);
        if self.nodes > MAX_NODES {
            self.fail(format!("over {MAX_NODES} nodes (nested aliases expand)"));
            return false;
        }
        true
    }

    /// Whether a node `depth` deep fits where the stack stands.
    fn fits(&mut self, depth: usize) -> bool {
        if self.stack.len() + depth > MAX_DEPTH {
            self.fail(format!("nested past {MAX_DEPTH} levels"));
            return false;
        }
        true
    }

    fn open(&mut self, frame: Frame, anchor: usize) {
        if self.fits(1) && self.count(1) {
            self.stack.push(Open {
                frame,
                anchor,
                size: 0,
                depth: 0,
            });
        } else {
            // Keep the events balanced; the error stands.
            self.stack.push(Open {
                frame,
                anchor: 0,
                size: 0,
                depth: 0,
            });
        }
    }

    fn push(&mut self, sized: Sized, anchor: usize) {
        if anchor > 0 {
            self.anchors.insert(anchor, sized.clone());
        }
        let Some(open) = self.stack.last_mut() else {
            self.documents.push(sized.node);
            return;
        };
        open.size = open.size.saturating_add(sized.size);
        open.depth = open.depth.max(sized.depth);
        match &mut open.frame {
            Frame::Seq(items, _) => items.push(sized.node),
            Frame::Map(entries, key) => match key.take() {
                Some((text, plain)) => entries.push((text, plain, sized.node)),
                None => match sized.node {
                    Node::Scalar(text, plain) => *key = Some((text, plain)),
                    _ => self.fail("a mapping key that isn't a scalar".to_owned()),
                },
            },
        }
    }
}

/// Whether a scalar with `tag` is plain (a boolean, number or null can be
/// read from it), or why the tag is refused.
fn scalar_tag(tag: Option<&Tag>, plain: bool) -> Result<bool, String> {
    let Some(tag) = tag else { return Ok(plain) };
    if tag.handle == CORE_SCHEMA || tag.handle == "!!" {
        return match tag.suffix.as_str() {
            "str" | "binary" | "timestamp" => Ok(false),
            "bool" | "int" | "float" | "null" => Ok(true),
            other => Err(format!("a !!{other} scalar")),
        };
    }
    Err(format!("the tag {}{} on a scalar", tag.handle, tag.suffix))
}

fn is_reference(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "reference"
}

/// Whether a collection's tag is one GitLab reads (`!reference` on a
/// sequence, a core collection tag).
fn collection_tag(tag: Option<&Tag>, sequence: bool) -> Result<bool, String> {
    match tag {
        None => Ok(false),
        Some(tag) if sequence && is_reference(tag) => Ok(true),
        Some(tag)
            if (tag.handle == CORE_SCHEMA || tag.handle == "!!")
                && matches!(tag.suffix.as_str(), "seq" | "map" | "omap") =>
        {
            Ok(false)
        }
        Some(tag) => Err(format!("the tag {}{}", tag.handle, tag.suffix)),
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, event: Event, _mark: Marker) {
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                match scalar_tag(tag.as_ref(), style == TScalarStyle::Plain) {
                    Ok(plain) => {
                        if self.fits(1) && self.count(1) {
                            let node = Node::Scalar(text, plain);
                            self.push(
                                Sized {
                                    node,
                                    size: 1,
                                    depth: 1,
                                },
                                anchor,
                            );
                        }
                    }
                    Err(why) => self.fail(format!("{why}: GitLab reads only !reference")),
                }
            }
            Event::SequenceStart(anchor, tag) => match collection_tag(tag.as_ref(), true) {
                Ok(reference) => self.open(Frame::Seq(Vec::new(), reference), anchor),
                Err(why) => {
                    self.fail(format!("{why}: GitLab reads only !reference"));
                    self.open(Frame::Seq(Vec::new(), false), 0);
                }
            },
            Event::SequenceEnd => {
                if let Some(Open {
                    frame: Frame::Seq(items, reference),
                    anchor,
                    size,
                    depth,
                }) = self.stack.pop()
                {
                    let node = if reference {
                        match items.iter().map(Node::text).collect::<Option<Vec<_>>>() {
                            Some(path) => {
                                Node::Reference(path.into_iter().map(str::to_owned).collect())
                            }
                            None => {
                                self.fail("a !reference that isn't a list of names".to_owned());
                                Node::null()
                            }
                        }
                    } else {
                        Node::Seq(items)
                    };
                    self.push(
                        Sized {
                            node,
                            size: size + 1,
                            depth: depth + 1,
                        },
                        anchor,
                    );
                }
            }
            Event::MappingStart(anchor, tag) => match collection_tag(tag.as_ref(), false) {
                Ok(_) => self.open(Frame::Map(Vec::new(), None), anchor),
                Err(why) => {
                    self.fail(format!("{why}: GitLab reads only !reference"));
                    self.open(Frame::Map(Vec::new(), None), 0);
                }
            },
            Event::MappingEnd => {
                if let Some(Open {
                    frame: Frame::Map(entries, _),
                    anchor,
                    size,
                    depth,
                }) = self.stack.pop()
                {
                    self.push(
                        Sized {
                            node: psych_map(entries),
                            size: size + 1,
                            depth: depth + 1,
                        },
                        anchor,
                    );
                }
            }
            Event::Alias(id) => {
                let Some(anchored) = self.anchors.get(&id).cloned() else {
                    self.fail("an alias to an unknown anchor".to_owned());
                    return;
                };
                if self.fits(anchored.depth) && self.count(anchored.size) {
                    self.push(anchored, 0);
                }
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
    }
}

/// Sets `key` to `value` in `map`: in place when present (keeping its
/// position, as a Ruby hash does), appended otherwise.
fn set(map: &mut Vec<(String, Node)>, key: String, value: Node) {
    match map.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => map.push((key, value)),
    }
}

/// A mapping as Psych (GitLab's YAML parser) builds it, in document order:
/// a duplicate key's last value; a plain `<<` merges its mapping over the
/// keys before it (a list of mappings: the first wins), later keys over it.
fn psych_map(entries: Vec<(String, bool, Node)>) -> Node {
    let mut map = Vec::new();
    for (key, plain, value) in entries {
        if key == "<<" && plain {
            match value {
                Node::Map(merged) => {
                    for (k, v) in merged {
                        set(&mut map, k, v);
                    }
                }
                Node::Seq(items) if items.iter().all(|i| matches!(i, Node::Map(_))) => {
                    let mut merged = Vec::new();
                    for item in items.into_iter().rev() {
                        if let Node::Map(entries) = item {
                            for (k, v) in entries {
                                set(&mut merged, k, v);
                            }
                        }
                    }
                    for (k, v) in merged {
                        set(&mut map, k, v);
                    }
                }
                other => set(&mut map, key, other),
            }
        } else {
            set(&mut map, key, value);
        }
    }
    Node::Map(map)
}

/// Parses YAML text into its documents, as GitLab's parser reads them.
///
/// # Errors
/// [`DistError::Ci`] for text that isn't YAML, a tag GitLab doesn't read, or
/// past the size and depth bounds.
pub fn parse(text: &str, what: &str) -> Result<Vec<Node>, DistError> {
    let mut builder = Builder::default();
    let mut parser = Parser::new_from_str(text);
    parser
        .load(&mut builder, true)
        .map_err(|e| DistError::Ci(format!("{what}: not YAML: {e}")))?;
    if let Some(error) = builder.error {
        return Err(DistError::Ci(format!("{what}: {error}")));
    }
    Ok(builder.documents)
}

/// `base` with `over` deep-merged into it: mappings merge key by key,
/// anything else is replaced (GitLab's include and `extends` merge).
fn deep_merge(base: Node, over: Node) -> Node {
    match (base, over) {
        (Node::Map(mut base), Node::Map(over)) => {
            for (key, value) in over {
                match base.iter().position(|(k, _)| *k == key) {
                    Some(at) => {
                        let (_, old) = base.remove(at);
                        base.insert(at, (key, deep_merge(old, value)));
                    }
                    None => base.push((key, value)),
                }
            }
            Node::Map(base)
        }
        (_, over) => over,
    }
}

/// An include the lint couldn't read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Its kind and where it points (`project: acme/seaworthy`).
    pub source: String,
    /// The files it names (`ci/gitlab/seaworthy.yml`), if any.
    pub files: Vec<String>,
}

impl std::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.files.is_empty() {
            write!(f, "{}", self.source)
        } else {
            write!(f, "{} ({})", self.source, self.files.join(", "))
        }
    }
}

/// A product's CI configuration, merged and resolved.
#[derive(Debug, Clone, Default)]
pub struct Pipeline {
    /// The stages, in order.
    pub stages: Vec<String>,
    /// Every job (hidden ones included), `extends` and `!reference`
    /// resolved.
    pub jobs: BTreeMap<String, Node>,
    /// Includes that couldn't be read (another project, a URL, a GitLab
    /// template, a component).
    pub unresolved: Vec<Unresolved>,
}

/// Loads `ci` (a product's `.gitlab-ci.yml`, its local includes resolved
/// against `root`, the repository root) with `extra` files merged in
/// before it, as if included first. An `extra` file's own inputs are its
/// defaults, and empty for one without a default: it stands for an include
/// whose inputs the lint can't read.
///
/// # Errors
/// [`DistError::Ci`] for a file that can't be read or isn't YAML, an
/// include that escapes the repository, loops or has rules, an input
/// without a value, an `extends` or `!reference` that can't be resolved or
/// loops, or past GitLab's limits; [`DistError::Io`] for an unreadable file.
pub fn load(root: &Path, ci: &Path, extra: &[PathBuf]) -> Result<Pipeline, DistError> {
    let mut loader = Loader {
        root: root.to_path_buf(),
        count: 0,
        unresolved: Vec::new(),
        files: None,
        stand_in: true,
    };
    let mut merged = Node::Map(Vec::new());
    for file in extra {
        let node = loader.file(file, &BTreeMap::new(), &mut Vec::new())?;
        merged = deep_merge(merged, node);
    }
    loader.stand_in = false;
    let node = loader.file(ci, &BTreeMap::new(), &mut Vec::new())?;
    merged = deep_merge(merged, node);
    let Node::Map(entries) = merged else {
        return Err(DistError::Ci(format!(
            "{}: the configuration isn't a mapping",
            ci.display()
        )));
    };
    let is_job =
        |key: &str, value: &Node| !GLOBAL_KEYS.contains(&key) && matches!(value, Node::Map(_));
    // `extends` first, then `!reference` (GitLab's order).
    let raw: BTreeMap<&str, &Node> = entries
        .iter()
        .filter(|(k, v)| is_job(k, v))
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let mut extended_entries = Vec::with_capacity(entries.len());
    for (key, value) in &entries {
        let value = if is_job(key, value) {
            extended(&raw, key, &mut Vec::new())?
        } else {
            value.clone()
        };
        extended_entries.push((key.clone(), value));
    }
    let top = Node::Map(extended_entries);
    let resolved = resolve_references(&top, &top, 0)?;
    let stages = match resolved.get("stages") {
        Some(Node::Seq(items)) => items
            .iter()
            .filter_map(Node::text)
            .map(str::to_owned)
            .collect(),
        _ => ["build", "test", "deploy"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let Node::Map(entries) = resolved else {
        return Err(DistError::Ci(
            "the configuration isn't a mapping".to_owned(),
        ));
    };
    let jobs = entries.into_iter().filter(|(k, v)| is_job(k, v)).collect();
    Ok(Pipeline {
        stages,
        jobs,
        unresolved: loader.unresolved,
    })
}

/// An included file's inputs, by name.
type Inputs = BTreeMap<String, Node>;

struct Loader {
    root: PathBuf,
    count: usize,
    unresolved: Vec<Unresolved>,
    /// The repository's files a glob matches against, once listed.
    files: Option<Vec<String>>,
    /// Loading the further files given beside the CI file: each stands for
    /// an include whose inputs the lint can't see, so an input without a
    /// default reads as empty at its top level.
    stand_in: bool,
}

impl Loader {
    /// One file, its includes merged under it.
    fn file(
        &mut self,
        path: &Path,
        inputs: &Inputs,
        chain: &mut Vec<PathBuf>,
    ) -> Result<Node, DistError> {
        self.count += 1;
        if self.count > MAX_INCLUDES {
            return Err(DistError::Ci(format!(
                "more than {MAX_INCLUDES} CI files included (GitLab's limit)"
            )));
        }
        let canonical = std::fs::canonicalize(path).map_err(|e| DistError::io(path, e))?;
        if chain.contains(&canonical) {
            return Err(DistError::Ci(format!(
                "{} includes itself (through {})",
                path.display(),
                chain
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" → ")
            )));
        }
        let size = std::fs::metadata(&canonical)
            .map_err(|e| DistError::io(path, e))?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(DistError::Ci(format!(
                "{}: over {MAX_FILE_BYTES} bytes",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(&canonical).map_err(|e| DistError::io(path, e))?;
        let what = path.display().to_string();
        let mut documents = parse(&text, &what)?.into_iter();
        let body = match (documents.next(), documents.next(), documents.next()) {
            (None, ..) => Node::Map(Vec::new()),
            (Some(header), Some(body), None) if header.get("spec").is_some() => {
                let stand_in = self.stand_in && chain.is_empty();
                let values = input_values(&header, inputs, &what, stand_in)?;
                interpolate(&body, &values, &what)?
            }
            (Some(only), None, _) => {
                if !inputs.is_empty() {
                    return Err(DistError::Ci(format!(
                        "{what}: given inputs, but it has no spec: header"
                    )));
                }
                only
            }
            _ => {
                return Err(DistError::Ci(format!(
                    "{what}: more than one YAML document (only a `spec:` header may precede the configuration)"
                )));
            }
        };
        if !matches!(body, Node::Map(_)) && !body.is_null() {
            return Err(DistError::Ci(format!(
                "{what}: the configuration isn't a mapping"
            )));
        }
        chain.push(canonical);
        let mut merged = Node::Map(Vec::new());
        if let Some(include) = body.get("include") {
            let entries = match include {
                Node::Seq(items) => items.clone(),
                other => vec![other.clone()],
            };
            for entry in entries {
                for (file, inputs) in self.includes(&entry, &what)? {
                    let node = self.file(&file, &inputs, chain)?;
                    merged = deep_merge(merged, node);
                }
            }
        }
        chain.pop();
        let own = match body {
            Node::Map(entries) => Node::Map(
                entries
                    .into_iter()
                    .filter(|(k, _)| k != "include")
                    .collect(),
            ),
            _ => Node::Map(Vec::new()),
        };
        Ok(deep_merge(merged, own))
    }

    /// The local files one `include` entry names, with the inputs given
    /// to them; anything else is recorded as unresolved.
    fn includes(&mut self, entry: &Node, what: &str) -> Result<Vec<(PathBuf, Inputs)>, DistError> {
        let (local, inputs) = match entry {
            Node::Scalar(text, _) => {
                if text.contains("://") {
                    self.unresolved.push(Unresolved {
                        source: format!("remote: {text}"),
                        files: Vec::new(),
                    });
                    return Ok(Vec::new());
                }
                (text.clone(), BTreeMap::new())
            }
            Node::Map(entries) => {
                if entry.get("rules").is_some() {
                    return Err(DistError::Ci(format!(
                        "{what}: an include with rules: the lint can't tell when it applies (include it unconditionally, or guard its jobs with rules instead)"
                    )));
                }
                let inputs: Inputs = match entry.get("inputs") {
                    Some(Node::Map(values)) => values.iter().cloned().collect(),
                    _ => BTreeMap::new(),
                };
                match entry.get("local").and_then(Node::text) {
                    Some(local) => (local.to_owned(), inputs),
                    None => {
                        let source = entries
                            .iter()
                            .find(|(k, _)| {
                                matches!(
                                    k.as_str(),
                                    "project" | "remote" | "template" | "component"
                                )
                            })
                            .map_or_else(
                                || "an include of an unknown kind".to_owned(),
                                |(k, v)| format!("{k}: {}", v.text().unwrap_or("…")),
                            );
                        let files = match entry.get("file") {
                            Some(Node::Scalar(file, _)) => vec![file.clone()],
                            Some(Node::Seq(files)) => files
                                .iter()
                                .filter_map(Node::text)
                                .map(str::to_owned)
                                .collect(),
                            _ => Vec::new(),
                        };
                        self.unresolved.push(Unresolved { source, files });
                        return Ok(Vec::new());
                    }
                }
            }
            _ => {
                return Err(DistError::Ci(format!(
                    "{what}: an include that's neither a path nor a mapping"
                )));
            }
        };
        let files = self.glob(&local, what)?;
        if files.is_empty() {
            return Err(DistError::Ci(format!(
                "{what}: include {local:?} matches no file"
            )));
        }
        Ok(files.into_iter().map(|f| (f, inputs.clone())).collect())
    }

    /// The repository's files, relative and `/`-separated: those git
    /// tracks (GitLab reads the commit, not the working tree), else every
    /// file under the root (no directory links followed, `.git` skipped).
    fn files(&mut self) -> Result<&[String], DistError> {
        if self.files.is_none() {
            let tracked = std::process::Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(["ls-files", "-z", "--cached"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| {
                    o.stdout
                        .split(|b| *b == 0)
                        .filter(|p| !p.is_empty())
                        .map(|p| String::from_utf8_lossy(p).into_owned())
                        .collect::<Vec<_>>()
                });
            let files = match tracked {
                Some(files) => files,
                None => walk(&self.root)?,
            };
            if files.len() > MAX_LISTED_FILES {
                return Err(DistError::Ci(format!(
                    "over {MAX_LISTED_FILES} files to match includes against"
                )));
            }
            self.files = Some(files);
        }
        Ok(self.files.as_deref().unwrap_or_default())
    }

    /// The repository's files a local include names, sorted.
    fn glob(&mut self, pattern: &str, what: &str) -> Result<Vec<PathBuf>, DistError> {
        let relative = pattern.trim_start_matches('/');
        if relative.is_empty()
            || Path::new(relative)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(DistError::Ci(format!(
                "{what}: include {pattern:?} isn't a path inside the repository"
            )));
        }
        let root = std::fs::canonicalize(&self.root).map_err(|e| DistError::io(&self.root, e))?;
        let base = self.root.clone();
        let mut found: Vec<PathBuf> = self
            .files()?
            .iter()
            .filter(|f| glob_matches(relative.as_bytes(), f.as_bytes()))
            .map(|f| base.join(f))
            .collect();
        found.sort();
        for file in &found {
            let canonical = std::fs::canonicalize(file).map_err(|e| DistError::io(file, e))?;
            if !canonical.starts_with(&root) {
                return Err(DistError::Ci(format!(
                    "{what}: include {pattern:?} reaches {} outside the repository",
                    file.display()
                )));
            }
        }
        Ok(found)
    }
}

/// Every file under `root` (relative, `/`-separated): `.git` skipped, no
/// directory link followed.
fn walk(root: &Path) -> Result<Vec<String>, DistError> {
    let mut files = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = root.join(&relative);
        for entry in std::fs::read_dir(&dir).map_err(|e| DistError::io(&dir, e))? {
            let entry = entry.map_err(|e| DistError::io(&dir, e))?;
            let name = entry.file_name();
            if name == ".git" {
                continue;
            }
            let path = relative.join(&name);
            let kind = entry.file_type().map_err(|e| DistError::io(&path, e))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() || (kind.is_symlink() && root.join(&path).is_file()) {
                files.push(
                    path.components()
                        .map(|c| c.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
            if files.len() > MAX_LISTED_FILES {
                return Err(DistError::Ci(format!(
                    "over {MAX_LISTED_FILES} files to match includes against"
                )));
            }
        }
    }
    Ok(files)
}

/// `path` matches a GitLab include `pattern`: `**` matches any run of
/// characters, `/` included; `*` any run but `/`; the rest literally.
fn glob_matches(pattern: &[u8], path: &[u8]) -> bool {
    match pattern {
        [] => path.is_empty(),
        [b'*', b'*', rest @ ..] => {
            (0..=path.len()).any(|skip| glob_matches(rest, path.get(skip..).unwrap_or_default()))
        }
        [b'*', rest @ ..] => {
            let run = path.iter().position(|b| *b == b'/').unwrap_or(path.len());
            (0..=run).any(|skip| glob_matches(rest, path.get(skip..).unwrap_or_default()))
        }
        [first, rest @ ..] => {
            path.first() == Some(first) && glob_matches(rest, path.get(1..).unwrap_or_default())
        }
    }
}

/// The inputs' values: those given, else each input's default, else (for a
/// `stand_in` file, whose inputs the lint can't see) an empty value.
fn input_values(
    header: &Node,
    given: &Inputs,
    what: &str,
    stand_in: bool,
) -> Result<Inputs, DistError> {
    let mut values = BTreeMap::new();
    if let Some(Node::Map(inputs)) = header.get("spec").and_then(|s| s.get("inputs")) {
        for (name, spec) in inputs {
            let value = given
                .get(name)
                .cloned()
                .or_else(|| spec.get("default").cloned())
                .or_else(|| stand_in.then(|| Node::Scalar(String::new(), false)))
                .ok_or_else(|| {
                    DistError::Ci(format!(
                        "{what}: input {name:?} has no default and isn't given"
                    ))
                })?;
            values.insert(name.clone(), value);
        }
    }
    if let Some(unknown) = given.keys().find(|k| !values.contains_key(*k)) {
        return Err(DistError::Ci(format!(
            "{what}: no input {unknown:?} in its spec"
        )));
    }
    Ok(values)
}

/// The input an interpolation block (`$[[ inputs.NAME | … ]]`, functions
/// ignored) names, and where it ends.
fn interpolation<'a>(
    text: &str,
    values: &'a Inputs,
    what: &str,
) -> Result<Option<(usize, usize, &'a Node)>, DistError> {
    let Some(start) = text.find("$[[") else {
        return Ok(None);
    };
    let after = &text[start + 3..];
    let Some(end) = after.find("]]") else {
        return Err(DistError::Ci(format!("{what}: an unterminated $[[ … ]]")));
    };
    let expression = after[..end].trim();
    let name = expression
        .split('|')
        .next()
        .unwrap_or_default()
        .trim()
        .strip_prefix("inputs.")
        .ok_or_else(|| DistError::Ci(format!("{what}: $[[ {expression} ]] isn't an input")))?;
    let value = values
        .get(name)
        .ok_or_else(|| DistError::Ci(format!("{what}: $[[ {expression} ]] names no input")))?;
    Ok(Some((start, start + 3 + end + 2, value)))
}

/// `text` with every interpolation block replaced by its value's text (a
/// list or mapping in flow style).
fn interpolate_text(text: &str, values: &Inputs, what: &str) -> Result<String, DistError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((start, end, value)) = interpolation(rest, values, what)? {
        out.push_str(&rest[..start]);
        out.push_str(&flow(value));
        rest = &rest[end..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The parsed configuration with its inputs filled in, as GitLab fills
/// them after parsing: a value that's one interpolation block becomes the
/// input's value (its type kept); any other interpolation, text.
fn interpolate(node: &Node, values: &Inputs, what: &str) -> Result<Node, DistError> {
    Ok(match node {
        Node::Scalar(text, _) => {
            if !text.contains("$[[") {
                return Ok(node.clone());
            }
            let trimmed = text.trim();
            match interpolation(trimmed, values, what)? {
                Some((0, end, value)) if end == trimmed.len() => value.clone(),
                // Partial: text, never a boolean or number.
                _ => Node::Scalar(interpolate_text(text, values, what)?, false),
            }
        }
        Node::Seq(items) => Node::Seq(
            items
                .iter()
                .map(|i| interpolate(i, values, what))
                .collect::<Result<_, _>>()?,
        ),
        Node::Map(entries) => {
            let mut map = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                set(
                    &mut map,
                    interpolate_text(key, values, what)?,
                    interpolate(value, values, what)?,
                );
            }
            Node::Map(map)
        }
        Node::Reference(path) => Node::Reference(
            path.iter()
                .map(|p| interpolate_text(p, values, what))
                .collect::<Result<_, _>>()?,
        ),
    })
}

/// A value as inline text.
fn flow(node: &Node) -> String {
    match node {
        Node::Scalar(text, _) => text.clone(),
        Node::Seq(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| match item {
                    Node::Scalar(text, _) => {
                        serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
                    }
                    other => flow(other),
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Node::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!(
                    "{}: {}",
                    serde_json::to_string(k).unwrap_or_else(|_| "\"\"".to_owned()),
                    flow(v)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Node::Reference(path) => format!("!reference [{}]", path.join(", ")),
    }
}

/// `node` with every `!reference` replaced by what it names in `top` (a
/// sequence's references to sequences spliced in, as GitLab does).
fn resolve_references(node: &Node, top: &Node, depth: usize) -> Result<Node, DistError> {
    if depth > MAX_REFERENCE_DEPTH {
        return Err(DistError::Ci(format!(
            "!reference nested past {MAX_REFERENCE_DEPTH} levels (GitLab's limit)"
        )));
    }
    match node {
        Node::Reference(path) => {
            let mut target = top;
            for key in path {
                target = target.get(key).ok_or_else(|| {
                    DistError::Ci(format!("!reference [{}] names nothing", path.join(", ")))
                })?;
            }
            resolve_references(target, top, depth + 1)
        }
        Node::Seq(items) => {
            let mut out = Vec::new();
            for item in items {
                let resolved = resolve_references(item, top, depth)?;
                match (item, resolved) {
                    (Node::Reference(_), Node::Seq(spliced)) => out.extend(spliced),
                    (_, resolved) => out.push(resolved),
                }
            }
            Ok(Node::Seq(out))
        }
        Node::Map(entries) => Ok(Node::Map(
            entries
                .iter()
                .map(|(k, v)| Ok((k.clone(), resolve_references(v, top, depth)?)))
                .collect::<Result<_, DistError>>()?,
        )),
        Node::Scalar(..) => Ok(node.clone()),
    }
}

/// Job `name` with its `extends` applied: each parent in order (itself
/// extended), then the job's own keys.
fn extended(
    raw: &BTreeMap<&str, &Node>,
    name: &str,
    chain: &mut Vec<String>,
) -> Result<Node, DistError> {
    if chain.iter().any(|c| c == name) {
        return Err(DistError::Ci(format!(
            "job {name:?} extends itself (through {})",
            chain.join(" → ")
        )));
    }
    // `chain` holds the jobs extending this one: eleven levels of
    // inheritance allowed, as GitLab allows.
    if chain.len() > MAX_EXTENDS_DEPTH {
        return Err(DistError::Ci(format!(
            "job {name:?}: extends nested past {MAX_EXTENDS_DEPTH} levels (GitLab's limit)"
        )));
    }
    let job = raw.get(name).ok_or_else(|| {
        DistError::Ci(format!(
            "{} extends {name:?}, which isn't defined",
            chain.last().map_or("a job", String::as_str)
        ))
    })?;
    let parents: Vec<String> = match job.get("extends") {
        None => Vec::new(),
        Some(Node::Scalar(text, _)) => vec![text.clone()],
        Some(Node::Seq(items)) => items
            .iter()
            .map(|i| {
                i.text()
                    .map(str::to_owned)
                    .ok_or_else(|| DistError::Ci(format!("job {name:?}: extends lists a non-name")))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => {
            return Err(DistError::Ci(format!(
                "job {name:?}: extends is neither a name nor a list"
            )));
        }
    };
    chain.push(name.to_owned());
    let mut merged = Node::Map(Vec::new());
    for parent in &parents {
        merged = deep_merge(merged, extended(raw, parent, chain)?);
    }
    chain.pop();
    let own = match job {
        Node::Map(entries) => Node::Map(
            entries
                .iter()
                .filter(|(k, _)| k != "extends")
                .cloned()
                .collect(),
        ),
        _ => Node::Map(Vec::new()),
    };
    Ok(deep_merge(merged, own))
}

/// One `needs` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Need {
    /// A job of this pipeline: whether optional, and whether only some of
    /// its `parallel: matrix` jobs.
    Job {
        name: String,
        optional: bool,
        partial: bool,
    },
    /// Another pipeline's or project's job: no order in this pipeline.
    Elsewhere,
}

/// A `needs` value: `None` when absent (stage order).
fn needs_of(list: Option<&Node>) -> Option<Vec<Need>> {
    let list = list?;
    let items = match list {
        Node::Seq(items) => items.clone(),
        other if other.is_null() => Vec::new(),
        other => vec![other.clone()],
    };
    Some(
        items
            .iter()
            .map(|item| match item {
                Node::Scalar(text, _) => Need::Job {
                    name: text.clone(),
                    optional: false,
                    partial: false,
                },
                map @ Node::Map(_)
                    if map.get("pipeline").is_none() && map.get("project").is_none() =>
                {
                    match map.get("job").and_then(Node::text) {
                        Some(name) => Need::Job {
                            name: name.to_owned(),
                            optional: map.get("optional").and_then(Node::boolean) == Some(true),
                            partial: map.get("parallel").is_some(),
                        },
                        None => Need::Elsewhere,
                    }
                }
                _ => Need::Elsewhere,
            })
            .collect(),
    )
}

/// The job's rules.
fn rules(job: &Node) -> Vec<&Node> {
    match job.get("rules") {
        Some(Node::Seq(items)) => items.iter().collect(),
        _ => Vec::new(),
    }
}

/// The needs a job can run with: the job's own, or with rules, each
/// runnable rule's (a rule's `needs` replaces the job's when it matches).
fn variants(job: &Node) -> Vec<Option<Vec<Need>>> {
    let own = needs_of(job.get("needs"));
    let runnable: Vec<Option<Vec<Need>>> = rules(job)
        .into_iter()
        .filter(|rule| rule.get("when").and_then(Node::text) != Some("never"))
        .map(|rule| match rule.get("needs") {
            Some(list) => needs_of(Some(list)),
            None => own.clone(),
        })
        .collect();
    if runnable.is_empty() {
        vec![own]
    } else {
        runnable
    }
}

/// The jobs `job` waits for whichever way it runs: in every variant's
/// explicit, non-optional, whole needs.
fn guaranteed(job: &Node) -> BTreeSet<String> {
    let mut sets = variants(job).into_iter().map(|variant| {
        variant
            .unwrap_or_default()
            .into_iter()
            .filter_map(|need| match need {
                Need::Job {
                    name,
                    optional: false,
                    partial: false,
                } => Some(name),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
    });
    let first = sets.next().unwrap_or_default();
    sets.fold(first, |all, set| all.intersection(&set).cloned().collect())
}

/// Whether `job` runs past failed needs: `when: always` or `on_failure`, in
/// the job or any rule.
fn runs_past_failure(job: &Node) -> bool {
    let past = |when: Option<&str>| matches!(when, Some("always" | "on_failure"));
    past(job.get("when").and_then(Node::text))
        || rules(job)
            .iter()
            .any(|rule| past(rule.get("when").and_then(Node::text)))
}

/// Whether an `allow_failure` value lets the job fail: true, or exit codes.
fn allows_failure(value: &Node) -> bool {
    value.boolean() == Some(true) || matches!(value, Node::Map(_))
}

/// Why client job `job` could fail without stopping a server deploy.
fn client_problems(name: &str, job: &Node) -> Vec<String> {
    let mut problems = Vec::new();
    let manual = job.get("when").and_then(Node::text) == Some("manual");
    match job.get("allow_failure") {
        Some(value) if allows_failure(value) => problems.push(format!(
            "client job {name:?} is allowed to fail (allow_failure): a server deploy would go on past its failure"
        )),
        None if manual => problems.push(format!(
            "client job {name:?} is manual, and a manual job outside rules is allowed to fail by default: set allow_failure: false"
        )),
        _ => {}
    }
    if rules(job)
        .iter()
        .any(|rule| rule.get("allow_failure").is_some_and(allows_failure))
    {
        problems.push(format!(
            "client job {name:?} has a rule that allows it to fail: a server deploy would go on past its failure"
        ));
    }
    if let Some(trigger) = job.get("trigger")
        && !matches!(
            trigger.get("strategy").and_then(Node::text),
            Some("depend" | "mirror")
        )
    {
        problems.push(format!(
            "client job {name:?} triggers a pipeline without strategy: depend (or mirror): it succeeds as soon as the child pipeline is created"
        ));
    }
    problems
}

/// What the check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Each server job and the client jobs it waits for, when all is well.
    pub ordered: Vec<(String, Vec<String>)>,
    /// What's wrong, one finding per line.
    pub findings: Vec<String>,
}

/// Checks that every server job in `servers` waits for every client job
/// in `clients` (the module docs give the rules).
#[must_use]
pub fn check(pipeline: &Pipeline, servers: &[String], clients: &[String]) -> Report {
    let mut report = Report::default();
    let defined = |name: &str| -> Option<&Node> {
        if name.starts_with('.') {
            None
        } else {
            pipeline.jobs.get(name)
        }
    };
    for client in clients {
        match defined(client) {
            Some(job) => report.findings.extend(client_problems(client, job)),
            None => report.findings.push(format!(
                "no client job {client:?} in the configuration{}",
                unresolved_hint(pipeline)
            )),
        }
    }
    for server in servers {
        let Some(job) = defined(server) else {
            report.findings.push(format!(
                "no server job {server:?} in the configuration{}",
                unresolved_hint(pipeline)
            ));
            continue;
        };
        if runs_past_failure(job) {
            report.findings.push(format!(
                "server job {server:?} runs when: always or on_failure (in the job or a rule): it would deploy past failed needs"
            ));
        }
        let reached = reachable(pipeline, server, true);
        let through_any = reachable(pipeline, server, false);
        let mut waits = Vec::new();
        for client in clients {
            if client == server {
                continue;
            }
            if reached.contains(client.as_str()) {
                waits.push(client.clone());
                continue;
            }
            let why = if through_any.contains(client.as_str()) {
                "waits for it only through a job that runs when: always or on_failure, which goes on past a failed client".to_owned()
            } else {
                unreached_reason(job, client)
            };
            report.findings.push(format!(
                "server job {server:?} can deploy before client job {client:?}: it {why} — add {client:?} to its needs"
            ));
        }
        report.ordered.push((server.clone(), waits));
    }
    report
}

/// Why server job `job` doesn't reach `client`, from its needs.
fn unreached_reason(job: &Node, client: &str) -> String {
    let ruled = rules(job).iter().any(|rule| rule.get("needs").is_some());
    let suffix = if ruled {
        " (counting every rule's needs, which replace the job's when the rule matches)"
    } else {
        ""
    };
    for variant in variants(job) {
        let reason = match variant {
            None => {
                "has no needs, so it waits only by stage order, which skips a job a rule leaves out of the pipeline"
            }
            Some(list) if list.is_empty() => "has needs: [], so it starts at once",
            Some(list) => match list.iter().find_map(|n| match n {
                Need::Job {
                    name,
                    optional,
                    partial,
                } if name == client => Some((*optional, *partial)),
                _ => None,
            }) {
                Some((true, _)) => "needs it only with optional: true",
                Some((_, true)) => "needs only some of its parallel: matrix jobs",
                Some(_) => continue,
                None => "doesn't need it, directly or through its needs",
            },
        };
        return format!("{reason}{suffix}");
    }
    format!("doesn't need it, directly or through its needs{suffix}")
}

fn unresolved_hint(pipeline: &Pipeline) -> String {
    if pipeline.unresolved.is_empty() {
        String::new()
    } else {
        format!(
            " (includes not read: {}; pass the file defining it)",
            pipeline
                .unresolved
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Every job `from` waits for through needs it has whichever way it runs,
/// transitively; with `strict`, never through a job that runs past failed
/// needs.
fn reachable<'a>(pipeline: &'a Pipeline, from: &str, strict: bool) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([from.to_owned()]);
    while let Some(name) = queue.pop_front() {
        let Some(job) = pipeline.jobs.get(&name) else {
            continue;
        };
        if strict && name != from && runs_past_failure(job) {
            continue;
        }
        for need in guaranteed(job) {
            if let Some((key, _)) = pipeline.jobs.get_key_value(&need)
                && seen.insert(key.as_str())
            {
                queue.push_back(need);
            }
        }
    }
    seen
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_as_gitlab_matches() {
        for (pattern, path, matches) in [
            ("ci/*.yml", "ci/deploy.yml", true),
            ("ci/*.yml", "ci/sub/deploy.yml", false),
            ("ci/*.yml", "ci/deploy.yaml", false),
            ("ci/**/*.yml", "ci/sub/deploy.yml", true),
            ("ci/**/*.yml", "ci/a/b/deploy.yml", true),
            ("ci/**/*.yml", "ci/top.yml", false),
            ("ci/**.yml", "ci/top.yml", true),
            ("ci/**.yml", "ci/sub/deploy.yml", true),
            ("ci/build-*", "ci/build-linux", true),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "acb", false),
            ("exact.yml", "exact.yml", true),
            ("exact.yml", "exact.yml.bak", false),
        ] {
            assert_eq!(
                glob_matches(pattern.as_bytes(), path.as_bytes()),
                matches,
                "{pattern} {path}"
            );
        }
    }

    #[test]
    fn merge_keys_and_duplicates_follow_document_order() {
        // The mapping's own keys after a merge win...
        let docs = parse(
            "a: &base {x: 1, y: 2}\nb:\n  <<: *base\n  y: 3\n  z: 4\n",
            "t",
        )
        .unwrap();
        assert_eq!(
            docs[0].get("b").unwrap(),
            &Node::Map(vec![
                ("x".into(), Node::Scalar("1".into(), true)),
                ("y".into(), Node::Scalar("3".into(), true)),
                ("z".into(), Node::Scalar("4".into(), true)),
            ])
        );
        // ...a merge after them overwrites them; in a list, the first wins;
        // a duplicate key keeps its last value; a quoted "<<" is a key.
        let docs = parse(
            "a: &a {x: 1}\nb: &b {x: 2, y: 2}\n\
             c: {x: 0, <<: *a}\nd: {<<: [*a, *b]}\ne: {x: 1, x: 2}\nf: {'<<': *a}\n",
            "t",
        )
        .unwrap();
        let x = |job: &str| docs[0].get(job).unwrap().get("x").and_then(Node::text);
        assert_eq!(x("c"), Some("1"));
        assert_eq!(x("d"), Some("1"));
        assert_eq!(
            docs[0].get("d").unwrap().get("y").and_then(Node::text),
            Some("2")
        );
        assert_eq!(x("e"), Some("2"));
        assert!(docs[0].get("f").unwrap().get("<<").is_some());
    }

    #[test]
    fn deep_merges_replace_arrays_and_merge_mappings() {
        let a = parse("j: {needs: [a, b], variables: {X: 1, Y: 2}}", "a").unwrap();
        let b = parse("j: {needs: [c], variables: {Y: 3}}", "b").unwrap();
        let merged = deep_merge(a[0].clone(), b[0].clone());
        let job = merged.get("j").unwrap();
        assert_eq!(
            job.get("needs").unwrap(),
            &Node::Seq(vec![Node::Scalar("c".into(), true)])
        );
        assert_eq!(
            job.get("variables").unwrap(),
            &Node::Map(vec![
                ("X".into(), Node::Scalar("1".into(), true)),
                ("Y".into(), Node::Scalar("3".into(), true)),
            ])
        );
    }

    #[test]
    fn inputs_fill_the_parsed_configuration() {
        let values = BTreeMap::from([
            ("name".to_owned(), Node::Scalar("deploy".into(), false)),
            (
                "jobs".to_owned(),
                Node::Seq(vec![
                    Node::Scalar("a".into(), true),
                    Node::Scalar("b c".into(), false),
                ]),
            ),
            ("flag".to_owned(), Node::Scalar("true".into(), true)),
            ("letter".to_owned(), Node::Scalar("n".into(), true)),
            (
                "evil".to_owned(),
                Node::Scalar("x\nneeds: []".into(), false),
            ),
        ]);
        let docs = parse(
            "# not $[[ inputs.missing ]] in a comment\n\
             s: $[[ inputs.name ]]\nl: $[[inputs.jobs | expand_vars]]\n\
             p: pre-$[[ inputs.name ]]-post\nb: $[[ inputs.flag ]]\ne: $[[ inputs.evil ]]\n\
             o: o$[[ inputs.letter ]]\n$[[ inputs.name ]]-job: k\n",
            "t",
        )
        .unwrap();
        let filled = interpolate(&docs[0], &values, "t").unwrap();
        assert_eq!(filled.get("s").and_then(Node::text), Some("deploy"));
        assert_eq!(filled.get("l"), values.get("jobs"));
        assert_eq!(
            filled.get("p").and_then(Node::text),
            Some("pre-deploy-post")
        );
        assert_eq!(filled.get("b").and_then(Node::boolean), Some(true));
        // A partial interpolation is text, even spelling a boolean.
        assert_eq!(filled.get("o").and_then(Node::text), Some("on"));
        assert_eq!(filled.get("o").and_then(Node::boolean), None);
        // Keys too (a job named from an input).
        assert_eq!(filled.get("deploy-job").and_then(Node::text), Some("k"));
        // An input's text never becomes structure.
        assert_eq!(filled.get("e").and_then(Node::text), Some("x\nneeds: []"));
        assert!(filled.get("needs").is_none());
        for bad in [
            "x: $[[ inputs.other ]]",
            "x: $[[ env.HOME ]]",
            "x: '$[[ inputs.name'",
        ] {
            let docs = parse(bad, "t").unwrap();
            assert!(interpolate(&docs[0], &values, "t").is_err(), "{bad}");
        }
    }

    #[test]
    fn scalars_read_as_gitlab_s_yaml_1_1_parser_reads_them() {
        let docs = parse(
            "a: true\nb: 'true'\nc: ~\nd: yes\ne: ON\nf: No\ng: !!bool \"true\"\nh: !!str yes\ni: NULL\n",
            "t",
        )
        .unwrap();
        let get = |k: &str| docs[0].get(k).unwrap();
        assert_eq!(get("a").boolean(), Some(true));
        assert_eq!(get("b").boolean(), None);
        assert!(get("c").is_null());
        assert_eq!(get("d").boolean(), Some(true));
        assert_eq!(get("e").boolean(), Some(true));
        assert_eq!(get("f").boolean(), Some(false));
        assert_eq!(get("g").boolean(), Some(true));
        assert_eq!(get("h").boolean(), None);
        assert!(get("i").is_null());
        for bad in [
            "a: !custom x\n",
            "a: !custom [x]\n",
            "a: !reference x\n",
            // GitLab's tag is the local `!reference`, not the core schema's.
            "a: !!reference [x, y]\n",
            "a: !!python/object {}\n",
        ] {
            let err = parse(bad, "t").unwrap_err().to_string();
            assert!(err.contains("GitLab reads only !reference"), "{bad}: {err}");
        }
    }

    #[test]
    fn nested_aliases_and_deep_nesting_are_bounded() {
        // Ten levels of ten aliases each: 10^10 nodes if expanded.
        let mut text = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for n in 1..10 {
            let p = n - 1;
            text.push_str(&format!(
                "a{n}: &a{n} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        let err = parse(&text, "t").unwrap_err().to_string();
        assert!(err.contains("nodes (nested aliases expand)"), "{err}");
        // A chain of aliases, each nesting the last: deep once expanded.
        let mut chain = String::from("a0: &a0 [x]\n");
        for n in 1..200 {
            chain.push_str(&format!("a{n}: &a{n} [*a{}]\n", n - 1));
        }
        let err = parse(&chain, "t").unwrap_err().to_string();
        assert!(err.contains("nested past 128 levels"), "{err}");
        let deep = format!("a: {}{}\n", "[".repeat(200), "]".repeat(200));
        let err = parse(&deep, "t").unwrap_err().to_string();
        assert!(err.contains("nested past 128 levels"), "{err}");
        assert!(parse(&format!("a: {}{}\n", "[".repeat(100), "]".repeat(100)), "t").is_ok());
    }
}
