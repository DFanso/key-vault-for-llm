//! What kv accepts in an `env` handle, and how big any secret value may be.
//!
//! The variables of an `env` handle are given to a program kv starts, so a
//! name can do more than carry a secret: `NODE_OPTIONS` or `LD_PRELOAD` make
//! the program load code, a proxy or package-index variable sends its traffic
//! elsewhere. The list here is not exhaustive; it names the families that
//! change how a program runs or where it connects, and kv refuses them in a
//! share while only warning about them in a handle the user makes.

/// The longest secret value, token or URL kv takes, in bytes. Service-
/// account JSON (about 2.4 KB) and an RSA-4096 PEM (about 3.3 KB) fit.
pub const MAX_VALUE_LEN: usize = 4096;

/// Most bytes of values in one `env` handle. The scrubber's cost is linear
/// in the values now (`scrub::MAX_TOTAL_COST` bounds the vault as a whole);
/// this keeps any one handle, which a share may deliver, to a small part of
/// that budget. Two 4096-byte values of punctuation, the most one handle
/// can cost, measured 28 MB and 0.08 s to build in a release build.
pub const MAX_VALUES_LEN: usize = 8 * 1024;

/// Most variables in one `env` handle.
pub const MAX_ENV_VARS: usize = 256;

/// Longest variable name, in bytes.
pub const MAX_ENV_NAME_LEN: usize = 128;

/// Why `name` cannot be an environment variable's name, if it cannot: it
/// starts with a letter or `_` and holds letters, digits and `_`. The
/// message names it, made safe to show.
pub fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("variable names cannot be empty".into());
    }
    if name.len() > MAX_ENV_NAME_LEN {
        return Some(format!(
            "the variable name {} is longer than 128 characters",
            shown(name)
        ));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Some(format!(
            "{} is not a variable name: names start with a letter or _ and hold only \
             letters, digits and _",
            shown(name)
        ));
    }
    None
}

/// A variable name as a message may show it: someone else may have picked
/// it, so anything but letters, digits and `_` becomes `?`, and it is cut
/// at 64 characters.
pub fn shown(name: &str) -> String {
    let mut out: String = name
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if name.chars().count() > 64 {
        out.push_str("...");
    }
    out
}

/// Names that change how a program runs or where it connects.
const RISKY: &[&str] = &[
    // Where programs and libraries are found, and what a shell runs.
    "PATH",
    "HOME",
    "SHELL",
    "IFS",
    "CDPATH",
    "SHELLOPTS",
    "BASHOPTS",
    "BASH_ENV",
    "PROMPT_COMMAND",
    "PS4",
    "ZDOTDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "MANPAGER",
    "LESSOPEN",
    // Windows: what runs a command, and which extensions run.
    "COMSPEC",
    "PATHEXT",
    // Language runtimes and build tools that load code or flags from the
    // environment, or fetch from where it says.
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "PYTHONBREAKPOINT",
    "PYTHONEXECUTABLE",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_HOME",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
    "DOTNET_STARTUP_HOOKS",
    "CORECLR_ENABLE_PROFILING",
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "GOFLAGS",
    "GOPROXY",
    "GOSUMDB",
    "GONOSUMDB",
    "GONOSUMCHECK",
    "GOINSECURE",
    "GOPRIVATE",
    "GONOPROXY",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_HOME",
    // Tools that run a command or read a config the variable names.
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_PROXY_COMMAND",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_TEMPLATE_DIR",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "KUBECONFIG",
    // Certificates, so traffic can be read.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
];

/// Families of names, by prefix: dynamic loaders, package managers' settings
/// (an index, registry or mirror to install from), git's config, exported
/// shell functions, .NET profilers, AWS endpoints.
const RISKY_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "NPM_CONFIG_",
    "YARN_",
    "BUNDLE_",
    "PIP_",
    "UV_",
    "GIT_CONFIG",
    "BASH_FUNC_",
    "CORECLR_PROFILER",
    "AWS_ENDPOINT_URL",
];

/// Whether `name` is one kv does not let a share set. Case does not matter:
/// `npm_config_registry` and `NPM_CONFIG_REGISTRY` are both read.
pub fn is_risky(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    RISKY.contains(&upper.as_str())
        || RISKY_PREFIXES.iter().any(|p| upper.starts_with(p))
        || upper.ends_with("_PROXY")
        // A program cargo runs each target binary through.
        || (upper.starts_with("CARGO_TARGET_") && upper.ends_with("_RUNNER"))
}

/// The names in `names` that are risky, in order.
pub fn risky<'a>(names: impl IntoIterator<Item = &'a String>) -> Vec<&'a str> {
    names
        .into_iter()
        .map(String::as_str)
        .filter(|name| is_risky(name))
        .collect()
}

/// Names for a message, each made safe to show: the first few, then how
/// many more.
pub fn list(names: &[&str]) -> String {
    const SHOWN: usize = 8;
    let mut text = names
        .iter()
        .take(SHOWN)
        .map(|name| shown(name))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        text.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked_for_shape() {
        assert_eq!(name_problem("DATABASE_URL"), None);
        assert_eq!(name_problem("_x1"), None);
        for bad in ["", "1X", "A-B", "A B", "A=B", "A\0B", "é", "A.B"] {
            assert!(name_problem(bad).is_some(), "{bad:?}");
        }
        assert!(name_problem(&"A".repeat(129)).is_some());
        assert_eq!(name_problem(&"A".repeat(128)), None);
    }

    #[test]
    fn loader_runtime_and_proxy_names_are_risky_in_any_case() {
        for name in [
            "LD_PRELOAD",
            "ld_library_path",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "Path",
            "NODE_OPTIONS",
            "BASH_ENV",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_COUNT",
            "npm_config_registry",
            "NPM_CONFIG_USERCONFIG",
            "UV_DEFAULT_INDEX",
            "PIP_INDEX_URL",
            "HTTPS_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "SSL_CERT_FILE",
            "KUBECONFIG",
            "PYTHONSTARTUP",
            "BASH_FUNC_x%%",
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_S3",
            "YARN_NPM_REGISTRY_SERVER",
            "BUNDLE_MIRROR__ALL",
            "GOPROXY",
            "DOTNET_STARTUP_HOOKS",
            "CORECLR_PROFILER_PATH",
            "COR_PROFILER",
            "MAVEN_OPTS",
            "GRADLE_OPTS",
            "JAVA_HOME",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "PATHEXT",
            "ComSpec",
            "HOME",
            "EDITOR",
        ] {
            assert!(is_risky(name), "{name}");
        }
    }

    #[test]
    fn ordinary_secrets_and_settings_are_not_risky() {
        for name in [
            "DATABASE_URL",
            "STRIPE_SECRET_KEY",
            "OPENAI_API_KEY",
            "NODE_ENV",
            "PYTHONUNBUFFERED",
            "LOG_LEVEL",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_REGION",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_TARGET_DIR",
            "PORT",
            "ENV",
        ] {
            assert!(!is_risky(name), "{name}");
        }
    }

    #[test]
    fn names_from_someone_else_are_shown_safely() {
        assert_eq!(shown("NODE_OPTIONS"), "NODE_OPTIONS");
        assert_eq!(shown("A\u{1b}[31mB"), "A??31mB");
        assert!(shown(&"A".repeat(100)).ends_with("..."));
        assert!(name_problem("A\nB").unwrap().starts_with("A?B is not"));
        assert_eq!(list(&["X\nY"]), "X?Y");
    }

    #[test]
    fn lists_stay_short() {
        let names: Vec<&str> = (0..12).map(|_| "X").collect();
        assert_eq!(list(&names[..2]), "X, X");
        assert!(list(&names).ends_with("and 4 more"));
    }
}
