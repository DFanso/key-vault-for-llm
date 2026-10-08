//! How `exec` finds the program to run. Its own test binary, because one
//! test changes the working directory.

use std::path::{Path, PathBuf};

use kv::broker::exec::resolve;

fn tool(dir: &Path, name: &str) -> PathBuf {
    let file = dir.join(if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    });
    std::fs::write(&file, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    file
}

#[test]
fn bare_names_are_found_on_absolute_path_entries_only() {
    let base = tempfile::TempDir::new().unwrap();
    let bin = base.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let expected = tool(&bin, "terraform");
    let path = std::env::join_paths([PathBuf::from("relative"), bin.clone()]).unwrap();
    assert_eq!(resolve("terraform", Some(&path)), Some(expected));

    let relative_only = std::env::join_paths([PathBuf::from("bin")]).unwrap();
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(base.path()).unwrap();
    let found = resolve("terraform", Some(&relative_only));
    std::env::set_current_dir(cwd).unwrap();
    assert_eq!(found, None);
}

#[test]
fn relative_paths_with_a_directory_are_never_run() {
    assert_eq!(resolve("./terraform", None), None);
    assert_eq!(resolve("bin/terraform", None), None);
}

#[test]
fn absolute_paths_are_used_as_given() {
    let base = tempfile::TempDir::new().unwrap();
    let file = tool(base.path(), "deploy");
    assert_eq!(resolve(file.to_str().unwrap(), None), Some(file.clone()));
    assert_eq!(
        resolve(base.path().join("missing").to_str().unwrap(), None),
        None
    );
}

#[cfg(unix)]
#[test]
fn files_without_execute_permission_are_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::TempDir::new().unwrap();
    let first = base.path().join("a");
    let second = base.path().join("b");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let plain = first.join("tool");
    std::fs::write(&plain, b"").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let runnable = tool(&second, "tool");
    let path = std::env::join_paths([first, second]).unwrap();
    assert_eq!(resolve("tool", Some(&path)), Some(runnable));
}
