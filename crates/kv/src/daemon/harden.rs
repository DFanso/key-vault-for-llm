//! Keeps secrets out of core dumps and, on Linux, stops other processes
//! running as the same user from attaching a debugger or reading the
//! daemon's memory through /proc.

pub fn apply() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}
