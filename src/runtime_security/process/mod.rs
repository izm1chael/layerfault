use crate::runtime_security::RuntimeProcess;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub fn enumerate() -> Vec<RuntimeProcess> {
    #[cfg(target_os = "linux")]
    {
        return linux::enumerate();
    }
    #[cfg(target_os = "macos")]
    {
        return macos::enumerate();
    }
    #[cfg(windows)]
    {
        return windows::enumerate();
    }
    #[allow(unreachable_code)]
    Vec::new()
}
