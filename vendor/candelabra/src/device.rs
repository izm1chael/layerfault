//! Hardware detection and device management with automatic fallback.

use crate::CandelabraError;
use candle_core::Device;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The type of compute device available for inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// Apple Metal GPU (macOS)
    Metal,
    /// NVIDIA CUDA GPU
    Cuda,
    /// CPU fallback
    Cpu,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Metal => write!(f, "Metal GPU"),
            DeviceType::Cuda => write!(f, "CUDA GPU"),
            DeviceType::Cpu => write!(f, "CPU"),
        }
    }
}

/// Returns the best available compute device with automatic fallback.
///
/// Priority order:
/// 1. Metal (macOS) - if the `metal` feature is enabled and creation succeeds
/// 2. CUDA - if the `cuda` feature is enabled and creation succeeds
/// 3. CPU - always available as fallback
pub fn get_best_device() -> (Device, DeviceType) {
    #[cfg(target_os = "macos")]
    {
        match try_metal_device() {
            Ok(Some(device)) => return device,
            Ok(None) => {}
            Err(e) => eprintln!("Metal device setup failed, falling back: {}", e),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        match try_cuda_device() {
            Ok(Some(device)) => return device,
            Ok(None) => {}
            Err(e) => eprintln!("CUDA device setup failed, falling back: {}", e),
        }
    }

    (Device::Cpu, DeviceType::Cpu)
}

/// Returns the best available compute device with detailed error information.
///
/// Unlike `get_best_device`, this function returns an error if a preferred
/// device type is explicitly requested but unavailable.
pub fn get_device(preferred: Option<DeviceType>) -> Result<(Device, DeviceType), CandelabraError> {
    if let Some(device_type) = preferred {
        return match device_type {
            DeviceType::Metal => try_metal_device()?
                .ok_or_else(|| CandelabraError::Device("Metal not available".to_string())),
            DeviceType::Cuda => try_cuda_device()?
                .ok_or_else(|| CandelabraError::Device("CUDA not available".to_string())),
            DeviceType::Cpu => Ok((Device::Cpu, DeviceType::Cpu)),
        };
    }

    Ok(get_best_device())
}

/// Returns a human-readable name for a device.
pub fn device_name(device: &Device) -> String {
    match device {
        Device::Cpu => "CPU".to_string(),
        #[cfg(not(target_os = "macos"))]
        Device::Cuda(_) => "CUDA GPU".to_string(),
        #[cfg(target_os = "macos")]
        Device::Metal(_) => "Metal GPU".to_string(),
        #[allow(unreachable_patterns)]
        _ => "Unknown".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn try_metal_device() -> Result<Option<(Device, DeviceType)>, CandelabraError> {
    let available = catch_unwind(AssertUnwindSafe(candle_core::utils::metal_is_available))
        .map_err(|panic| device_panic_error("Metal availability check", panic))?;

    if !available {
        return Ok(None);
    }

    match catch_unwind(AssertUnwindSafe(|| Device::new_metal(0))) {
        Ok(Ok(device)) => Ok(Some((device, DeviceType::Metal))),
        Ok(Err(e)) => Err(CandelabraError::Device(format!("Metal: {}", e))),
        Err(panic) => Err(device_panic_error("Metal device creation", panic)),
    }
}

#[cfg(not(target_os = "macos"))]
fn try_metal_device() -> Result<Option<(Device, DeviceType)>, CandelabraError> {
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn try_cuda_device() -> Result<Option<(Device, DeviceType)>, CandelabraError> {
    let available = catch_unwind(AssertUnwindSafe(candle_core::utils::cuda_is_available))
        .map_err(|panic| device_panic_error("CUDA availability check", panic))?;

    if !available {
        return Ok(None);
    }

    match catch_unwind(AssertUnwindSafe(|| Device::new_cuda(0))) {
        Ok(Ok(device)) => Ok(Some((device, DeviceType::Cuda))),
        Ok(Err(e)) => Err(CandelabraError::Device(format!("CUDA: {}", e))),
        Err(panic) => Err(device_panic_error("CUDA device creation", panic)),
    }
}

#[cfg(target_os = "macos")]
fn try_cuda_device() -> Result<Option<(Device, DeviceType)>, CandelabraError> {
    Ok(None)
}

fn device_panic_error(context: &str, panic: Box<dyn Any + Send>) -> CandelabraError {
    CandelabraError::Device(format!(
        "{} panicked: {}",
        context,
        panic_payload_message(panic.as_ref())
    ))
}

pub(crate) fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::panic_payload_message;

    #[test]
    fn panic_payload_message_extracts_static_string() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("missing CUDA symbol");

        assert_eq!(
            panic_payload_message(payload.as_ref()),
            "missing CUDA symbol"
        );
    }

    #[test]
    fn panic_payload_message_extracts_owned_string() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(String::from("driver mismatch"));

        assert_eq!(panic_payload_message(payload.as_ref()), "driver mismatch");
    }
}
