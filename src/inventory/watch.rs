use super::{diff_states, snapshot, InventoryDelta, InventoryOptions, InventoryState};
use anyhow::{bail, Result};
use std::time::Duration;
pub fn watch<F>(options: &InventoryOptions, interval: Duration, mut on_delta: F) -> Result<()>
where
    F: FnMut(&InventoryState, &InventoryDelta) -> Result<bool>,
{
    if interval < Duration::from_secs(30) {
        bail!("inventory watch interval must be at least 30 seconds")
    }
    let mut previous = snapshot(options)?;
    loop {
        std::thread::sleep(interval);
        let current = snapshot(options)?;
        let delta = diff_states(&previous, &current);
        if !on_delta(&current, &delta)? {
            return Ok(());
        }
        previous = current;
    }
}
