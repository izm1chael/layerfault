pub mod common;
pub mod javascript;
pub mod powershell;
pub mod python;
pub mod shell;
pub mod template;

mod frontend;

pub use frontend::{scan_language_member, LanguageId};
