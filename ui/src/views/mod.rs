//! Page-level views, one per route. Reusable building blocks live in
//! [`crate::components`].

pub mod dashboard;
pub mod error;
pub mod project;
pub mod setup;

pub use dashboard::*;
pub use error::*;
pub use project::*;
pub use setup::*;
