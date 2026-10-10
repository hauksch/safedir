//! Directory backends: offline extract, in-memory, and (feature `vas`) the
//! live SPML/VAS client.

mod extract;
mod memory;

pub use extract::ExtractResolver;
pub use memory::InMemoryResolver;
