This is EARLY dev- read  file in the /docs dir. 




From earlier dev --- 

The difficulty isn’t that Rust is too new for Serpent—it’s more that the cryptography ecosystem in Rust (especially for less-common algorithms like Serpent) is still maturing. The Serpent crate you’re using (v0.5.1) was built against an older version of the underlying cipher traits (cipher 0.3), while other crates like block‑modes have since moved on to cipher 0.4. This mismatch creates compatibility issues, such as the one you see with the new_from_slices function.

In essence, because Serpent isn’t as widely used as AES, its maintenance hasn’t kept pace with the rapid evolution of the RustCrypto libraries. This leaves you with a few options:

Fork and Patch: Update the Serpent crate yourself (or use a fork) to implement the newer cipher traits so it can work with the latest block‑modes.
Use Alternative Algorithms: Consider using a more actively maintained cipher like AES, which integrates smoothly with current RustCrypto dependencies.
Search for a Compatible Commit: Try to locate a commit in the block‑modes repository (from before the upgrade to cipher 0.4) and reference it by its hash in your Cargo.toml. (This approach can be tricky, as the branch or commit might no longer be available.)
These issues are a common challenge when working with cryptographic libraries in rapidly evolving ecosystems. Although it can be frustrating, it also reflects the vibrant, yet still-developing state of Rust’s cryptography landscape.
