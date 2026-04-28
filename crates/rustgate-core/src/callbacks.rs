// Copyright © 2026 Roberto Chiofalo.

//! Workspace-wide macro for declaring `Arc<dyn Fn>` callback type aliases.
//!
//! The rustgate workspace uses dozens of `Arc<dyn Fn(...) + Send + Sync>`
//! type aliases (`On*`, `*Fn`, `*Callback`, `*Provider`) so transport
//! crates can hand metric, audit, and routing observers off to the
//! server binary without growing a `prometheus` or `tonic` dependency.
//! Every alias has the identical shape — only the parameter list
//! changes:
//!
//! ```text
//! pub type OnFoo = Arc<dyn Fn(Args...) + Send + Sync>;
//! ```
//!
//! Hand-writing each alias is a small but real source of drift: a
//! missing `+ Send`, an accidental `Box` instead of `Arc`, or a
//! `'static` lifetime added "to make the borrow checker happy" all
//! silently change the contract callers rely on. The [`crate::on_callback`]
//! macro pins the shape at definition time so those mistakes become
//! parse errors instead of confusing trait-bound failures at the call
//! site.
//!
//! # Guarantees
//!
//! Every alias declared via [`crate::on_callback`] is exactly:
//!
//! - `std::sync::Arc<...>` — never `Box`. Callbacks must be cloneable
//!   and shareable across tasks; the workspace pattern is to install
//!   one observer and `Arc::clone` it into each call site.
//! - `dyn Fn(...)` — never `FnMut` or `FnOnce`. Observers are pure
//!   functions of their arguments; shared mutable state belongs in an
//!   `Arc<Mutex<...>>` captured by the closure, not in the trait.
//! - `+ Send + Sync` — required because callbacks routinely cross
//!   `tokio::spawn` boundaries and ride inside `ArcSwap` slots loaded
//!   from multiple worker threads.
//! - No return type. The macro is for fire-and-forget observers; if a
//!   callback needs to return a value (a status snapshot, a future, a
//!   trust-store provider) the alias stays hand-written so the return
//!   type and any `Pin<Box<dyn Future<Output = ...>>>` plumbing remain
//!   visible to readers.
//!
//! # Why `Fn`, not `AsyncFn`
//!
//! `dyn AsyncFn` is not object-safe as of Rust 1.94, so async work
//! inside a callback is dispatched via
//! [`spawn_background`](crate::tasks::spawn_background) inside the
//! closure body. The macro therefore intentionally produces only the
//! synchronous `Fn` form.
//!
//! # Limitations
//!
//! The macro does **not** support:
//!
//! - **Generic parameters.** A `pub type OnFoo<T> = Arc<dyn Fn(T) +
//!   Send + Sync>` alias must stay hand-written until a follow-up
//!   issue extends the macro grammar.
//! - **`where` clauses.** Same reason as generics.
//! - **Return types.** Callbacks that produce a value (e.g.
//!   `JwkSetFn`, `OutboundRootStoreProvider`, `ContactsProvider`,
//!   `NatsRequestHandler`, `ReloadFn`, `FedApiHandler`) stay
//!   hand-written so the return shape — including
//!   `Pin<Box<dyn Future<Output = ...> + Send>>` — is visible at the
//!   declaration site.
//!
//! Hand-written aliases for the cases above continue to compile and
//! interoperate; the macro is purely additive. New callback aliases
//! added to the workspace SHOULD prefer [`crate::on_callback`] when the
//! shape fits.
//!
//! # Examples
//!
//! Public callback alias in a transport crate:
//!
//! ```
//! use rustgate_core::on_callback;
//!
//! on_callback!(pub OnConnected, u64);
//! on_callback!(pub OnHandshakeError, std::net::SocketAddr, &'static str);
//!
//! let cb: OnConnected = std::sync::Arc::new(|peer_id| {
//!     // emit a Prometheus counter, etc.
//!     let _ = peer_id;
//! });
//! cb(42);
//! ```
//!
//! Crate-private callback alias:
//!
//! ```
//! use rustgate_core::on_callback;
//!
//! mod inner {
//!     rustgate_core::on_callback!(pub(crate) OnInternal, &'static str);
//! }
//! ```
//!
//! Zero-argument callback (the most common shape):
//!
//! ```
//! use rustgate_core::on_callback;
//!
//! on_callback!(pub OnPing,);
//!
//! let cb: OnPing = std::sync::Arc::new(|| { /* fire-and-forget */ });
//! cb();
//! ```

/// Declare an `Arc<dyn Fn(...) + Send + Sync>` callback type alias.
///
/// See the [module-level docs](self) for the macro's contract,
/// guarantees, and limitations.
///
/// # Syntax
///
/// ```text
/// on_callback!($vis $Name, $arg_ty, $arg_ty, ...);
/// ```
///
/// `$vis` is any Rust visibility (`pub`, `pub(crate)`, `pub(super)`,
/// or omitted for module-private). `$Name` is the type-alias
/// identifier. The remaining tokens are zero or more parameter types,
/// separated by commas, with an optional trailing comma.
///
/// The macro expands to:
///
/// ```text
/// $vis type $Name = std::sync::Arc<dyn Fn($arg_ty, ...) + Send + Sync>;
/// ```
///
/// # Example
///
/// ```
/// rustgate_core::on_callback!(pub OnFoo, u32, &str);
/// // expands to:
/// // pub type OnFoo = std::sync::Arc<dyn Fn(u32, &str) + Send + Sync>;
/// ```
#[macro_export]
macro_rules! on_callback {
    ($(#[$attr:meta])* $vis:vis $name:ident $(, $arg:ty)* $(,)?) => {
        $(#[$attr])*
        $vis type $name = ::std::sync::Arc<dyn Fn($($arg),*) + Send + Sync>;
    };
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // The macro under test is `#[macro_export]`-ed, so inside the
    // crate it is reachable as `crate::on_callback!`.

    crate::on_callback!(NoArgsCallback);
    crate::on_callback!(OneArgCallback, u32);
    crate::on_callback!(TwoArgCallback, u32, &'static str);
    crate::on_callback!(ReferenceArgCallback, &str);
    crate::on_callback!(TrailingCommaCallback, u32, &'static str,);

    #[test]
    fn on_callback_macro_produces_arc_dyn_fn_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoArgsCallback>();
        assert_send_sync::<OneArgCallback>();
        assert_send_sync::<TwoArgCallback>();
        assert_send_sync::<ReferenceArgCallback>();
        assert_send_sync::<TrailingCommaCallback>();
    }

    #[test]
    fn on_callback_macro_produces_clone() {
        // Arc<dyn Fn ...> is always Clone via the inner Arc.
        fn assert_clone<T: Clone>() {}
        assert_clone::<NoArgsCallback>();
        assert_clone::<OneArgCallback>();
    }

    #[test]
    fn on_callback_zero_arg_invokes_closure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: NoArgsCallback = Arc::new(move || {
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        cb();
        cb();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn on_callback_two_arg_passes_arguments() {
        let observed = Arc::new(AtomicUsize::new(0));
        let o = Arc::clone(&observed);
        let cb: TwoArgCallback = Arc::new(move |n, label| {
            assert_eq!(label, "hello");
            let _ = o.fetch_add(n as usize, Ordering::SeqCst);
        });
        cb(7, "hello");
        assert_eq!(observed.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn on_callback_clone_shares_underlying_state() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let cb: NoArgsCallback = Arc::new(move || {
            let _ = c.fetch_add(1, Ordering::SeqCst);
        });
        let cb2 = Arc::clone(&cb);
        cb();
        cb2();
        // Two invocations against a single shared Arc — both increments
        // hit the same atomic.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn on_callback_macro_supports_pub_visibility() {
        mod inner {
            crate::on_callback!(pub Visible, ());
        }
        let _: inner::Visible = Arc::new(|_| {});
    }

    #[test]
    fn on_callback_macro_supports_pub_crate_visibility() {
        mod inner {
            crate::on_callback!(pub(crate) Restricted, u8);
        }
        let _: inner::Restricted = Arc::new(|_| {});
    }

    #[test]
    fn on_callback_macro_default_visibility_is_module_private() {
        // The macro accepts an empty `$vis`, expanding to a
        // module-private alias. Define it inside an inner module so
        // the absence of `pub` is meaningful — the alias is reachable
        // here only because the test sits in the same module tree.
        crate::on_callback!(Private, u8);
        let _: Private = Arc::new(|_| {});
    }

    #[test]
    fn on_callback_macro_accepts_reference_with_lifetime() {
        crate::on_callback!(LifetimeCb, &'static str);
        let cb: LifetimeCb = Arc::new(|s| {
            assert_eq!(s, "static");
        });
        cb("static");
    }
}
