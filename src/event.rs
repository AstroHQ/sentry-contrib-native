//! Sentry event implementation.

use crate::{global_read, CToR, Level, Object, RToC, Value};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt::{Display, Formatter, Result},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    os::raw::c_char,
    ptr,
};

/// A Sentry event.
///
/// # Examples
/// ```
/// # use sentry_contrib_native::Event;
/// # use std::collections::BTreeMap;
/// let mut event = Event::new();
/// let mut extra = BTreeMap::new();
/// extra.insert("some extra data".into(), "test data".into());
/// event.insert("extra".into(), extra.into());
/// event.capture();
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct Event {
    /// Event interface.
    interface: Interface,
    /// Event content.
    map: BTreeMap<String, Value>,
}

/// Sentry event interface.
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum Interface {
    /// Plain interface.
    Event,
    /// Message interface.
    Message {
        /// Level.
        level: Level,
        /// Logger.
        logger: Option<String>,
        /// Message text.
        text: String,
    },
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

impl Object for Event {
    fn into_parts(self) -> (sys::Value, BTreeMap<String, Value>) {
        let event = match self.interface {
            Interface::Event => unsafe { sys::value_new_event() },
            Interface::Message {
                level,
                logger,
                text,
            } => {
                let logger = logger.map(RToC::into_cstring);
                let logger = logger
                    .as_ref()
                    .map_or(ptr::null(), |logger| logger.as_ptr());
                let text = text.into_cstring();

                unsafe { sys::value_new_message_event(level.into_raw(), logger, text.as_ptr()) }
            }
        };

        (event, self.map)
    }
}

impl Deref for Event {
    type Target = BTreeMap<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl DerefMut for Event {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl Event {
    /// Creates a new Sentry event.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Event;
    /// let mut event = Event::new();
    /// ```
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new() -> Self {
        Self {
            interface: Interface::Event,
            map: BTreeMap::new(),
        }
    }

    /// Creates a new Sentry message event.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::{Event, Level};
    /// let mut event = Event::new_message(Level::Debug, Some("test logger".into()), "test");
    /// ```
    pub fn new_message<S: Into<String>>(level: Level, logger: Option<String>, text: S) -> Self {
        Self {
            interface: Interface::Message {
                level,
                logger,
                text: text.into(),
            },
            map: BTreeMap::new(),
        }
    }

    /// Generate stacktrace.
    fn stacktrace(len: usize) -> BTreeMap<String, Value> {
        let event = unsafe {
            let value = sys::value_new_event();
            sys::event_value_add_stacktrace(value, ptr::null_mut(), len);
            Value::from_raw(value)
        };

        event
            .into_map()
            .ok()
            .and_then(|mut event| event.remove("threads"))
            .and_then(|threads| threads.into_map().ok())
            .expect("failed to get stacktrace")
    }

    /// Adds a stacktrace to the [`Event`].
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::{Event, Level};
    /// let mut event = Event::new_message(Level::Debug, Some("test logger".into()), "test");
    /// event.add_stacktrace(0);
    /// event.capture();
    /// ```
    pub fn add_stacktrace(&mut self, len: usize) {
        self.insert("threads".into(), Self::stacktrace(len).into());
    }

    /// Adds an exception to the [`Event`] along with a stacktrace. As a
    /// workaround for <https://github.com/getsentry/sentry-native/issues/235>,
    /// the stacktrace is moved to the `exception` object so that it shows up
    /// correctly in Sentry.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Event;
    /// # use std::collections::BTreeMap;
    /// let mut event = Event::new();
    /// let mut exception = BTreeMap::new();
    /// exception.insert("type".into(), "test exception".into());
    /// exception.insert("value".into(), "test exception value".into());
    /// event.add_exception(exception.into(), 0);
    /// event.capture();
    /// ```
    pub fn add_exception(&mut self, mut exception: BTreeMap<String, Value>, len: usize) {
        let stacktrace = Self::stacktrace(len)
            .remove("values")
            .and_then(|values| values.into_list().ok())
            .and_then(|values| values.into_iter().next())
            .and_then(|thread| thread.into_map().ok())
            .and_then(|mut thread| thread.remove("stacktrace"))
            .filter(Value::is_map)
            .expect("failed to move stacktrace");

        exception.insert("stacktrace".into(), stacktrace);
        self.insert("exception".into(), exception.into());
    }

    /// Sends the [`Event`].
    ///
    /// # Panics
    /// Panics if any [`String`] contains a null byte.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Event;
    /// # use std::collections::BTreeMap;
    /// let mut event = Event::new();
    /// let mut extra = BTreeMap::new();
    /// extra.insert("some extra data".into(), "test data".into());
    /// event.insert("extra".into(), extra.into());
    /// event.capture();
    /// ```
    #[allow(clippy::must_use_candidate)]
    pub fn capture(self) -> Uuid {
        let event = self.into_raw();

        {
            let _lock = global_read();
            Uuid(unsafe { sys::capture_event(event) })
        }
    }
}

/// A Sentry UUID.
///
/// # Examples
/// ```
/// # use sentry_contrib_native::Event;
/// let uuid = Event::new().capture();
/// println!("event sent has UUID \"{}\"", uuid);
/// ```
#[derive(Debug, Copy, Clone)]
pub struct Uuid(sys::Uuid);

impl PartialEq for Uuid {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut string = [0; 37];

        unsafe { sys::uuid_as_string(&self.0, string.as_mut_ptr()) };

        write!(
            f,
            "{}",
            unsafe { string.as_ptr().as_str() }.expect("invalid pointer")
        )
    }
}

impl Eq for Uuid {}

impl PartialOrd for Uuid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.as_bytes().partial_cmp(&other.as_bytes())
    }
}

impl Ord for Uuid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(&other.as_bytes())
    }
}

impl Hash for Uuid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl Uuid {
    /// Creates a new empty Sentry UUID.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Uuid;
    /// assert_eq!(
    ///     "00000000-0000-0000-0000-000000000000",
    ///     Uuid::new().to_string()
    /// );
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self(unsafe { sys::uuid_nil() })
    }

    /// Creates a new empty UUID with the given `bytes`.
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Uuid;
    /// Uuid::from_bytes([0; 16]);
    /// ```
    #[must_use]
    pub const fn from_bytes(bytes: [c_char; 16]) -> Self {
        Self(sys::Uuid { bytes })
    }

    /// Returns the bytes of the [`Uuid`].
    ///
    /// # Examples
    /// ```
    /// # use sentry_contrib_native::Uuid;
    /// assert_eq!([0; 16], Uuid::new().as_bytes());
    /// ```
    #[must_use]
    pub const fn as_bytes(self) -> [c_char; 16] {
        self.0.bytes
    }
}

impl From<[c_char; 16]> for Uuid {
    fn from(value: [c_char; 16]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<Uuid> for [c_char; 16] {
    fn from(value: Uuid) -> Self {
        value.as_bytes()
    }
}

#[test]
fn event() -> anyhow::Result<()> {
    let event = Event::new();

    if let Interface::Message { .. } = event.interface {
        unreachable!()
    }

    event.capture();

    let event = Event::new_message(Level::Debug, Some("test".into()), "test");

    if let Interface::Message {
        level,
        logger,
        text,
    } = &event.interface
    {
        assert_eq!(&Level::Debug, level);
        assert_eq!(&Some("test".into()), logger);
        assert_eq!("test", text);
    } else {
        unreachable!()
    }

    event.capture();

    let mut event = Event::new();
    event.add_stacktrace(0);
    event.capture();

    let mut event = Event::new_message(Level::Debug, None, "test");
    event.add_stacktrace(0);
    event.capture();

    let mut event = Event::new();
    let mut exception = BTreeMap::new();
    exception.insert("type".into(), "test type".into());
    exception.insert("value".into(), "test value".into());
    event.add_exception(exception, 0);

    let exception = event.get("exception").unwrap().as_map().unwrap();
    assert_eq!(Some("test type"), exception.get("type").unwrap().as_str());
    assert_eq!(Some("test value"), exception.get("value").unwrap().as_str());
    let stacktrace = exception.get("stacktrace").unwrap().as_map().unwrap();
    let frames = stacktrace.get("frames").unwrap().as_list().unwrap();
    assert_ne!(None, frames.get(0).unwrap().as_map());

    event.capture();

    Ok(())
}

#[test]
fn uuid() {
    assert_eq!(
        "00000000-0000-0000-0000-000000000000",
        Uuid::new().to_string()
    );
}
