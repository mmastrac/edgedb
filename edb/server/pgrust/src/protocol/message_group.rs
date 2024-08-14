macro_rules! message_group {
    ($(#[$doc:meta])* $group:ident = [$($message:ty),*]) => {
        paste::paste!(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $group {
            $(
                #[doc = concat!("Matched [`", stringify!($message), "`]")]
                $message
            ),*
        }

        pub trait [<$group Match>] {
            $(
                fn [<$message:snake>]<'a>(&mut self) -> Option<impl FnMut(data::$message<'a>)> {
                    // No implementation by default
                    let mut opt = Some(|_| {});
                    opt.take();
                    opt
                }
            )*
            // fn unknown(&mut self, message: self::struct_defs::Message::Message) {
            //     // No implementation by default
            // }
        }

        impl $group {
            pub fn identify(buf: &[u8]) -> Option<Self> {
                $(
                    if <$message as $crate::protocol::Enliven>::WithLifetime::is(buf) {
                        return Some(Self::$message);
                    }
                )*
                None
            }

            pub fn match_message(matcher: &mut impl [<$group Match>], buf: &[u8]) {
                $(
                    if data::$message::is(buf) {
                        if let Some(mut f) = matcher.[<$message:snake>]() {
                            let message = data::$message::new(buf);
                            f(message);
                            return;
                        }
                    }
                )*
            }
        }
        );
    };
}
pub(crate) use message_group;

/// Peform a match on a message.
///
/// ```rust
/// use pgrust::protocol::*;
///
/// let buf = [0, 1, 2];
/// match_message!(&buf, Backend {
///     (BackendKeyData as data) => {
///         todo!();
///     },
///     unknown => {
///         eprintln!("Unknown message: {unknown:?}");
///     }
/// });
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __match_message {
    ($buf:expr, $messages:ty {
        $(( $i1:path $(as $i2:ident )?) => $impl:block,)*
        $unknown:ident => $unknown_impl:block $(,)?
    }) => {
        {
            let buf: &[u8] = $buf.as_ref();
            $(
                if <$i1>::is(buf) {
                    $(let $i2 = <$i1>::new(buf);)?
                    $impl
                } else
            )*
            {
                let $unknown = <$messages>::identify(buf);
                $unknown_impl
            }
        }
    };
}

#[doc(inline)]
pub use __match_message as match_message;
