macro_rules! message_group {
    ($group:ident = [$($message:ident),*]) => {
        paste::paste!(
        pub struct $group {
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
