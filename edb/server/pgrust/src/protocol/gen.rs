/// Performs a first-pass parse on a struct, filling out some additional
/// metadata that makes the jobs of further macro passes much simpler.
macro_rules! struct_elaborate {
    (
        $next:ident $( ($($next_args:tt)*) )? => 
        $( #[ $sdoc:meta ] )*
        struct $name:ident {
            $(
                $( #[ $fdoc:meta ] )* $field:ident : $type:ty $( = $value:literal)?
            ),*
            $(,)?
        }
    ) => {
        // paste! is necessary here because it allows us to re-interpret a "ty"
        // as an explicit type pattern below.
        paste::paste!(struct_elaborate!(__builder_type__ fields($(
            [
                // Note that we double the type so we can re-use some output patterns in `__builder_type__`
                type($type)($type),
                value($($value)?),
                docs($([$fdoc]),*),
                name($field),
            ]
        )*) accum() original($next $( ($($next_args)*) )? => $(#[$sdoc])* struct $name {})););
    };

    // End of push-down automation - jumps to `__finalize__`
    (__builder_type__ fields() accum($($faccum:tt)*) original($($original:tt)*)) => {
        struct_elaborate!(__finalize__ accum($($faccum)*) original($($original)*));
    };

    // Pattern match on known fixed-sized types and mark them as `size(fixed=fixed)`
    (__builder_type__ fields([type(u8)($ty:ty), $($rest:tt)*] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder_value__ fields([type($ty), size(fixed=fixed), $($rest)*] $($frest)*) $($srest)*);
    };
    (__builder_type__ fields([type(i16)($ty:ty), $($rest:tt)*] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder_value__ fields([type($ty), size(fixed=fixed), $($rest)*] $($frest)*) $($srest)*);
    };
    (__builder_type__ fields([type(i32)($ty:ty), $($rest:tt)*] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder_value__ fields([type($ty), size(fixed=fixed), $($rest)*] $($frest)*) $($srest)*);
    };
    // Skip __builder_value__ for Length
    (__builder_type__ fields([type(Length)($ty:ty), value(), $($rest:tt)*] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder__ fields([type($ty), size(fixed=fixed), value(auto=auto), $($rest)*] $($frest)*) $($srest)*);
    };

    // Fallback for other types - variable sized
    (__builder_type__ fields([type($ty:ty)($ty2:ty), $($rest:tt)*] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder_value__ fields([type($ty), size(variable=variable), $($rest)*] $($frest)*) $($srest)*);
    };

    // Next, mark the presence or absence of a value
    (__builder_value__ fields([
        type($ty:ty), size($($size:tt)*), value(), $($rest:tt)*
    ] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder__ fields([type($ty), size($($size)*), value(no_value=no_value), $($rest)*] $($frest)*) $($srest)*);
    };
    (__builder_value__ fields([
        type($ty:ty), size($($size:tt)*), value($($value:tt)+), $($rest:tt)*
    ] $($frest:tt)*) $($srest:tt)*) => {
        struct_elaborate!(__builder__ fields([type($ty), size($($size)*), value(value=($($value)*)), $($rest)*] $($frest)*) $($srest)*);
    };

    // Push down the field to the accumulator
    (__builder__ fields([
        type($ty:ty), size($($size:tt)*), value($($value:tt)*), docs($($fdoc:tt),*), name($field:ident),
    ] $($frest:tt)*) accum($($faccum:tt)*) original($($original:tt)*)) => {
        struct_elaborate!(__builder_type__ fields($($frest)*) accum(
            $($faccum)*
            {
                name($field),
                type($ty),
                size($($size)*),
                value($($value)*),
                docs($($fdoc),*),
            },
        ) original($($original)*));
    };

    // Write the final struct
    (__finalize__ accum($($accum:tt)*) original($next:ident $( ($($next_args:tt)*) )?=> $( #[ $sdoc:meta ] )* struct $name:ident {})) => {
        $next ! (
            $( $($next_args)* , )?
            struct $name {
                docs($($sdoc),*),
                fields(
                    $($accum)*
                ),
            }
        );
    }
}

macro_rules! protocol2 {
    ($( $( #[ $sdoc:meta ] )* struct $name:ident $struct:tt )+) => {
        $(
            paste::paste!(
                pub(crate) mod [<$name:lower>] {
                    #[allow(unused_imports)]
                    use super::*;
                    use $crate::protocol::gen::*;
                    struct_elaborate!(protocol2_builder(__struct__) => $( #[ $sdoc ] )* struct $name $struct );
                    struct_elaborate!(protocol2_builder(__meta__) => $( #[ $sdoc ] )* struct $name $struct );
                    struct_elaborate!(protocol2_builder(__measure__) => $( #[ $sdoc ] )* struct $name $struct );
                    struct_elaborate!(protocol2_builder(__builder__) => $( #[ $sdoc ] )* struct $name $struct );
                }
            );
        )+

        pub mod data {
            #![allow(unused_imports)]
            $(
                paste::paste!(
                    pub use super::[<$name:lower>]::$name;
                );
            )+
        }
        pub mod meta {
            #![allow(unused_imports)]
            $(
                paste::paste!(
                    pub use super::[<$name:lower>]::[<$name Meta>] as $name;
                );
            )+
        }
        pub mod builder {
            #![allow(unused_imports)]
            $(
                paste::paste!(
                    pub use super::[<$name:lower>]::[<$name Builder>] as $name;
                );
            )+
        }
        pub mod measure {
            #![allow(unused_imports)]
            $(
                paste::paste!(
                    pub use super::[<$name:lower>]::[<$name Measure>] as $name;
                );
            )+
        }
    };
}

macro_rules! r#if {
    (__is_empty__ [] {$($true:tt)*} else {$($false:tt)*}) => {
        $($true)*
    };
    (__is_empty__ [$($x:tt)+] {$($true:tt)*} else {$($false:tt)*}) => {
        $($false)*
    };
    (__has__ [$($x:tt)+] {$($true:tt)*}) => {
        $($true)*
    };
    (__has__ [] {$($true:tt)*}) => {
    };
}

macro_rules! protocol2_builder {
    (__struct__, struct $name:ident {
        docs($($sdoc:meta),*),
        fields($({
            name($field:ident),
            type($type:ty),
            size($($size:tt)*),
            value($(value = ($value:expr))? $(no_value = $no_value:ident)? $(auto = $auto:ident)?),
            $($rest:tt)*
        },)*),
    }) => {
        paste::paste!(
            type S<'a> = $name<'a>;
            type META = [<$name Meta>];
            type M<'a> = [<$name Measure>]<'a>;
            type B<'a> = [<$name Builder>]<'a>;
            type F<'a> = [<$name Fields>];

            pub struct $name<'a> {
                buf: &'a [u8],
                fields: [usize; META::FIELD_COUNT + 1]
            }

            impl PartialEq for $name<'_> {
                fn eq(&self, other: &Self) -> bool {
                    self.buf.eq(other.buf)
                }
            }

            impl std::fmt::Debug for $name<'_> {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let mut s = f.debug_struct(stringify!($name));
                    s.field("buf", &self.buf);
                    s.finish()
                }
            }

            #[allow(unused)]
            impl <'a> S<'a> {
                /// Checks the constant values for this struct to determine whether
                /// this message matches.
                #[inline]
                pub const fn is(buf: &'a [u8]) -> bool {
                    let mut offset = 0;

                    // NOTE! This only works for fixed-sized fields and assumes
                    // that they all exist before variable-sized fields.

                    $(
                        $(if $crate::protocol::FieldAccess::<$type>::extract(buf.split_at(offset).1) != $value as usize as _ { return false;})?
                        offset += std::mem::size_of::<$type>();
                    )*

                    true
                }

                #[inline]
                pub const fn new(mut buf: &'a [u8]) -> Self {
                    let mut fields = [0; META::FIELD_COUNT + 1];
                    let mut offset = 0;
                    let mut index = 0;
                    $(
                        fields[index] = offset;
                        offset += $crate::protocol::FieldAccess::<$type>::size_of_field_at(buf.split_at(offset).1);
                        index += 1;
                    )*
                    fields[index] = offset;

                    Self {
                        buf,
                        fields,
                    }
                }

                $(
                    #[allow(unused)]
                    #[inline]
                    pub const fn $field<'s>(&'s self) -> <$type as $crate::protocol::Enliven<'a>>::WithLifetime where 's : 'a {
                        let offset1 = self.fields[F::$field as usize];
                        let offset2 = self.fields[F::$field as usize + 1];
                        let (_, buf) = self.buf.split_at(offset1);
                        let (buf, _) = buf.split_at(offset2 - offset1);
                        $crate::protocol::FieldAccess::<$type>::extract(buf)
                    }
                )*
            }
        );
    };

    (__meta__, struct $name:ident {
        docs($($sdoc:meta),*),
        fields($({
            name($field:ident),
            type($type:ty),
            size($($size:tt)*),
            value($(value = ($value:expr))? $(no_value = $no_value:ident)? $(auto = $auto:ident)?),
            $($rest:tt)*
        },)*),
    }) => {
        paste::paste!(
            $( #[$sdoc] )?
            #[allow(unused)]
            pub struct [<$name Meta>] {
            }

            #[allow(unused)]
            #[allow(non_camel_case_types)]
            #[derive(Eq, PartialEq)]
            #[repr(u8)]
            enum [<$name Fields>] {
                $(
                    $field,
                )*
            }

            impl META {
                const FIELD_COUNT: usize = [$(stringify!($field)),*].len();
                $($(pub const [<$field:upper _VALUE>]: $type = $crate::protocol::FieldAccess::<$type>::constant($value as usize);)?)*
            }

            impl <'a> $crate::protocol::Enliven<'a> for META {
                type WithLifetime = S<'a>;
                type ForMeasure = M<'a>;
                type ForBuilder = B<'a>;
            }

            impl $crate::protocol::FieldAccess<META> {
                #[inline(always)]
                pub const fn name() -> &'static str {
                    stringify!($name)
                }
                #[inline]
                pub const fn size_of_field_at(buf: &[u8]) -> usize {
                    let mut offset = 0;
                    $(
                        offset += $crate::protocol::FieldAccess::<$type>::size_of_field_at(buf.split_at(offset).1);
                    )*
                    offset
                }
                #[inline(always)]
                pub const fn extract(buf: &[u8]) -> $name<'_> {
                    $name::new(buf)
                }
                #[inline(always)]
                pub const fn measure(measure: &M) -> usize {
                    measure.measure()
                }
                #[inline(always)]
                pub fn copy_to_buf(buf: &mut $crate::protocol::writer::BufWriter, builder: &B) {
                    builder.copy_to_buf(buf)
                }
            }

            $crate::protocol::field_access!{[<$name Meta>]}
            $crate::protocol::arrays::array_access!{[<$name Meta>]}
        );
    };

    (__measure__, struct $name:ident {
        docs($($sdoc:meta),*),
        fields($({
            name($field:ident),
            type($type:ty),
            size( $( fixed=$fixed_marker:ident )? $( variable=$variable_marker:ident )? ),
            $($rest:tt)*
        },)*),
    }) => {
        paste::paste!(
            r#if!(__is_empty__ [$($($variable_marker)?)*] {
                // No variable-sized fields
                #[derive(Default, Eq, PartialEq)]
                pub struct [<$name Measure>]<'a> {      
                    _phantom: std::marker::PhantomData<&'a ()>
                }
            } else {
                pub struct [<$name Measure>]<'a> {
                    // Because of how macros may expand in the context of struct
                    // fields, we need to do a * repeat, then a ? repeat and
                    // somehow use $variable_marker in the remainder of the
                    // pattern.
                    $($(
                        pub $field: r#if!(__has__ [$variable_marker] {<$type as $crate::protocol::Enliven<'a>>::ForMeasure}),
                    )?)*
                }
            });

            impl <'a> M<'a> {
                pub const fn measure(&self) -> usize {
                    let mut size = 0;
                    $(
                        r#if!(__has__ [$($variable_marker)?] { size += $crate::protocol::FieldAccess::<$type>::measure(self.$field); });
                        r#if!(__has__ [$($fixed_marker)?] { size += std::mem::size_of::<$type>(); });
                    )*
                    size
                }
            }
        );
    };

    (__builder__, struct $name:ident {
        docs($($sdoc:meta),*),
        fields($({
            name($field:ident),
            type($type:ty),
            size($($size:tt)*),
            value($(value = ($value:expr))? $(no_value = $no_value:ident)? $(auto = $auto:ident)?),
            $($rest:tt)*
        },)*),
    }) => {
        paste::paste!(
            r#if!(__is_empty__ [$($($no_value)?)*] {
                // No unfixed-value fields
                #[derive(Default, Eq, PartialEq)]
                pub struct [<$name Builder>]<'a> {      
                    _phantom: std::marker::PhantomData<&'a ()>
                }
            } else {
                #[derive(Default, Eq, PartialEq)]
                pub struct [<$name Builder>]<'a> {
                    // Because of how macros may expand in the context of struct
                    // fields, we need to do a * repeat, then a ? repeat and
                    // somehow use $no_value in the remainder of the pattern.
                    $($(
                        pub $field: r#if!(__has__ [$no_value] {<$type as $crate::protocol::Enliven<'a>>::ForBuilder}),
                    )?)*
                }
            });

            impl <'a> B<'a> {
                #[allow(unused)]
                pub fn copy_to_buf(&self, buf: &mut $crate::protocol::writer::BufWriter) {
                    $(
                        r#if!(__is_empty__ [$($value)?] {
                            r#if!(__is_empty__ [$($auto)?] {
                                $crate::protocol::FieldAccess::<$type>::copy_to_buf(buf, self.$field);
                            } else {
                                let auto_offset = buf.size();
                                $crate::protocol::FieldAccess::<$type>::copy_to_buf(buf, 0);
                            });
                        } else {
                            $crate::protocol::FieldAccess::<$type>::copy_to_buf(buf, $($value)? as usize as _);
                        });
                    )*

                    $(
                        r#if!(__has__ [$($auto)?] {
                            $crate::protocol::FieldAccess::<Length>::copy_to_buf_rewind(buf, auto_offset, buf.size() - auto_offset);
                        });
                    )*

                }

                /// Convert this builder into a vector of bytes. This is generally
                /// not the most efficient way to perform serialization.
                #[allow(unused)]
                pub fn to_vec(self) -> Vec<u8> {
                    let mut vec = Vec::with_capacity(256);
                    let mut buf = $crate::protocol::writer::BufWriter::new(&mut vec);
                    self.copy_to_buf(&mut buf);
                    match buf.finish() {
                        Ok(size) => {
                            vec.truncate(size);
                            vec
                        },
                        Err(size) => {
                            vec.resize(size, 0);
                            let mut buf = $crate::protocol::writer::BufWriter::new(&mut vec);
                            self.copy_to_buf(&mut buf);
                            let size = buf.finish().unwrap();
                            vec.truncate(size);
                            vec
                        }
                    }
                }
            }
        );
    };
}

pub(crate) use {protocol2, protocol2_builder, struct_elaborate, r#if};

#[cfg(test)]
mod tests {
    mod fixed_only {
        protocol2!(struct FixedOnly {
            a: u8,
        });
    }

    mod fixed_only_value {
        protocol2!(struct FixedOnlyValue {
            a: u8 = 1,
        });
    }

    mod mixed {
        use crate::protocol::meta::ZTString;
        protocol2!(struct Mixed {
            a: u8 = 1,
            s: ZTString,
        });
    }

    mod docs {
        use crate::protocol::meta::ZTString;
        protocol2!(
            /// Docs
            struct Docs {
                /// Docs
                a: u8 = 1,
                /// Docs
                s: ZTString,
            }
        );
    }

    macro_rules! assert_stringify {
        (($($struct:tt)*), $expected:literal) => {
            struct_elaborate!(assert_stringify(__internal__ $expected) => $($struct)*);
        };
        (__internal__ $expected:literal, $($struct:tt)*) => {
            assert_eq!(stringify!($($struct)*), $expected);
        };
    }

    #[test]
    fn empty_struct() {
        assert_stringify!((struct Foo {}), "struct Foo { docs(), fields(), }");
    }

    #[test]
    fn fixed_size_fields() {
        assert_stringify!((struct Foo {
            a: u8,
        }), r#"struct Foo
{
    docs(),
    fields({
        name(a), type (u8), size(fixed = fixed), value(no_value = no_value),
        docs(),
    },),
}"#);
    }
}
