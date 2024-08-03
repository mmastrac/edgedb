// TODO

// Maybe they can also have the "measurement" / creation types too
// Finish tuplenest/tupleunest
// Create filtering for nested tuples to remove the fixed size stuff for measurement
// Maybe it can also remove the fixed-value itsems as well for creation


mod arrays;
mod datatypes;
mod definition;
mod gen;

/// Metatypes
pub mod meta {
    pub use super::definition::gen::meta::*;
    pub use super::datatypes::meta::{Encoded, Rest, ZTString};
    pub use super::arrays::meta::*;
}

pub mod measure {
    pub use super::definition::gen::measure::*;
}

#[allow(unused)]
pub use definition::gen::data::*;
#[allow(unused)]
pub use datatypes::*;
#[allow(unused)]
pub use arrays::*;

pub trait Enliven<'a> {
    type WithLifetime;
    type ForBuilder;
}

/// Delegates to a concrete `FieldAccess` but as a non-const trait.
pub(crate) trait FieldAccessNonConst<'a, T: 'a> {
    fn size_of_field_at(buf: &[u8]) -> usize;
    fn extract(buf: &'a [u8]) -> T;
}

tuplemagic::tuple_filter_predicate!(pub VariableSize = { 
    include = (~ <T> meta::ZTArray<T>, ~ <T, U> meta::Array<T, U>, meta::Rest, meta::ZTString, meta::Encoded), 
    exclude = (u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, [u8; 4]) 
});

pub trait FieldTypes {
    type FieldTypes;
}

/// This struct is specialized for each type we want to extract data from. We
/// have to do it this way to work around Rust's lack of const specialization.
pub(crate) struct FieldAccess<T: for <'a> Enliven<'a>> {
    _phantom_data: PhantomData<T>,
}

/// Delegate to the concrete `FieldAccess` for each type we want to extract.
macro_rules! field_access {
    ($ty:ty) => {
        impl <'a> $crate::protocol::FieldAccessNonConst<'a, <$ty as Enliven<'a>>::WithLifetime> for <$ty as Enliven<'a>>::WithLifetime {
            #[inline(always)]
            fn size_of_field_at(buf: &[u8]) -> usize {
                $crate::protocol::FieldAccess::<$ty>::size_of_field_at(buf)
            }
            #[inline(always)]
            fn extract(buf: &'a [u8]) -> <$ty as $crate::protocol::Enliven<'a>>::WithLifetime {
                $crate::protocol::FieldAccess::<$ty>::extract(buf)
            }            
        }
    };
}
pub(crate) use field_access;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sasl_response() {
        let buf = [b'p', 5, 0, 0, 0, 2];
        let message = SASLResponse::new(&buf);
        assert_eq!(message.mlen(), 5);
        assert_eq!(message.response().len(), 1);
    }

    #[test]
    fn test_sasl_response_measure() {
        let measure = measure::SASLResponse {
            response: &[1, 2, 3, 4, 5]
        };
        assert_eq!(measure.measure(), 10)
    }

    #[test]
    fn test_startup_message() {
        let buf = [
            5, 0, 0, 0, 
            0, 0x30, 0, 0, 
            b'a', 0, b'b', 0,
            b'c', 0, b'd', 0, 0];
        let message = StartupMessage::new(&buf);
        let arr = message.params();
        let mut vals = vec![];
        for entry in arr {
            vals.push(entry.name().to_owned());
            vals.push(entry.value().to_owned());
        }
        assert_eq!(vals, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn test_row_description() {
        let buf = [
            b'T',
            0, 0, 0, 0,
            2, 0, // # of fields
            b'f', b'1', 0,
            0, 0, 0, 0,
            0, 0,
            0, 0, 0, 0,
            0, 0,
            0, 0, 0, 0,
            0, 0,
            b'f', b'2', 0,
            0, 0, 0, 0,
            0, 0,
            0, 0, 0, 0,
            0, 0,
            0, 0, 0, 0,
            0, 0,
        ];
        let message = RowDescription::new(&buf);
        assert_eq!(message.fields().len(), 2);
        let mut iter = message.fields().into_iter();
        let f1 = iter.next().unwrap();
        assert_eq!(f1.name(), "f1");
        let f2 = iter.next().unwrap();
        assert_eq!(f2.name(), "f2");
        assert_eq!(None, iter.next());
    }

    #[test]
    fn test_row_description_measure() {
        let measure = measure::RowDescription {
            fields: &[
                measure::RowField {
                    name: "F1"
                },
                measure::RowField {
                    name: "F2"
                }
            ]
        };
        assert_eq!(49, measure.measure())
    }
}
