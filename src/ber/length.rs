use alloc::vec::Vec;
use core::convert::TryFrom;
use crate::ber::tag::Tag;
use crate::ber::value::ValueReaderError;
#[cfg(test)]
use crate::ber::tag::{TagClass, TagForm, BasicTagType};
use crate::number::Number;
use crate::util::BufferReader;
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};

#[derive(Clone, Debug, PartialEq)]
pub enum Length {
    Short(usize),
    Long(Number),
    Indefinite,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConversionError {
    ValueTooLarge,
    Unconvertable,
}

impl From<ConversionError> for ValueReaderError {
    fn from(x: ConversionError) -> ValueReaderError {
        match x {
            ConversionError::ValueTooLarge => ValueReaderError::LengthTooBig,
            ConversionError::Unconvertable => ValueReaderError::LengthIncompatible,
        }
    }
}

impl<'a> TryFrom<&'a Length> for usize {
    type Error = ConversionError;

    fn try_from(x: &Length) -> Result<usize, Self::Error> {
        match x {
            Length::Short(x) => Ok(*x),
            Length::Long(ref v) => usize::try_from(v),
            Length::Indefinite => Err(ConversionError::Unconvertable),
        }
    }
}

impl From<usize> for Length {
    fn from(x: usize) -> Self {
        Length::Short(x)
    }
}

#[cfg(test)]
impl Arbitrary for Length {
    fn arbitrary<G: Gen>(g: &mut G) -> Length {
        match g.next_u32() % 3 {
            0 => Length::Short(usize::arbitrary(g) % 128),
            1 => Length::Long(Number::arbitrary(g)),
            2 => Length::Indefinite,
            _ => panic!("Mathematics broke."),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum LengthReaderError {
    NotEnoughData,
    IllegalConstructedFound,
    IllegalLong,
}

#[derive(Debug, PartialEq)]
pub enum LengthWriterError {
    SizeTooLarge,
}

impl Length {
    /// Read the next length value from the provided iterator, in the context of the provided tag.
    /// (In some cases, the tag will allow or disallow certain forms of length field, hence the
    /// need for the context.)
    pub fn read<I: Iterator<Item = u8>>(tag: &Tag, it: &mut I) -> Result<Length, LengthReaderError> {
        let constructed_form_allowed = !tag.has_primitive_form();

        match it.next() {
            None =>
                Err(LengthReaderError::NotEnoughData),
            Some(l) if l < 128 =>
                Ok(Length::Short(l as usize)),
            Some(l) if l == 0b1000_0000 && constructed_form_allowed =>
                Ok(Length::Indefinite),
            Some(l) if l == 0b1111_1111 =>
                Err(LengthReaderError::IllegalLong),
            Some(l) => {
                let bytelen = (l & 0b0111_1111) as usize;
                match bytelen.read_buffer(it) {
                    None => Err(LengthReaderError::NotEnoughData),
                    Some(bytes) => {
                      let num = Number::from_bytes(&bytes);
                      Ok(Length::Long(num))
                    }
                }
            }
        }
    }

    /// Write the start of a length value to the data stream. Unfortunately, for lengths, you may
    /// also need to write something after the value, as well; for that, use `write_postfix` to
    /// ensure you frame the length appropriately.
    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<(), LengthWriterError> {
        match self {
            Length::Short(s) if *s > 127 =>
                Err(LengthWriterError::SizeTooLarge),
            Length::Short(s) => {
                buffer.push(*s as u8);
                Ok(())
            }
            Length::Long(n) => {
                let bytes = n.serialize();

                if bytes.len() > 127 {
                    return Err(LengthWriterError::SizeTooLarge);
                }

                buffer.push((bytes.len() as u8) | 0b1000_0000);
                for x in bytes.iter() {
                    buffer.push(*x);
                }
                Ok(())
            }
            Length::Indefinite => {
                buffer.push(0b1000_0000);
                Ok(())
            }
        }
    }

    /// Write, if required, the postfix bytes to the object. This is only relevant for a very
    /// narrow set of types, but I suggest calling it no matter what; it will never do harm to call
    /// it.
    pub fn write_postfix(&self, buffer: &mut Vec<u8>) {
        match self {
            Length::Indefinite => {
                buffer.push(0b0000_0000);
                buffer.push(0b0000_0000);
            }
            _ => {}
        }
    }
}

impl BufferReader for Length {
    fn read_buffer<I: Iterator<Item=u8>>(&self, it: &mut I) -> Option<Vec<u8>> {
        match self {
            Length::Indefinite => {
                let mut res = Vec::new();
                let mut successive_zeros = 0;

                while successive_zeros < 2 {
                    let next = it.next()?;

                    if next == 0 {
                        successive_zeros += 1;
                    } else {
                        successive_zeros = 0;
                    }

                    res.push(next);
                }

                res.truncate(res.len() - 2);
                Some(res)
            }
            Length::Long(x) => match usize::try_from(x) {
                Err(_) => None,
                Ok(x) => x.read_buffer(it),
            }
            Length::Short(x) => x.read_buffer(it),
        }
    }
}

#[cfg(test)]
quickcheck! {
    fn length_bytes_length(l: Length) -> bool {
        let form = if l == Length::Indefinite { TagForm::Constructed } else { TagForm::Primitive };
        let tag = Tag::Simple(TagClass::Universal, form, BasicTagType::Boolean);
        let mut output = Vec::new();
        l.write(&mut output).unwrap();
        let mut outiter = output.iter().map(|x| *x);
        match Length::read(&tag, &mut outiter) {
            Err(e) => {
                println!("Error found: {:?}", e);
                false
            }
            Ok(l2) => {
                println!("Result: {:?}", l2);
                l == l2
            }
        }
    }
}
