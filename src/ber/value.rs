use crate::ber::length::{Length, LengthReaderError, LengthWriterError};
use crate::ber::tag::{Tag, TagClass, TagForm, TagReaderError, TagSerializationError, BasicTagType};
use crate::lift_error;
use crate::number::Number;
use crate::real::Real;
use crate::util::BufferReader;

pub enum Value {
    Boolean(TagClass, TagForm, bool),
    Integer(TagClass, TagForm, Number),
    Null(TagClass, TagForm),
    Real(TagClass, TagForm, Real),
}

pub enum ValueReaderError {
    LengthIncompatible,
    LengthTooBig,
    NotEnoughData,
    InvalidFormat(BasicTagType),
    TagReaderProblem(TagReaderError),
    LengthReaderError(LengthReaderError),
}

lift_error!(TagReaderError, TagReaderProblem, ValueReaderError);
lift_error!(LengthReaderError, ValueReaderError);

pub enum ValueWriterError {
    Length(LengthWriterError),
    Tag(TagSerializationError),
}

lift_error!(LengthWriterError, Length, ValueWriterError);
lift_error!(TagSerializationError, Tag, ValueWriterError);

impl Value {
    /// Read a value from the provided iterator.
    pub fn read<I: Iterator<Item = u8>>(it: &mut I) -> Result<Value, ValueReaderError> {
        let tag = Tag::read(it)?;
        let length = Length::read(&tag, it)?;
        let mut bytes: Vec<u8> = match length.read_buffer(it) {
            None => return Err(ValueReaderError::NotEnoughData),
            Some(x) => x,
        };

        match tag {
            Tag::Simple(c, f, BasicTagType::Boolean) => {
                match it.next() {
                    None => Err(ValueReaderError::NotEnoughData),
                    Some(0) => Ok(Value::Boolean(c, f, false)),
                    Some(_) => Ok(Value::Boolean(c, f, true)),
                }
            }

            Tag::Simple(c, f, BasicTagType::Null) =>
                Ok(Value::Null(c, f)),

            Tag::Simple(c, f, BasicTagType::Integer) => {
                let res = Number::from_bytes(&bytes);
                Ok(Value::Integer(c, f, res))
            }

            Tag::Simple(c, f, BasicTagType::Real) => {
                if bytes.len() == 0 {
                    return Err(ValueReaderError::InvalidFormat(BasicTagType::Real));
                }

                let leader = bytes.remove(0); // has the handy side-effect of making bytes by the
                                              // actual value.

                if leader == 0b01000000 {
                    return Ok(Value::Real(c, f, Real::PositiveInfinity));
                }

                if leader == 0b01000001 {
                    return Ok(Value::Real(c, f, Real::NegativeInfinity));
                }

                if leader >> 6 == 0b00 {
                    match String::from_utf8(bytes) {
                        Err(_) => return Err(ValueReaderError::InvalidFormat(BasicTagType::Real)),
                        Ok(v) => {
                            let has_e = v.chars().any(|c| (c == 'e') || (c == 'E'));
                            let has_p = v.chars().any(|c| (c == '.'));
                            let nr = leader & 0b00111111;

                            match nr {
                                0b01 if !has_e && !has_p => return Ok(Value::Real(c, f, Real::ISO6093(v))),
                                0b10 if !has_e &&  has_p => return Ok(Value::Real(c, f, Real::ISO6093(v))),
                                0b11 if  has_e &&  has_p => return Ok(Value::Real(c, f, Real::ISO6093(v))),
                                _ => return Err(ValueReaderError::InvalidFormat(BasicTagType::Real)),
                            }
                        }
                    }
                }

                if (leader >> 7) == 0 {
                    return Err(ValueReaderError::InvalidFormat(BasicTagType::Real));
                }

                let positive = (leader >> 6) & 1 == 0;
                let mant_shift = ((leader >> 2) & 0b11) as usize;
                let exp_shift = match (leader >> 4) & 0b11 {
                    0b00 => 0,
                    0b01 => 2,
                    0b10 => 3,
                    _ => return Err(ValueReaderError::InvalidFormat(BasicTagType::Real)),
                } as usize;
                let explen = match leader & 0b11 {
                    0 => 1,
                    1 => 2,
                    2 => 3,
                    3 => bytes.remove(0),
                    _ => panic!("Mathematics has failed us.")
                } as usize;

                let mut exponent = Number::from_bytes(&bytes[0..explen]);
                let mut mantissa = Number::from_bytes(&bytes[explen..]);

                exponent <<= exp_shift;
                mantissa <<= mant_shift;

                if !positive {
                    mantissa = -mantissa;
                }

                Ok(Value::Real(c, f, Real::new(exponent, mantissa)))
            }

            _ =>
                unimplemented!("Cannot parse tag {:?}", tag)
        }
    }

    /// Serialize the value to the given buffer. Note that this writes the full definiton of the
    /// value: it's type, it's length, and the value itself.
    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<(), ValueWriterError> {
        match self {
            Value::Boolean(cl, form, v) => {
                Length::from(1).write(buffer)?;
                Tag::Simple(*cl, *form, BasicTagType::Boolean).write(buffer)?;
                if *v {
                    buffer.push(0b10101010);
                } else {
                    buffer.push(0b00000000);
                }
                Ok(())
            }

            Value::Integer(c, f, n) => {
                let mut bytes = n.serialize();
                Length::from(bytes.len()).write(buffer)?;
                Tag::Simple(*c, *f, BasicTagType::Integer).write(buffer)?;
                buffer.append(&mut bytes);
                Ok(())
            }

            Value::Null(c, f) => {
                Length::from(0).write(buffer)?;
                Tag::Simple(*c, *f, BasicTagType::Null).write(buffer)?;
                Ok(())
            }

            Value::Real(c, f, r) => {
                unimplemented!() 
            }
        }
    }
}
