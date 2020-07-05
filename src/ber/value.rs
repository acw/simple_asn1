use crate::ber::length::{Length, LengthReaderError, LengthWriterError};
use crate::ber::tag::{Tag, TagClass, TagForm, TagReaderError, TagSerializationError, BasicTagType};
use crate::lift_error;
use crate::number::Number;
use crate::util::BufferReader;

pub enum Value {
    Boolean(TagClass, TagForm, bool),
    Integer(TagClass, TagForm, Number),
    Null(TagClass, TagForm),
}

pub enum ValueReaderError {
    LengthIncompatible,
    LengthTooBig,
    NotEnoughData,
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
        let bytes: Vec<u8> = match length.read_buffer(it) {
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
        }
    }
}
