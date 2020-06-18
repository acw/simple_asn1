use crate::bitstring::BitString;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BasicTagType {
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    ObjectDescriptor = 7,
    External = 8,
    Real = 9,
    Enumerated = 10,
    EmbeddedBDV = 11,
    UTF8String = 12,
    RelativeOID = 13,
    Sequence = 16,
    Set = 17,
    NumericString = 18,
    PrintableString = 19,
    TeletexString = 20,
    VideotexString = 21,
    IA5String = 22,
    UTCTime = 23,
    GeneralizedTime = 24,
    GraphicString = 25,
    VisibleString = 26,
    GeneralString = 27,
    UniversalString = 28,
    CharacterString = 29,
    BMPString = 30,
}

#[cfg(test)]
impl Arbitrary for BasicTagType {
    fn arbitrary<G: Gen>(g: &mut G) -> BasicTagType {
        let options = vec![
            BasicTagType::Boolean,
            BasicTagType::Integer,
            BasicTagType::BitString,
            BasicTagType::OctetString,
            BasicTagType::Null,
            BasicTagType::ObjectIdentifier,
            BasicTagType::ObjectDescriptor,
            BasicTagType::External,
            BasicTagType::Real,
            BasicTagType::Enumerated,
            BasicTagType::EmbeddedBDV,
            BasicTagType::UTF8String,
            BasicTagType::RelativeOID,
            BasicTagType::Sequence,
            BasicTagType::Set,
            BasicTagType::NumericString,
            BasicTagType::PrintableString,
            BasicTagType::TeletexString,
            BasicTagType::VideotexString,
            BasicTagType::IA5String,
            BasicTagType::UTCTime,
            BasicTagType::GeneralizedTime,
            BasicTagType::GraphicString,
            BasicTagType::VisibleString,
            BasicTagType::GeneralString,
            BasicTagType::UniversalString,
            BasicTagType::CharacterString,
            BasicTagType::BMPString,
        ];
        let index = usize::arbitrary(g) % options.len();
        options[index]
    }
}

#[derive(Debug, PartialEq)]
pub enum TagTypeParseError {
    UsedReservedSlot,
    UsedSignalSlot,
    ValueTooLarge,
}

impl fmt::Display for TagTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TagTypeParseError::UsedReservedSlot => write!(
                f,
                "Tag type value was one marked reserved in our specification."
            ),
            TagTypeParseError::UsedSignalSlot => write!(
                f,
                "Tag type value was the one that signals a multi-byte tag."
            ),
            TagTypeParseError::ValueTooLarge => {
                write!(f, "Tag type value was much too large for us.")
            }
        }
    }
}

impl TryFrom<u8> for BasicTagType {
    type Error = TagTypeParseError;

    fn try_from(x: u8) -> Result<BasicTagType, TagTypeParseError> {
        match x {
            0 => Err(TagTypeParseError::UsedReservedSlot),
            1 => Ok(BasicTagType::Boolean),
            2 => Ok(BasicTagType::Integer),
            3 => Ok(BasicTagType::BitString),
            4 => Ok(BasicTagType::OctetString),
            5 => Ok(BasicTagType::Null),
            6 => Ok(BasicTagType::ObjectIdentifier),
            7 => Ok(BasicTagType::ObjectDescriptor),
            8 => Ok(BasicTagType::External),
            9 => Ok(BasicTagType::Real),
            10 => Ok(BasicTagType::Enumerated),
            11 => Ok(BasicTagType::EmbeddedBDV),
            12 => Ok(BasicTagType::UTF8String),
            13 => Ok(BasicTagType::RelativeOID),
            14 => Err(TagTypeParseError::UsedReservedSlot),
            15 => Err(TagTypeParseError::UsedReservedSlot),
            16 => Ok(BasicTagType::Sequence),
            17 => Ok(BasicTagType::Set),
            18 => Ok(BasicTagType::NumericString),
            19 => Ok(BasicTagType::PrintableString),
            20 => Ok(BasicTagType::TeletexString),
            21 => Ok(BasicTagType::VideotexString),
            22 => Ok(BasicTagType::IA5String),
            23 => Ok(BasicTagType::UTCTime),
            24 => Ok(BasicTagType::GeneralizedTime),
            25 => Ok(BasicTagType::GraphicString),
            26 => Ok(BasicTagType::VisibleString),
            27 => Ok(BasicTagType::GeneralString),
            28 => Ok(BasicTagType::UniversalString),
            29 => Ok(BasicTagType::CharacterString),
            30 => Ok(BasicTagType::BMPString),
            31 => Err(TagTypeParseError::UsedSignalSlot),
            _ => Err(TagTypeParseError::ValueTooLarge),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

#[cfg(test)]
impl Arbitrary for TagClass {
    fn arbitrary<G: Gen>(g: &mut G) -> TagClass {
        let options = vec![
            TagClass::Universal,
            TagClass::Application,
            TagClass::ContextSpecific,
            TagClass::Private,
        ];
        let index = usize::arbitrary(g) % options.len();
        options[index]
    }
}

#[derive(Debug, PartialEq)]
pub enum TagClassParseError {
    TagClassTooLarge,
}

impl fmt::Display for TagClassParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TagClassParseError::TagClassTooLarge => write!(f, "Tag class value is too big"),
        }
    }
}

impl TryFrom<u8> for TagClass {
    type Error = TagClassParseError;

    fn try_from(x: u8) -> Result<TagClass, TagClassParseError> {
        match x {
            0 => Ok(TagClass::Universal),
            1 => Ok(TagClass::Application),
            2 => Ok(TagClass::ContextSpecific),
            3 => Ok(TagClass::Private),
            _ => Err(TagClassParseError::TagClassTooLarge),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TagForm {
    Primitive = 0,
    Constructed = 1,
}

#[cfg(test)]
impl Arbitrary for TagForm {
    fn arbitrary<G: Gen>(g: &mut G) -> TagForm {
        let options = vec![TagForm::Primitive, TagForm::Constructed];
        let index = usize::arbitrary(g) % options.len();
        options[index]
    }
}

#[derive(Debug, PartialEq)]
pub enum TagFormParseError {
    TagFormTooLarge,
}

impl fmt::Display for TagFormParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TagFormParseError::TagFormTooLarge => write!(f, "Tag form value is more than one bit"),
        }
    }
}

impl TryFrom<u8> for TagForm {
    type Error = TagFormParseError;

    fn try_from(x: u8) -> Result<TagForm, TagFormParseError> {
        match x {
            0 => Ok(TagForm::Primitive),
            1 => Ok(TagForm::Constructed),
            _ => Err(TagFormParseError::TagFormTooLarge),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Tag {
    Simple(TagClass, TagForm, BasicTagType),
    Extended(TagClass, TagForm, Vec<u8>),
}

#[cfg(test)]
impl Arbitrary for Tag {
    fn arbitrary<G: Gen>(g: &mut G) -> Tag {
        if g.next_u32() & 1 == 0 {
            Tag::Simple(
                TagClass::arbitrary(g),
                TagForm::arbitrary(g),
                BasicTagType::arbitrary(g),
            )
        } else {
            let mut basic_vec = Vec::<u8>::arbitrary(g);
            basic_vec.push(u8::arbitrary(g)); // just to ensure there's at least one
            Tag::Extended(TagClass::arbitrary(g), TagForm::arbitrary(g), basic_vec)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TagReaderError {
    NotEnoughData,
    InappropriateExtendedLength,
    TagClassProblem(TagClassParseError),
    TagFormProblem(TagFormParseError),
    TagTypeProblem(TagTypeParseError),
}

impl From<TagClassParseError> for TagReaderError {
    fn from(x: TagClassParseError) -> TagReaderError {
        TagReaderError::TagClassProblem(x)
    }
}

impl From<TagFormParseError> for TagReaderError {
    fn from(x: TagFormParseError) -> TagReaderError {
        TagReaderError::TagFormProblem(x)
    }
}

impl From<TagTypeParseError> for TagReaderError {
    fn from(x: TagTypeParseError) -> TagReaderError {
        TagReaderError::TagTypeProblem(x)
    }
}

#[derive(Debug, PartialEq)]
pub enum TagSerializationError {
    NoExtendedTag,
    ExtendedTagTooSmall,
    InternalError,
}

impl Tag {
    pub fn read<I: Iterator<Item = u8>>(it: &mut I) -> Result<Tag, TagReaderError> {
        match it.next() {
            None => Err(TagReaderError::NotEnoughData),
            Some(b) => {
                let class = TagClass::try_from(b >> 6)?;
                let form = TagForm::try_from((b >> 5) & 1)?;
                let tag = b & 0b11111;

                if tag == 31 {
                    let mut bitstr = BitString::new();

                    // OK, here's an example of what we have to do here.
                    // Imagine that this tag was four bytes [67,33,30,42]:
                    //
                    //   01000011_00100001_00011110_00101010
                    //
                    // To encode them, we're going to pad the front, and then
                    // group them into sevens:
                    //
                    //   0000100_0011001_0000100_0111100_0101010
                    //      4       25      4       60      42
                    //
                    // We'll then set the high bits on the first 4, giving us
                    // an input to this function of:
                    //     132     153     132     188      42
                    //
                    // On the flip side, to parse, we need to first turn these
                    // back into 8 bit quantities:
                    //    00001000_01100100_00100011_11000101_010
                    let mut ended_clean = false;

                    while let Some(b) = it.next() {
                        bitstr.push_bits(7, b);
                        if b & 0b1000_0000 == 0 {
                            ended_clean = true;
                            break;
                        }
                    }

                    if !ended_clean {
                        return Err(TagReaderError::NotEnoughData);
                    }
                    //
                    // which is off by three.
                    let padding = bitstr.len() % 8;
                    //
                    // So if we pull three bits off the front we get back to:
                    //    01000011_00100001_00011110_00101010
                    //
                    let mut bititer = bitstr.bits().skip(padding);
                    let mut res = Vec::new();
                    let mut work_byte = 0;
                    let mut count = 0;

                    while let Some(x) = bititer.next() {
                        work_byte = (work_byte << 1) | (x & 1);
                        count += 1;
                        if count == 8 {
                            res.push(work_byte);
                            count = 0;
                            work_byte = 0;
                        }
                    }

                    if count != 0 {
                        return Err(TagReaderError::InappropriateExtendedLength);
                    }

                    return Ok(Tag::Extended(class, form, res));
                }

                Ok(Tag::Simple(class, form, BasicTagType::try_from(tag)?))
            }
        }
    }

    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<(), TagSerializationError> {
        match self {
            Tag::Simple(class, form, basic) => {
                let class_val = (*class as u8) << 6;
                let form_val = (*form as u8) << 5;
                let basic_val = *basic as u8;

                buffer.push(class_val | form_val | basic_val);
                Ok(())
            }
            Tag::Extended(class, form, value) => {
                let class_val = (*class as u8) << 6;
                let form_val = (*form as u8) << 5;
                let basic_val = 0b00011111;

                if value.len() == 0 {
                    return Err(TagSerializationError::NoExtendedTag);
                }

                buffer.push(class_val | form_val | basic_val);
                let original_length = value.len() * 8;
                let mut work_byte = 0;
                let mut bits_added = if original_length % 7 == 0 {
                    0
                } else {
                    7 - (original_length % 7)
                };
                let mut bitstream = BitString::from(value.iter().map(|x| *x)).bits().peekable();

                while bitstream.peek().is_some() {
                    while bits_added < 7 {
                        match bitstream.next() {
                            None => return Err(TagSerializationError::InternalError),
                            Some(b) => {
                                bits_added += 1;
                                work_byte = (work_byte << 1) | b;
                            }
                        }
                    }

                    buffer.push(0b1000_0000 | work_byte);
                    bits_added = 0;
                    work_byte = 0;
                }

                let last_idx = buffer.len() - 1;
                buffer[last_idx] &= 0b0111_1111;

                Ok(())
            }
        }
    }
}

macro_rules! item_u8_item {
    ($name: ident, $type: ident) => {
        #[cfg(test)]
        quickcheck! {
            fn $name(t: $type) -> bool {
                let t8 = t as u8;
                match $type::try_from(t8) {
                    Err(_) => false,
                    Ok(t2) => t == t2,
                }
            }
        }
    };
}

item_u8_item!(tag_u8_tag, BasicTagType);
item_u8_item!(form_u8_form, TagForm);
item_u8_item!(class_u8_class, TagClass);

#[cfg(test)]
quickcheck! {
    fn tag_bytes_tag(t: Tag) -> bool {
        let mut bytes = Vec::new();
        let () = t.write(&mut bytes).unwrap();
        let mut byteiter = bytes.iter().map(|x| *x);
        match Tag::read(&mut byteiter) {
            Err(e) => {
                // println!("Error result: {:?}", e);
                false
            }
            Ok(t2) => {
                // println!("Result: {:?}", t2);
                t == t2
            }
        }
    }
}
