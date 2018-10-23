//! A small ASN.1 parsing library for Rust. In particular, this library is used
//! to translate the binary DER encoding of an ASN.1-formatted document into the
//! core primitives of ASN.1. It is assumed that you can do what you need to
//! from there.
//!
//! The critical items for this document are the traits `ToASN1` and `FromASN1`.
//! The first takes your data type and encodes it into a `Vec` of simple ASN.1
//! structures (`ASN1Block`s). The latter inverts the process.
//!
//! Items that implement `ToASN1` can be used with the function `der_encode`
//! to provide single-step encoding of a data type to binary DER encoding.
//! Similarly, items that are `FromASN` can be single-step decoded using
//! the helper function `der_decode`.
//!
//! You can implement one or both traits, depending on your needs. If you do
//! implement both, the obvious encode/decode quickcheck property is strongly
//! advised.
//!
//! For decoding schemes that require the actual bytes associated with the
//! binary representation, we also provide `FromASN1WithBody`. This can be
//! used with the offset information in the primitive `ASN1Block`s to, for
//! example, validate signatures in X509 documents.
//!
//! Finally, this library supports ASN.1 class information. I'm still not sure
//! why it's useful, but there it is.
//!
//! Please send any bug reports, patches, and curses to the GitHub repository
//! at <code>https://github.com/acw/simple_asn1</code>.
extern crate chrono;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[cfg(test)]
extern crate rand;

use chrono::{DateTime,TimeZone,Utc};
use num::{BigInt,BigUint,FromPrimitive,One,ToPrimitive,Zero};
use std::iter::FromIterator;
use std::mem::size_of;

/// An ASN.1 block class.
///
/// I'm not sure if/when these are used, but here they are in case you want
/// to do something with them.
#[derive(Clone,Copy,Debug,PartialEq)]
pub enum ASN1Class { Universal, Application, ContextSpecific, Private }

/// A primitive block from ASN.1.
///
/// Primitive blocks all contain the class of the block and the offset from
/// the beginning of the parsed document, followed by whatever data is
/// associated with the block. The latter should be fairly self-explanatory,
/// so let's discuss the offset.
///
/// The offset is only valid during the reading process. It is ignored for
/// the purposes of encoding blocks into their binary form. It is also
/// ignored for the purpose of comparisons via `==`. It is included entirely
/// to support the parsing of things like X509 certificates, in which it is
/// necessary to know when particular blocks end.
#[derive(Clone,Debug)]
pub enum ASN1Block {
    Boolean(ASN1Class, usize, bool),
    Integer(ASN1Class, usize, BigInt),
    BitString(ASN1Class, usize, usize, Vec<u8>),
    OctetString(ASN1Class, usize, Vec<u8>),
    Null(ASN1Class, usize),
    ObjectIdentifier(ASN1Class, usize, OID),
    UTF8String(ASN1Class, usize, String),
    PrintableString(ASN1Class, usize, String),
    TeletexString(ASN1Class, usize, String),
    IA5String(ASN1Class, usize, String),
    UTCTime(ASN1Class, usize, DateTime<Utc>),
    GeneralizedTime(ASN1Class, usize, DateTime<Utc>),
    UniversalString(ASN1Class, usize, String),
    BMPString(ASN1Class, usize, String),
    Sequence(ASN1Class, usize, Vec<ASN1Block>),
    Set(ASN1Class, usize, Vec<ASN1Block>),
    Unknown(ASN1Class, usize, BigUint, Vec<u8>)
}

impl ASN1Block {
    /// Get the class associated with the given ASN1Block, regardless of what
    /// kind of block it is.
    pub fn class(&self) -> ASN1Class {
        match self {
            &ASN1Block::Boolean(c,_,_)          => c,
            &ASN1Block::Integer(c,_,_)          => c,
            &ASN1Block::BitString(c,_,_,_)      => c,
            &ASN1Block::OctetString(c,_,_)      => c,
            &ASN1Block::Null(c,_)               => c,
            &ASN1Block::ObjectIdentifier(c,_,_) => c,
            &ASN1Block::UTF8String(c,_,_)       => c,
            &ASN1Block::PrintableString(c,_,_)  => c,
            &ASN1Block::TeletexString(c,_,_)    => c,
            &ASN1Block::IA5String(c,_,_)        => c,
            &ASN1Block::UTCTime(c,_,_)          => c,
            &ASN1Block::GeneralizedTime(c,_,_)  => c,
            &ASN1Block::UniversalString(c,_,_)  => c,
            &ASN1Block::BMPString(c,_,_)        => c,
            &ASN1Block::Sequence(c,_,_)         => c,
            &ASN1Block::Set(c,_,_)              => c,
            &ASN1Block::Unknown(c,_,_,_)        => c
        }
    }

    /// Get the starting offset associated with the given ASN1Block, regardless
    /// of what kind of block it is.
    pub fn offset(&self) -> usize {
        match self {
            &ASN1Block::Boolean(_,o,_)          => o,
            &ASN1Block::Integer(_,o,_)          => o,
            &ASN1Block::BitString(_,o,_,_)      => o,
            &ASN1Block::OctetString(_,o,_)      => o,
            &ASN1Block::Null(_,o)               => o,
            &ASN1Block::ObjectIdentifier(_,o,_) => o,
            &ASN1Block::UTF8String(_,o,_)       => o,
            &ASN1Block::PrintableString(_,o,_)  => o,
            &ASN1Block::TeletexString(_,o,_)    => o,
            &ASN1Block::IA5String(_,o,_)        => o,
            &ASN1Block::UTCTime(_,o,_)          => o,
            &ASN1Block::GeneralizedTime(_,o,_)  => o,
            &ASN1Block::UniversalString(_,o,_)  => o,
            &ASN1Block::BMPString(_,o,_)        => o,
            &ASN1Block::Sequence(_,o,_)         => o,
            &ASN1Block::Set(_,o,_)              => o,
            &ASN1Block::Unknown(_,o,_,_)        => o
        }
    }
}

impl PartialEq for ASN1Block {
    fn eq(&self, other: &ASN1Block) -> bool {
        match (self, other) {
            (&ASN1Block::Boolean(a1,_,b1),
             &ASN1Block::Boolean(a2,_,b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::Integer(a1,_,ref b1),
             &ASN1Block::Integer(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::BitString(a1,_,b1,ref c1),
             &ASN1Block::BitString(a2,_,b2,ref c2)) =>
                (a1 == a2) && (b1 == b2) && (c1 == c2),
            (&ASN1Block::OctetString(a1,_,ref b1),
             &ASN1Block::OctetString(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::Null(a1,_),
             &ASN1Block::Null(a2,_)) =>
                (a1 == a2),
            (&ASN1Block::ObjectIdentifier(a1,_,ref b1),
             &ASN1Block::ObjectIdentifier(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::UTF8String(a1,_,ref b1),
             &ASN1Block::UTF8String(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::PrintableString(a1,_,ref b1),
             &ASN1Block::PrintableString(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::TeletexString(a1,_,ref b1),
             &ASN1Block::TeletexString(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::IA5String(a1,_,ref b1),
             &ASN1Block::IA5String(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::UTCTime(a1,_,ref b1),
             &ASN1Block::UTCTime(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::GeneralizedTime(a1,_,ref b1),
             &ASN1Block::GeneralizedTime(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::UniversalString(a1,_,ref b1),
             &ASN1Block::UniversalString(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::BMPString(a1,_,ref b1),
             &ASN1Block::BMPString(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::Sequence(a1,_,ref b1),
             &ASN1Block::Sequence(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::Set(a1,_,ref b1),
             &ASN1Block::Set(a2,_,ref b2)) =>
                (a1 == a2) && (b1 == b2),
            (&ASN1Block::Unknown(a1,_,ref b1,ref c1),
             &ASN1Block::Unknown(a2,_,ref b2,ref c2)) =>
                (a1 == a2) && (b1 == b2) && (c1 == c2),
            _ =>
                false
        }
    }
}

/// An ASN.1 OID.
#[derive(Clone,Debug,PartialEq)]
pub struct OID(Vec<BigUint>);

impl OID {
    /// Generate an ASN.1. The vector should be in the obvious format,
    /// with each component going left-to-right.
    pub fn new(x: Vec<BigUint>) -> OID {
        OID(x)
    }
}

impl<'a> PartialEq<OID> for &'a OID {
    fn eq(&self, v2: &OID) -> bool {
        let &&OID(ref vec1) = self;
        let &OID(ref vec2) = v2;

        if vec1.len() != vec2.len() {
            return false
        }

        for i in 0..vec1.len() {
            if vec1[i] != vec2[i] {
                return false;
            }
        }

        true
    }
}

/// A handy macro for generating OIDs from a sequence of `u64`s.
///
/// Usage: oid!(1,2,840,113549,1,1,1) creates an OID that matches
/// 1.2.840.113549.1.1.1. (Coincidentally, this is RSA.)
#[macro_export]
macro_rules! oid {
    ( $( $e: expr ),* ) => {{
        let mut res = Vec::new();

        $(
            res.push(BigUint::from($e as u64));
        )*
        OID::new(res)
    }};
}

const PRINTABLE_CHARS: &'static str =
  "ABCDEFGHIJKLMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+,-./:=? ";

/// An error that can arise decoding ASN.1 primitive blocks.
#[derive(Clone,Debug,PartialEq)]
pub enum ASN1DecodeErr {
    EmptyBuffer,
    BadBooleanLength,
    LengthTooLarge,
    UTF8DecodeFailure,
    PrintableStringDecodeFailure,
    InvalidDateValue(String)
}

/// An error that can arise encoding ASN.1 primitive blocks.
#[derive(Clone,Debug,PartialEq)]
pub enum ASN1EncodeErr {
    ObjectIdentHasTooFewFields,
    ObjectIdentVal1TooLarge,
    ObjectIdentVal2TooLarge
}

/// Translate a binary blob into a series of `ASN1Block`s, or provide an
/// error if it didn't work.
pub fn from_der(i: &[u8]) -> Result<Vec<ASN1Block>,ASN1DecodeErr> {
    from_der_(i, 0)
}

fn from_der_(i: &[u8], start_offset: usize)
    -> Result<Vec<ASN1Block>,ASN1DecodeErr>
{
    let mut result: Vec<ASN1Block> = Vec::new();
    let mut index:  usize          = 0;
    let     len                    = i.len();

    while index < len {
        let soff = start_offset + index;
        let (tag, class) = decode_tag(i, &mut index);
        let len = decode_length(i, &mut index)?;
        let body = &i[index .. (index + len)];

        match tag.to_u8() {
            // BOOLEAN
            Some(0x01) => {
                if len != 1 {
                    return Err(ASN1DecodeErr::BadBooleanLength);
                }
                result.push(ASN1Block::Boolean(class, soff, body[0] != 0));
            }
            // INTEGER
            Some(0x02) => {
                let res = BigInt::from_signed_bytes_be(&body);
                result.push(ASN1Block::Integer(class, soff, res));
            }
            // BIT STRING
            Some(0x03) if body.len() == 0 => {
                result.push(ASN1Block::BitString(class, soff, 0, Vec::new()))
            }
            Some(0x03) => {
                let bits = (&body[1..]).to_vec();
                let nbits = (bits.len() * 8) - (body[0] as usize);
                result.push(ASN1Block::BitString(class, soff, nbits, bits))
            }
            // OCTET STRING
            Some(0x04) => {
                result.push(ASN1Block::OctetString(class, soff, body.to_vec()))
            }
            // NULL
            Some(0x05) => {
                result.push(ASN1Block::Null(class, soff));
            }
            // OBJECT IDENTIFIER
            Some(0x06) => {
                let mut value1 = BigUint::zero();
                let mut value2 = BigUint::from_u8(body[0]).unwrap();
                let mut oidres = Vec::new();
                let mut bindex = 1;

                if body[0] >= 40 {
                    if body[0] < 80 {
                        value1 = BigUint::one();
                        value2 = value2 - BigUint::from_u8(40).unwrap();
                    } else {
                        value1 = BigUint::from_u8(2).unwrap();
                        value2 = value2 - BigUint::from_u8(80).unwrap();
                    }
                }

                oidres.push(value1);
                oidres.push(value2);
                while bindex < body.len() {
                    oidres.push(decode_base127(body, &mut bindex));
                }
                let res = OID(oidres);

                result.push(ASN1Block::ObjectIdentifier(class, soff, res))
            }
            // UTF8STRING
            Some(0x0C) => {
                match String::from_utf8(body.to_vec()) {
                    Ok(v) =>
                        result.push(ASN1Block::UTF8String(class, soff, v)),
                    Err(_) =>
                        return Err(ASN1DecodeErr::UTF8DecodeFailure)
                }
            }
            // SEQUENCE
            Some(0x10) => {
                match from_der_(body, start_offset + index) {
                    Ok(items) =>
                        result.push(ASN1Block::Sequence(class, soff, items)),
                    Err(e) =>
                        return Err(e)
                }
            }
            // SET
            Some(0x11) => {
                match from_der_(body, start_offset + index) {
                    Ok(items) =>
                        result.push(ASN1Block::Set(class, soff, items)),
                    Err(e) =>
                        return Err(e)
                }
            }
            // PRINTABLE STRING
            Some(0x13) => {
                let mut res = String::new();
                let mut val = body.iter().map(|x| *x as char);

                for c in val {
                    if PRINTABLE_CHARS.contains(c) {
                        res.push(c);
                    } else {
                        return Err(ASN1DecodeErr::PrintableStringDecodeFailure);
                    }
                }
                result.push(ASN1Block::PrintableString(class, soff, res));
            }
            // TELETEX STRINGS
            Some(0x14) => {
                match String::from_utf8(body.to_vec()) {
                    Ok(v) =>
                        result.push(ASN1Block::TeletexString(class, soff, v)),
                    Err(_) =>
                        return Err(ASN1DecodeErr::UTF8DecodeFailure)
                }
            }
            // IA5 (ASCII) STRING
            Some(0x16) => {
                let val = body.iter().map(|x| *x as char);
                let res = String::from_iter(val);
                result.push(ASN1Block::IA5String(class, soff, res))
            }
            // UTCTime
            Some(0x17) => {
                if body.len() != 13 {
                    return Err(ASN1DecodeErr::InvalidDateValue(format!("{}",body.len())));
                }

                let v = String::from_iter(body.iter().map(|x| *x as char));
                match Utc.datetime_from_str(&v, "%y%m%d%H%M%SZ") {
                    Err(_) =>
                        return Err(ASN1DecodeErr::InvalidDateValue(v)),
                    Ok(t) => {
                        result.push(ASN1Block::UTCTime(class, soff, t))
                    }
                }
            }
            // GeneralizedTime
            Some(0x18) => {
                if body.len() < 15 {
                    return Err(ASN1DecodeErr::InvalidDateValue(format!("{}",body.len())));
                }

                let mut v = String::from_iter(body.iter().map(|x| *x as char));
                // We need to add padding back to the string if it's not there.
                if v.find('.').is_none() {
                    v.insert(15, '.')
                }
                while v.len() < 25 {
                    let idx = v.len() - 1;
                    v.insert(idx, '0');
                }
                match Utc.datetime_from_str(&v, "%Y%m%d%H%M%S.%fZ") {
                    Err(_) =>
                        return Err(ASN1DecodeErr::InvalidDateValue(v)),
                    Ok(t) => {
                        result.push(ASN1Block::GeneralizedTime(class, soff, t))
                    }
                }
            }
            // UNIVERSAL STRINGS
            Some(0x1C) => {
                match String::from_utf8(body.to_vec()) {
                    Ok(v) =>
                        result.push(ASN1Block::UniversalString(class, soff, v)),
                    Err(_) =>
                        return Err(ASN1DecodeErr::UTF8DecodeFailure)
                }
            }
            // UNIVERSAL STRINGS
            Some(0x1E) => {
                match String::from_utf8(body.to_vec()) {
                    Ok(v) =>
                        result.push(ASN1Block::BMPString(class, soff, v)),
                    Err(_) =>
                        return Err(ASN1DecodeErr::UTF8DecodeFailure)
                }
            }
            // Dunno.
            _ => {
                result.push(ASN1Block::Unknown(class, soff, tag, body.to_vec()));
            }
        }
        index += len;
    }

    if result.is_empty() {
        Err(ASN1DecodeErr::EmptyBuffer)
    } else {
        Ok(result)
    }
}

fn decode_tag(i: &[u8], index: &mut usize) -> (BigUint, ASN1Class) {
    let tagbyte = i[*index];
    let class   = decode_class(tagbyte);
    let basetag = tagbyte & 0b11111;

    *index += 1;
    if basetag == 0b11111 {
        let res = decode_base127(i, index);
        (res, class)
    } else {
        (BigUint::from(basetag), class)
    }
}

fn decode_base127(i: &[u8], index: &mut usize) -> BigUint {
    let mut res = BigUint::zero();

    loop {
        let nextbyte = i[*index];

        *index += 1;
        res = (res << 7) + BigUint::from(nextbyte & 0x7f);
        if (nextbyte & 0x80) == 0 {
            return res;
        }
    }
}

fn decode_class(i: u8) -> ASN1Class {
    match i >> 6 {
        0b00 => ASN1Class::Universal,
        0b01 => ASN1Class::Application,
        0b10 => ASN1Class::ContextSpecific,
        0b11 => ASN1Class::Private,
        _    => panic!("The universe is broken.")
    }
}

fn decode_length(i: &[u8], index: &mut usize) -> Result<usize,ASN1DecodeErr> {
    let startbyte = i[*index];

    // NOTE: Technically, this size can be much larger than a usize.
    // However, our whole universe starts to break down if we get
    // things that big. So we're boring, and only accept lengths
    // that fit within a usize.
    *index += 1;
    if startbyte >= 0x80 {
        let mut lenlen = (startbyte & 0x7f) as usize;
        let mut res = 0;

        if lenlen > size_of::<usize>() {
            return Err(ASN1DecodeErr::LengthTooLarge);
        }

        while lenlen > 0 {
            res = (res << 8) + (i[*index] as usize);

            *index += 1;
            lenlen -= 1;
        }

        Ok(res)
    } else {
        Ok(startbyte as usize)
    }
}

/// Given an `ASN1Block`, covert it to its DER encoding, or return an error
/// if something broke along the way.
pub fn to_der(i: &ASN1Block) -> Result<Vec<u8>,ASN1EncodeErr> {
    match i {
        // BOOLEAN
        &ASN1Block::Boolean(cl, _, val) => {
            let inttag = BigUint::one();
            let mut tagbytes = encode_tag(cl, &inttag);
            tagbytes.push(1);
            tagbytes.push(if val { 0xFF } else { 0x00 });
            Ok(tagbytes)
        }
        // INTEGER
        &ASN1Block::Integer(cl, _, ref int) => {
            let mut base = int.to_signed_bytes_be();
            let mut lenbytes = encode_len(base.len());
            let     inttag   = BigUint::from_u8(0x02).unwrap();
            let mut tagbytes = encode_tag(cl, &inttag);

            let mut result = Vec::new();
            result.append(&mut tagbytes);
            result.append(&mut lenbytes);
            result.append(&mut base);
            Ok(result)
        }
        // BIT STRING
        &ASN1Block::BitString(cl, _, bits, ref vs) => {
            let inttag = BigUint::from_u8(0x03).unwrap();
            let mut tagbytes = encode_tag(cl, &inttag);

            if bits == 0 {
                tagbytes.push(0);
                Ok(tagbytes)
            } else {
                let mut lenbytes = encode_len(vs.len() + 1);
                let     nbits    = (vs.len() * 8) - bits;

                let mut result = Vec::new();
                result.append(&mut tagbytes);
                result.append(&mut lenbytes);
                result.push(nbits as u8);
                result.extend(vs.iter());
                Ok(result)
            }
        }
        // OCTET STRING
        &ASN1Block::OctetString(cl, _, ref bytes) => {
            let inttag = BigUint::from_u8(0x04).unwrap();
            let mut tagbytes = encode_tag(cl, &inttag);
            let mut lenbytes = encode_len(bytes.len());

            let mut result = Vec::new();
            result.append(&mut tagbytes);
            result.append(&mut lenbytes);
            result.extend(bytes.iter());
            Ok(result)
        }
        // NULL
        &ASN1Block::Null(cl, _) => {
            let inttag = BigUint::from_u8(0x05).unwrap();
            let mut result = encode_tag(cl, &inttag);
            result.push(0);
            Ok(result)
        }
        // OBJECT IDENTIFIER
        &ASN1Block::ObjectIdentifier(cl, _, OID(ref nums)) => {
            match (nums.get(0), nums.get(1)) {
                (Some(v1), Some(v2)) => {
                    let two = BigUint::from_u8(2).unwrap();

                    // first, validate that the first two items meet spec
                    if v1 > &two {
                        return Err(ASN1EncodeErr::ObjectIdentVal1TooLarge)
                    }

                    let u175 = BigUint::from_u8(175).unwrap();
                    let u39 = BigUint::from_u8(39).unwrap();
                    let bound = if v1 == &two { u175 } else { u39 };

                    if v2 > &bound {
                        return Err(ASN1EncodeErr::ObjectIdentVal2TooLarge);
                    }

                    // the following unwraps must be safe, based on the
                    // validation above.
                    let value1 = v1.to_u8().unwrap();
                    let value2 = v2.to_u8().unwrap();
                    let byte1  = (value1 * 40) + value2;

                    // now we can build all the rest of the body
                    let mut body = vec![byte1];
                    for num in nums.iter().skip(2) {
                        let mut local = encode_base127(&num);
                        body.append(&mut local);
                    }

                    // now that we have the body, we can build the header
                    let inttag = BigUint::from_u8(0x06).unwrap();
                    let mut result = encode_tag(cl, &inttag);
                    let mut lenbytes = encode_len(body.len());

                    result.append(&mut lenbytes);
                    result.append(&mut body);

                    Ok(result)
                }
                _ => {
                    Err(ASN1EncodeErr::ObjectIdentHasTooFewFields)
                }
            }
        }
        // SEQUENCE
        &ASN1Block::Sequence(cl, _, ref items) => {
            let mut body = Vec::new();

            // put all the subsequences into a block
            for x in items.iter() {
                let mut bytes = to_der(x)?;
                body.append(&mut bytes);
            }

            let inttag = BigUint::from_u8(0x10).unwrap();
            let mut lenbytes = encode_len(body.len());
            let mut tagbytes = encode_tag(cl, &inttag);

            let mut res = Vec::new();
            res.append(&mut tagbytes);
            res.append(&mut lenbytes);
            res.append(&mut body);
            Ok(res)
        }
        // SET
        &ASN1Block::Set(cl, _, ref items) => {
            let mut body = Vec::new();

            // put all the subsequences into a block
            for x in items.iter() {
                let mut bytes = to_der(x)?;
                body.append(&mut bytes);
            }

            let inttag = BigUint::from_u8(0x11).unwrap();
            let mut lenbytes = encode_len(body.len());
            let mut tagbytes = encode_tag(cl, &inttag);

            let mut res = Vec::new();
            res.append(&mut tagbytes);
            res.append(&mut lenbytes);
            res.append(&mut body);
            Ok(res)
        }
        &ASN1Block::UTCTime(cl, _, ref time) => {
            let mut body = time.format("%y%m%d%H%M%SZ").to_string().into_bytes();
            let inttag = BigUint::from_u8(0x17).unwrap();
            let mut lenbytes = encode_len(body.len());
            let mut tagbytes = encode_tag(cl, &inttag);

            let mut res = Vec::new();
            res.append(&mut tagbytes);
            res.append(&mut lenbytes);
            res.append(&mut body);
            Ok(res)
        }
        &ASN1Block::GeneralizedTime(cl, _, ref time) => {
            let base = time.format("%Y%m%d%H%M%S.%f").to_string();
            let zclear = base.trim_right_matches('0');
            let dclear = zclear.trim_right_matches('.');
            let mut body = format!("{}Z", dclear).into_bytes();

            let inttag = BigUint::from_u8(0x18).unwrap();
            let mut lenbytes = encode_len(body.len());
            let mut tagbytes = encode_tag(cl, &inttag);

            let mut res = Vec::new();
            res.append(&mut tagbytes);
            res.append(&mut lenbytes);
            res.append(&mut body);
            Ok(res)
        }
        &ASN1Block::UTF8String(cl, _, ref str)      =>
            encode_asn1_string(0x0c, false, cl, str),
        &ASN1Block::PrintableString(cl, _, ref str) =>
            encode_asn1_string(0x13, true,  cl, str),
        &ASN1Block::TeletexString(cl, _, ref str)   =>
            encode_asn1_string(0x14, false, cl, str),
        &ASN1Block::UniversalString(cl, _, ref str) =>
            encode_asn1_string(0x1c, false, cl, str),
        &ASN1Block::IA5String(cl, _, ref str)       =>
            encode_asn1_string(0x16, true,  cl, str),
        &ASN1Block::BMPString(cl, _, ref str)       =>
            encode_asn1_string(0x1e, false, cl, str),
        // Unknown blocks
        &ASN1Block::Unknown(class, _, ref tag, ref bytes) => {
            let mut tagbytes = encode_tag(class, &tag);
            let mut lenbytes = encode_len(bytes.len());

            let mut res = Vec::new();
            res.append(&mut tagbytes);
            res.append(&mut lenbytes);
            res.extend(bytes.iter());
            Ok(res)
        }
    }
}

fn encode_asn1_string(tag: u8, force_chars: bool, c: ASN1Class, s: &String)
    -> Result<Vec<u8>,ASN1EncodeErr>
{
    let mut body = { if force_chars {
                         let mut out = Vec::new();

                         for c in s.chars() {
                             out.push(c as u8);
                         }
                         out
                     } else {
                         s.clone().into_bytes()
                     } };
    let inttag = BigUint::from_u8(tag).unwrap();
    let mut lenbytes = encode_len(body.len());
    let mut tagbytes = encode_tag(c, &inttag);

    let mut res = Vec::new();
    res.append(&mut tagbytes);
    res.append(&mut lenbytes);
    res.append(&mut body);
    Ok(res)
}

fn encode_tag(c: ASN1Class, t: &BigUint) -> Vec<u8> {
    let cbyte = encode_class(c);

    match t.to_u8() {
        Some(x) if x < 31 => {
            vec![cbyte | x]
        }
        _ => {
            let mut res = encode_base127(t);
            res.insert(0, cbyte | 0b00011111);
            res
        }
    }
}

fn encode_base127(v: &BigUint) -> Vec<u8> {
    let mut acc = v.clone();
    let mut res = Vec::new();
    let u128 = BigUint::from_u8(128).unwrap();
    let zero = BigUint::zero();

    while acc > zero {
        // we build this vector backwards
        let digit = &acc % &u128;
        acc = acc >> 7;

        match digit.to_u8() {
            None =>
                panic!("7 bits don't fit into 8, cause ..."),
            Some(x) if res.is_empty() =>
                res.push(x),
            Some(x) =>
                res.push(x | 0x80)
        }
    }

    res.reverse();
    res
}

fn encode_class(c: ASN1Class) -> u8 {
    match c {
        ASN1Class::Universal       => 0b00000000,
        ASN1Class::Application     => 0b01000000,
        ASN1Class::ContextSpecific => 0b10000000,
        ASN1Class::Private         => 0b11000000,
    }
}


fn encode_len(x: usize) -> Vec<u8> {
    if x < 128 {
        vec![x as u8]
    } else {
        let mut bstr = Vec::new();
        let mut work = x;

        // convert this into bytes, backwards
        while work > 0 {
            bstr.push(work as u8);
            work = work >> 8;
        }

        // encode the front of the length
        let len = bstr.len() as u8;
        bstr.push(len | 0x80);

        // and then reverse it into the right order
        bstr.reverse();
        bstr
    }
}

// ----------------------------------------------------------------------------

/// A trait defining types that can be decoded from an `ASN1Block` stream,
/// assuming they also have access to the underlying bytes making up the
/// stream.
pub trait FromASN1WithBody : Sized {
    type Error : From<ASN1DecodeErr>;

    fn from_asn1_with_body<'a>(v: &'a[ASN1Block], _b: &[u8])
        -> Result<(Self,&'a[ASN1Block]),Self::Error>;
}

/// A trait defining types that can be decoded from an `ASN1Block` stream.
/// Any member of this trait is also automatically a member of
/// `FromASN1WithBody`, as it can obviously just ignore the body.
pub trait FromASN1 : Sized {
    type Error : From<ASN1DecodeErr>;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(Self,&[ASN1Block]),Self::Error>;
}

impl<T: FromASN1> FromASN1WithBody for T {
    type Error = T::Error;

    fn from_asn1_with_body<'a>(v: &'a[ASN1Block], _b: &[u8])
        -> Result<(T,&'a[ASN1Block]),T::Error>
    {
        T::from_asn1(v)
    }
}

/// Automatically decode a type via DER encoding, assuming that the type
/// is a member of `FromASN1` or `FromASN1WithBody`.
pub fn der_decode<T: FromASN1WithBody>(v: &[u8]) -> Result<T,T::Error>
{
    let vs = from_der(v)?;
    T::from_asn1_with_body(&vs, v).and_then(|(a,_)| Ok(a))
}

/// The set of types that can automatically converted into a sequence
/// of `ASN1Block`s. You should probably use to_asn1() but implement
/// to_asn1_class(). The former has a default implementation that passes
/// `ASN1Class::Universal` as the tag to use, which should be good for
/// most people.
pub trait ToASN1 {
    type Error : From<ASN1EncodeErr>;

    fn to_asn1(&self) -> Result<Vec<ASN1Block>,Self::Error> {
        self.to_asn1_class(ASN1Class::Universal)
    }
    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,Self::Error>;
}

/// Automatically encode a type into binary via DER encoding, assuming
/// that the type is a member of `ToASN1`.
pub fn der_encode<T: ToASN1>(v: &T) -> Result<Vec<u8>,T::Error>
{
    let blocks = T::to_asn1(&v)?;
    let mut res = Vec::new();

    for block in blocks {
        let mut x = to_der(&block)?;
        res.append(&mut x);
    }

    Ok(res)
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::offset::LocalResult;
    use quickcheck::{Arbitrary,Gen};
    use std::fs::File;
    use std::io::Read;
    use rand::{Rng, distributions::Standard};
    use super::*;

    impl Arbitrary for ASN1Class {
        fn arbitrary<G: Gen>(g: &mut G) -> ASN1Class {
            match g.gen::<u8>() % 4 {
                0 => ASN1Class::Private,
                1 => ASN1Class::ContextSpecific,
                2 => ASN1Class::Universal,
                3 => ASN1Class::Application,
                _ => panic!("I weep for a broken life.")
            }
        }
    }

    quickcheck! {
        fn class_encdec_roundtrips(c: ASN1Class) -> bool {
            c == decode_class(encode_class(c.clone()))
        }

        fn class_decenc_roundtrips(v: u8) -> bool {
            (v & 0b11000000) == encode_class(decode_class(v))
        }
    }

    #[derive(Clone,Debug)]
    struct RandomUint {
        x: BigUint
    }

    impl Arbitrary for RandomUint {
        fn arbitrary<G: Gen>(g: &mut G) -> RandomUint {
            let v = BigUint::from_u32(g.gen::<u32>()).unwrap();
            RandomUint{ x: v }
        }
    }

   quickcheck! {
        fn tags_encdec_roundtrips(c: ASN1Class, t: RandomUint) -> bool {
            let bytes = encode_tag(c, &t.x);
            let mut zero = 0;
            let (t2, c2) = decode_tag(&bytes[..], &mut zero);
            (c == c2) && (t.x == t2)
        }

        fn len_encdec_roundtrips(l: usize) -> bool {
            let bytes = encode_len(l);
            let mut zero = 0;
            match decode_length(&bytes[..], &mut zero) {
                Err(_) => false,
                Ok(l2) => l == l2
            }
        }
    }

    #[derive(Clone,Debug)]
    struct RandomInt {
        x: BigInt
    }

    impl Arbitrary for RandomInt {
        fn arbitrary<G: Gen>(g: &mut G) -> RandomInt {
            let v = BigInt::from_i64(g.gen::<i64>()).unwrap();
            RandomInt{ x: v }
        }
    }

    type ASN1BlockGen<G: Gen> = fn(&mut G, usize) -> ASN1Block;

    fn arb_boolean<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let c = ASN1Class::arbitrary(g);
        let v = g.gen::<bool>();
        ASN1Block::Boolean(c, 0, v)
    }

    fn arb_integer<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let c = ASN1Class::arbitrary(g);
        let d = RandomInt::arbitrary(g);
        ASN1Block::Integer(c, 0, d.x)
    }

    fn arb_bitstr<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let size = g.gen::<u16>() as usize % 16;
        let maxbits = (size as usize) * 8;
        let modbits = g.gen::<u8>() as usize % 8;
        let nbits = if modbits > maxbits
                      { maxbits }
                    else { maxbits - modbits };
        let bytes = g.sample_iter::<u8, _>(&Standard).take(size).collect();
        ASN1Block::BitString(class, 0, nbits, bytes)
    }

    fn arb_octstr<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let size = g.gen::<u16>() as usize % 16;
        let bytes = g.sample_iter::<u8, _>(&Standard).take(size).collect();
        ASN1Block::OctetString(class, 0, bytes)
    }

    fn arb_null<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        ASN1Block::Null(class, 0)
    }

    impl Arbitrary for OID {
        fn arbitrary<G: Gen>(g: &mut G) -> OID {
            let     count = g.gen_range::<usize>(0, 40);
            let     val1  = g.gen::<u8>() % 3;
            let     v2mod = if val1 == 2 { 176 } else { 40 };
            let     val2  = g.gen::<u8>() % v2mod;
            let     v1    = BigUint::from_u8(val1).unwrap();
            let     v2    = BigUint::from_u8(val2).unwrap();
            let mut nums  = vec![v1, v2];

            for _ in 0..count {
                let num = RandomUint::arbitrary(g);
                nums.push(num.x);
            }

            OID(nums)
        }
    }

    fn arb_objid<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let oid   = OID::arbitrary(g);
        ASN1Block::ObjectIdentifier(class, 0, oid)
    }

    fn arb_seq<G: Gen>(g: &mut G, d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let count = g.gen_range::<usize>(1, 64);
        let mut items = Vec::new();

        for _ in 0..count {
            items.push(limited_arbitrary(g, d - 1));
        }

        ASN1Block::Sequence(class, 0, items)
    }

    fn arb_set<G: Gen>(g: &mut G, d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let count = g.gen_range::<usize>(1, 64);
        let mut items = Vec::new();

        for _ in 0..count {
            items.push(limited_arbitrary(g, d - 1));
        }

        ASN1Block::Set(class, 0, items)
    }

    fn arb_print<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let count = g.gen_range::<usize>(0, 384);
        let mut items = Vec::new();

        for _ in 0..count {
            let v = g.choose(PRINTABLE_CHARS.as_bytes()).unwrap();
            items.push(*v as char);
        }

        ASN1Block::PrintableString(class, 0, String::from_iter(items.iter()))
    }

    fn arb_ia5<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let count = g.gen_range::<usize>(0, 384);
        let mut items = Vec::new();

        for _ in 0..count {
            items.push(g.gen::<u8>() as char);
        }

        ASN1Block::IA5String(class, 0, String::from_iter(items.iter()))
    }

    fn arb_utf8<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let val = String::arbitrary(g);
        ASN1Block::UTF8String(class, 0, val)
    }

    fn arb_tele<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let val = String::arbitrary(g);
        ASN1Block::TeletexString(class, 0, val)
    }

    fn arb_uni<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let val = String::arbitrary(g);
        ASN1Block::UniversalString(class, 0, val)
    }

    fn arb_bmp<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let val = String::arbitrary(g);
        ASN1Block::BMPString(class, 0, val)
    }

    fn arb_utc<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);

        loop {
            let y = g.gen_range::<i32>(1970,2069);
            let m = g.gen_range::<u32>(1,13);
            let d = g.gen_range::<u32>(1,32);
            match Utc.ymd_opt(y,m,d) {
                LocalResult::None => {}
                LocalResult::Single(d) => {
                    let h = g.gen_range::<u32>(0,24);
                    let m = g.gen_range::<u32>(0,60);
                    let s = g.gen_range::<u32>(0,60);
                    let t = d.and_hms(h,m,s);
                    return ASN1Block::UTCTime(class, 0, t);
                }
                LocalResult::Ambiguous(_,_) => {}
            }
        }
    }

    fn arb_time<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);

        loop {
            let y = g.gen_range::<i32>(0,10000);
            let m = g.gen_range::<u32>(1,13);
            let d = g.gen_range::<u32>(1,32);
            match Utc.ymd_opt(y,m,d) {
                LocalResult::None => {}
                LocalResult::Single(d) => {
                    let h = g.gen_range::<u32>(0,24);
                    let m = g.gen_range::<u32>(0,60);
                    let s = g.gen_range::<u32>(0,60);
                    let n = g.gen_range::<u32>(0,1000000000);
                    let t = d.and_hms_nano(h,m,s,n);
                    return ASN1Block::GeneralizedTime(class, 0, t);
                }
                LocalResult::Ambiguous(_,_) => {}
            }
        }
    }

    fn arb_unknown<G: Gen>(g: &mut G, _d: usize) -> ASN1Block {
        let class = ASN1Class::arbitrary(g);
        let tag   = RandomUint::arbitrary(g);
        let size  = g.gen_range::<usize>(0, 128);
        let items = g.sample_iter::<u8, _>(&Standard).take(size).collect();

        ASN1Block::Unknown(class, 0, tag.x, items)
    }

    fn limited_arbitrary<G: Gen>(g: &mut G, d: usize) -> ASN1Block {
        let mut possibles: Vec<ASN1BlockGen<G>> =
            vec![arb_boolean,
                 arb_integer,
                 arb_bitstr,
                 arb_octstr,
                 arb_null,
                 arb_objid,
                 arb_utf8,
                 arb_print,
                 arb_tele,
                 arb_uni,
                 arb_ia5,
                 arb_utc,
                 arb_time,
                 arb_bmp,
                 arb_unknown];

        if d > 0 {
            possibles.push(arb_seq);
            possibles.push(arb_set);
        }

        match g.choose(&possibles[..]) {
            Some(f) => f(g, d),
            None    => panic!("Couldn't generate arbitrary value.")
        }
    }

    impl Arbitrary for ASN1Block {
        fn arbitrary<G: Gen>(g: &mut G) -> ASN1Block {
            limited_arbitrary(g, 2)
        }
    }

    quickcheck! {
        fn encode_decode_roundtrips(v: ASN1Block) -> bool {
            match to_der(&v) {
                Err(e) => {
                    println!("Serialization error: {:?}", e);
                    false
                }
                Ok(bytes) =>
                    match from_der(&bytes[..]) {
                        Err(e) => {
                            println!("Parse error: {:?}", e);
                            false
                        }
                        Ok(ref rvec) if rvec.len() == 1 => {
                            let v2 = rvec.get(0).unwrap();
                            if &v != v2 {
                                println!("Original: {:?}", v);
                                println!("Constructed: {:?}", v2);
                            }
                            &v == v2
                        }
                        Ok(_) => {
                            println!("Too many results returned.");
                            false
                        }
                    }
            }
        }
    }

    fn result_int(v: i16) -> Result<Vec<ASN1Block>,ASN1DecodeErr> {
        let val = BigInt::from(v);
        Ok(vec![ASN1Block::Integer(ASN1Class::Universal, 0, val)])
    }

    #[test]
    fn generalized_time_tests() {
        check_spec(&Utc.ymd(1992, 5, 21).and_hms(0,0,0),
                   "19920521000000Z".to_string());
        check_spec(&Utc.ymd(1992, 6, 22).and_hms(12,34,21),
                   "19920622123421Z".to_string());
        check_spec(&Utc.ymd(1992, 7, 22).and_hms_milli(13,21,00,300),
                   "19920722132100.3Z".to_string());
    }

    fn check_spec(d: &DateTime<Utc>, s: String) {
        let b = ASN1Block::GeneralizedTime(ASN1Class::Universal, 0, d.clone());
        match to_der(&b) {
            Err(_) => assert_eq!(format!("Broken: {}", d), s),
            Ok(ref vec) => {
                let mut resvec = vec.clone();
                resvec.remove(0);
                resvec.remove(0);
                assert_eq!(String::from_utf8(resvec).unwrap(), s);
            }
        }
    }

    #[test]
    fn base_integer_tests() {
        assert_eq!(from_der(&vec![0x02,0x01,0x00]), result_int(0));
        assert_eq!(from_der(&vec![0x02,0x01,0x7F]), result_int(127));
        assert_eq!(from_der(&vec![0x02,0x02,0x00,0x80]), result_int(128));
        assert_eq!(from_der(&vec![0x02,0x02,0x01,0x00]), result_int(256));
        assert_eq!(from_der(&vec![0x02,0x01,0x80]), result_int(-128));
        assert_eq!(from_der(&vec![0x02,0x02,0xFF,0x7F]), result_int(-129));
    }

    fn can_parse(f: &str) -> Result<Vec<ASN1Block>,ASN1DecodeErr> {
        let mut fd = File::open(f).unwrap();
        let mut buffer = Vec::new();
        let _amt = fd.read_to_end(&mut buffer);
        from_der(&buffer[..])
    }

    #[test]
    fn x509_tests() {
        assert!(can_parse("test/server.bin").is_ok());
        assert!(can_parse("test/key.bin").is_ok());
    }
}
