use core::convert::TryFrom;
use core::ops::{Neg, ShlAssign};
use crate::ber::length::ConversionError;
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};

#[derive(Clone, Debug, PartialEq)]
pub struct Number {
    value: Vec<u64>,
    bits: usize,
}

#[cfg(test)]
impl Arbitrary for Number {
    fn arbitrary<G: Gen>(g: &mut G) -> Number {
        let bytes = u8::arbitrary(g) as usize;
        let digits = (bytes + 7) / 8;
        let bits = bytes * 8;

        let mut value = Vec::with_capacity(digits);
        for _ in 0..digits {
            value.push(g.next_u64());
        }

        if digits > 0 {
            let spare_bits = (digits * 64) - bits;
            let mask = 0xFFFFFFFFFFFFFFFFu64 >> spare_bits;
            value[digits - 1] &= mask;
        }

        Number {
            value,
            bits,
        }
    }
}

impl Number {
    pub fn new() -> Number {
        Number {
            value: Vec::new(),
            bits: 0
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let serialized_bytes = (self.bits + 7) / 8;
        let mut res = Vec::with_capacity(serialized_bytes);

        for idx in 0..serialized_bytes {
            let byte_off = serialized_bytes - idx - 1;
            let val64_off = byte_off / 8;
            let internal_bit_off = (byte_off % 8) * 8;
            let val = (self.value[val64_off] >> internal_bit_off) & 0xff;

            res.push(val as u8);
        }

        res
    }

    pub fn from_bytes(bytes: &[u8]) -> Number {
        let bits = bytes.len() * 8;
        let digit_len = (bytes.len() + 7) / 8;
        let mut value = Vec::with_capacity(digit_len);
        let mut bytes_added = 0;
        let mut next = 0u64;

        for x in bytes.iter().rev() {
            next += (*x as u64) << (bytes_added * 8);
            bytes_added += 1;
            if bytes_added == 8 {
                value.push(next);
                next = 0;
                bytes_added = 0;
            }
        }

        if bytes_added != 0 {
            value.push(next);
        }

        Number { value, bits }
    }
}

#[cfg(test)]
#[test]
fn basic_serialization() {
    assert_eq!(Number::new().serialize(), vec![]);
    //
    let one = Number {
        value: vec![1],
        bits: 8,
    };
    let onevec = vec![1];
    assert_eq!(one.serialize(), onevec);
    assert_eq!(Number::from_bytes(&onevec), one);
    //
    let one_oh_oh_one = Number {
        value: vec![0x1001],
        bits: 16,
    };
    let one_oh_oh_one_vec = vec![0x10,0x01];
    assert_eq!(one_oh_oh_one.serialize(), one_oh_oh_one_vec);
    assert_eq!(Number::from_bytes(&one_oh_oh_one_vec), one_oh_oh_one);
    //
    let one_to_nine = Number {
        value: vec![0x0807060504030201, 0x09],
        bits: 72,
    };
    let one_to_nine_vec = vec![0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
    assert_eq!(one_to_nine.serialize(), one_to_nine_vec);
    assert_eq!(Number::from_bytes(&one_to_nine_vec), one_to_nine);
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct SmallByteArray {
    a: Vec<u8>
}

#[cfg(test)]
impl Arbitrary for SmallByteArray {
    fn arbitrary<G: Gen>(g: &mut G) -> SmallByteArray {
        let len = u8::arbitrary(g);
        let mut a = Vec::with_capacity(len as usize);
        for _ in 0..len {
            a.push(u8::arbitrary(g));
        }
        SmallByteArray{ a }
    }
}

#[cfg(test)]
quickcheck! {
    fn bytes_num_bytes(x: SmallByteArray) -> bool {
        let num = Number::from_bytes(&x.a);
        let y = num.serialize();
        println!("x.a: {:?}", x.a);
        println!("y:   {:?}", y);
        &x.a == &y
    }

    fn num_bytes_num(x: Number) -> bool {
        let bytes = x.serialize();
        let y = Number::from_bytes(&bytes);
        println!("x: {:?}", x);
        println!("b: {:?}", bytes);
        println!("y: {:?}", y);
        x == y
    }
}

impl From<u8> for Number {
    fn from(x: u8) -> Number {
        Number {
            value: vec![x as u64],
            bits: 8,
        }
    }
}

impl<'a> TryFrom<&'a Number> for usize {
    type Error = ConversionError;

    fn try_from(x: &Number) -> Result<Self, Self::Error> {
        if x.value.iter().skip(1).all(|v| *v == 0) {
            if x.value.len() == 0 {
                return Ok(0);
            }

            let mut value = x.value[0];

            if x.bits < 64 {
                value &= 0xFFFFFFFFFFFFFFFFu64 >> (64 - x.bits);
            }

            match usize::try_from(value) {
                Err(_) => Err(ConversionError::ValueTooLarge),
                Ok(v) => Ok(v)
            }
        } else {
            Err(ConversionError::ValueTooLarge)
        }
    }
}

impl ShlAssign<usize> for Number {
    fn shl_assign(&mut self, amt: usize) {
        unimplemented!()
    }
}

impl Neg for Number {
    type Output = Number;

    fn neg(self) -> Number {
        unimplemented!()
    }
}