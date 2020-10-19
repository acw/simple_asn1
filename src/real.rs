use crate::number::Number;

pub enum Real {
    PositiveInfinity,
    NegativeInfinity,
    ISO6093(String),
    Binary(RealNumber),
}

impl Real {
    pub fn new(exponent: Number, mantissa: Number) -> Real {
        Real::Binary(RealNumber{
            exponent,
            mantissa,
        })
    }
}

pub struct RealNumber {
    exponent: Number,
    mantissa: Number,
}

