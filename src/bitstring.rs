pub struct BitString {
    current_bit: usize,
    work_byte: u8,
    contents: Vec<u8>,
}

pub struct BitIter {
    current_bit: usize,
    contents: BitString,
}

impl BitString {
    /// Create a new, empty bit string
    pub fn new() -> BitString {
        BitString {
            current_bit: 7,
            work_byte: 0,
            contents: vec![],
        }
    }

    /// Create an iterator over the bits in the BitString
    pub fn bits(self) -> BitIter {
        BitIter {
            current_bit: 0,
            contents: self,
        }
    }

    /// Add a bit to the end of the bitstring
    pub fn push_bit(&mut self, x: bool) {
        let bitval = if x { 1 } else { 0 };
        self.work_byte |= bitval << self.current_bit;

        if self.current_bit == 0 {
            self.contents.push(self.work_byte);
            self.work_byte = 0;
            self.current_bit = 7;
        } else {
            self.current_bit -= 1;
        }
    }

    /// Add the low `n` bits of the provided byte to the BitString
    pub fn push_bits(&mut self, mut n: usize, x: u8) {
        while n > 0 {
            let bit = (x >> (n - 1)) & 1 == 1;
            self.push_bit(bit);
            n -= 1;
        }
    }

    /// Get the length of this bitstring, in bits
    pub fn len(&self) -> usize {
        (self.contents.len() * 8) + (7 - self.current_bit)
    }
}

impl<I: Iterator<Item = u8>> From<I> for BitString {
    fn from(x: I) -> BitString {
        let contents: Vec<u8> = x.collect();
        BitString {
            current_bit: contents.len() * 8,
            work_byte: 0,
            contents,
        }
    }
}

impl Iterator for BitIter {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let byte_idx = self.current_bit / 8;
        let bit_idx = self.current_bit % 8;
        let shift_amt = 7 - bit_idx;

        // if we're still in the main body of the thing, then we just compute
        // the offset and shift and be done with it.
        if byte_idx < self.contents.contents.len() {
            let byte = self.contents.contents[byte_idx];
            let retval = byte >> shift_amt;
            self.current_bit += 1;
            return Some(retval & 1);
        }

        // just a sanity check; this should reallly never happen.
        if byte_idx > self.contents.contents.len() {
            return None;
        }

        // in this case, we're processing in the work_byte area of our parent
        // BitString.
        if shift_amt <= self.contents.current_bit {
            return None;
        }

        self.current_bit += 1;
        return Some((self.contents.work_byte >> shift_amt) & 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullary_test() {
        let bitstr = BitString::new();
        let bits: Vec<u8> = bitstr.bits().collect();
        assert_eq!(bits.len(), 0);
    }

    #[test]
    fn add_bit() {
        let mut bitstr = BitString::new();

        bitstr.push_bit(false);
        bitstr.push_bit(true);
        bitstr.push_bit(false);
        bitstr.push_bit(false);
        bitstr.push_bit(true);
        bitstr.push_bit(true);
        bitstr.push_bit(true);
        bitstr.push_bit(false);
        bitstr.push_bit(false);
        let bits: Vec<u8> = bitstr.bits().collect();
        assert_eq!(bits, vec![0, 1, 0, 0, 1, 1, 1, 0, 0]);
    }

    #[test]
    fn add_bits() {
        let mut bitstr = BitString::new();

        bitstr.push_bits(5, 0b11111111);
        let bits: Vec<u8> = bitstr.bits().collect();
        assert_eq!(bits, vec![1, 1, 1, 1, 1]);
    }
}
