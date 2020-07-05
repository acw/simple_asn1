use alloc::vec::Vec;

pub trait BufferReader {
    fn read_buffer<I: Iterator<Item=u8>>(&self, it: &mut I) -> Option<Vec<u8>>;
}

impl BufferReader for usize {
    fn read_buffer<I: Iterator<Item=u8>>(&self, it: &mut I) -> Option<Vec<u8>> {
        let me = *self;
        let mut res = Vec::with_capacity(me);

        while res.len() < me {
            let n = it.next()?;
            res.push(n);
        }

        Some(res)
    }
}

#[macro_export]
macro_rules! lift_error {
    ($fromt: ident, $tot: ident) => {
        lift_error!($fromt, $fromt, $tot);
    };
    ($fromt: ident, $const: ident, $tot: ident) => {
        impl From<$fromt> for $tot {
            fn from(x: $fromt) -> $tot {
                $tot::$const(x)
            }
        }
    }
}
