mod decoder;
mod encoder;

use crate::cipherer::Cipherer;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;

pub use self::encoder::PlayfairEncoder;
pub use self::decoder::PlayfairDecoder;

struct Playfair<T: Read> {
    cipherer: Cipherer,
    reader: BufReader<T>,
    carry_encrypted: Option<u8>,
    carry: Option<u8>,
}

impl<T: Read> Playfair<T> {
    pub fn new(key: &str, stream: T) -> Self {
        Self {
            cipherer: Cipherer::with(key.as_bytes()),
            reader: BufReader::new(stream),
            carry_encrypted: None,
            carry: None,
        }
    }
}

impl<T: Read> Playfair<T> {
    fn __read(&mut self, buf: &mut [u8], decode: bool) -> io::Result<usize> {
        // Trivial case - provided buffer has a length of 0
        if buf.is_empty() {
            return Ok(0);
        }

        // There is a carry byte left after previous reads
        let mut written = if let Some(chr) = self.carry_encrypted {
            buf[0] = chr;
            self.carry_encrypted = None;
            1
        } else {
            0
        };
        loop {
            let mut consumed = 0;
            if self.reader.buffer().is_empty() {
                self.reader.fill_buf()?;
            }

            let internal_buf = self.reader.buffer();

            if internal_buf.is_empty() {
                if let Some(chr) = self.carry {
                    // Unwrap is justified here as Duplicate variant can only come up when
                    // the carry character is x and it is the last character in the stream.
                    // Handling this case in the normal manner would lead to an infinite loop
                    // x -> xx -> xqx -> x -> xx -> xqx -> ...
                    let (x, y) = self.cipherer.cipher(chr, b'x', decode).unwrap();
                    buf[written] = x;
                    if written == buf.len() - 1 {
                        self.carry_encrypted = Some(y);
                        return Ok(written + 1);
                    }
                    buf[written + 1] = y;
                    return Ok(written + 2);
                }
                return Ok(written);
            }

            if let Some(chr) = self.carry {
                let outcome = self.cipherer.cipher(chr, internal_buf[0], decode);
                let (x, y) = outcome.unwrap();
                if !outcome.is_duplicate() {
                    consumed += 1;
                }

                buf[written] = x;
                if written == buf.len() - 1 {
                    self.carry_encrypted = Some(y);
                    return Ok(written);
                }
                buf[written + 1] = x;
                written += 2;
            }

            while written < buf.len() - 1 && consumed < internal_buf.len() - 1 {
                let outcome = self.cipherer.cipher(
                    internal_buf[consumed],
                    internal_buf[consumed + 1],
                    decode,
                );
                let (x, y) = outcome.unwrap();
                buf[written] = x;
                buf[written + 1] = y;
                written += 2;
                consumed += if outcome.is_duplicate() { 1 } else { 2 };
            }

            if written == buf.len() {
                self.reader.consume(consumed);
                return Ok(written);
            }

            if consumed == internal_buf.len() - 1 {
                self.carry = Some(internal_buf[consumed]);
                self.reader.consume(consumed + 1);
                continue;
            }

            // length of provided buffer is odd and less or equal to internal buf lenth
            if written == buf.len() - 1 && consumed < internal_buf.len() {
                let outcome = self.cipherer.cipher(
                    internal_buf[consumed],
                    internal_buf[consumed + 1],
                    decode,
                );
                self.reader.consume(consumed + 2);
                let (x, y) = outcome.unwrap();
                buf[written] = x;
                self.carry_encrypted = Some(y);
                return Ok(written + 1);
            }
            self.reader.consume(consumed);
        }
    }
}

#[cfg(test)]
mod io_tests_mock {
    use std::io::Read;
    const TEST_KEY: &'static str = "playfairexample";
    const SHORT_ODD: &'static str = "aksjdaksdjh";
    const SHORT_ODD_ANS: &'static str = "pokmoenkbegm";
    const SHORT: &'static str = "aksjdaksdj";
    const SHORT_ANS: &'static str = "pokmoenkbe";
    const SHORT_DUP: &'static str = "aabbccdd";
    const SHORT_DUP_ANS: &'static str = "yepdcddgge";

    #[test]
    fn buf_file_dup() {
        let reader = SHORT_DUP.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 64];
        let size = encoder.read(&mut buf).unwrap();
        assert_eq!(size, SHORT_DUP_ANS.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), SHORT_DUP_ANS);
    }

    #[test]
    // Buffer is bigger than the file and the file size is odd
    fn buf_file_odd() {
        let reader = SHORT_ODD.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 64];
        let size = encoder.read(&mut buf).unwrap();
        assert_eq!(size, SHORT_ODD_ANS.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), SHORT_ODD_ANS);
    }

    #[test]
    // Buffer is bigger than the file
    fn buf_file() {
        let reader = SHORT.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 64];
        let size = encoder.read(&mut buf).unwrap();
        assert_eq!(size, SHORT_ANS.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), SHORT_ANS);
    }

    #[test]
    // Buffer length is odd and it is bigger that the file
    fn buf_odd_file() {
        let reader = SHORT.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 63];
        let size = encoder.read(&mut buf).unwrap();
        assert_eq!(size, SHORT_ANS.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), SHORT_ANS);
    }

    #[test]
    // Buffer length is odd and it is bigger that the file
    fn buf_odd_file_odd() {
        let reader = SHORT_ODD.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 63];
        let size = encoder.read(&mut buf).unwrap();
        assert_eq!(size, SHORT_ODD_ANS.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), SHORT_ODD_ANS);
    }
}
