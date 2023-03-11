mod cipherer;

use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::BufReader;

use std::cmp::min;
use std::str::from_utf8;

use std::fs;
use std::env;
use std::iter::Iterator;

use cipherer::Cipherer;

struct PlayfairEncoder<T: Read> {
    cipherer: Cipherer,
    reader: BufReader<T>,
    carry_encrypted: Option<u8>,
    carry: Option<u8>,
}

impl<T: Read> PlayfairEncoder<T> {
    fn new(key: &str, stream: T) -> Self {
        Self {
            cipherer: Cipherer::with(key.as_bytes()),
            reader: BufReader::new(stream),
            carry_encrypted: None,
            carry: None,
        }
    }

    pub fn encode(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Trivial case - provided buffer has a length of 0
        if buf.is_empty() {
            return Ok(0);
        }

        // There is a carry byte left after previous reads
        let mut start = if let Some(chr) = self.carry_encrypted {
            buf[0] = chr;
            self.carry_encrypted = None;
            1
        } else { 0 };

        loop {
            if self.reader.buffer().is_empty() {
                self.reader.fill_buf()?;
            }

            let internal_buf = self.reader.buffer();

            if internal_buf.is_empty() {
                if let Some(chr) = self.carry {
                    let (x, y) = self.cipherer.cipher(chr, b'x');
                    buf[start] = x;
                    if start == buf.len() - 1 {
                        self.carry_encrypted = Some(y);
                        return Ok(start+1);
                    }
                    buf[start+1] = y;
                    return Ok(start+2);
                }
                return Ok(start);
            }

            if let Some(chr) = self.carry {
                let (x, y) = self.cipherer.cipher(chr, internal_buf[0]);
                buf[start] = x;
                if start == buf.len() - 1 {
                    self.carry_encrypted = Some(y);
                    return Ok(start);
                }
                buf[start + 1] = x;
                start += 2;
            }

            let size_ = min(buf.len() - start, internal_buf.len());

            let size_even = size_ - (size_ & 1);
            for i in (0..size_even).step_by(2) {
                let (x, y) = self.cipherer.cipher(internal_buf[i], internal_buf[i+1]);
                buf[i+start] = x; buf[i+start + 1] = y;
            }
            start += size_even;

            if start == buf.len() {
                self.reader.consume(size_even);
                return Ok(size_even);
            }

            if size_even == internal_buf.len() - 1 {
                self.carry = Some(internal_buf[size_even]);
                self.reader.consume(size_);
                continue;
            }

            // length of provided buffer is odd and less or equal to internal buf lenth
            if size_even == buf.len() - 1 && size_ < internal_buf.len() {
                let (x, y) = self.cipherer.cipher(internal_buf[size_even], internal_buf[size_even + 1]);
                buf[size_ - 1 + start] = x;
                self.carry_encrypted = Some(y);
                self.reader.consume(size_ + 1);
                return Ok(size_);
            }
            self.reader.consume(size_even);
        }
    }
}


fn main() -> io::Result<()> {
    let args = env::args().collect::<Vec<String>>();
    let reader: Box<dyn io::Read> = if let Some(filename) = args.get(2) {
        Box::new(fs::File::open(filename)?)
    } else {
        Box::new(io::stdin())
    };
    let mut enc = PlayfairEncoder::new(&args[1], reader);
    let mut buf = vec![0u8; 256];
    let len = enc.encode(&mut buf)?;
    print!("{} {}", len, from_utf8(&buf).unwrap());
    Ok(())
}

#[cfg(test)]
mod io_tests_mock {
    const TEST_KEY: &'static str = "playfairexample";
    const CONTENT_SHORT_ODD: &'static str = "aksjdaksdjh";
    const CONTENT_SHORT_ODD_ANS: &'static str = "pokmoenkbegm";
    const CONTENT_SHORT: &'static str = "aksjdaksdj";
    const CONTENT_SHORT_ANS: &'static str = "pokmoenkbe";

    #[test]
    // Buffer is bigger than the file and the file size is odd
    fn buf_file_odd() {
        let reader = CONTENT_SHORT_ODD.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 64];
        let size = encoder.encode(&mut buf).unwrap();
        assert_eq!(size, CONTENT_SHORT_ODD.len() + 1);
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), CONTENT_SHORT_ODD_ANS);
    }

    #[test]
    // Buffer is bigger than the file
    fn buf_file() {
        let reader = CONTENT_SHORT.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 64];
        let size = encoder.encode(&mut buf).unwrap();
        assert_eq!(size, CONTENT_SHORT.len());
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), CONTENT_SHORT_ANS);
    }

    #[test]
    // Buffer length is odd and it is bigger that the file
    fn buf_odd_file() {
        let reader = CONTENT_SHORT.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 63];
        let size = encoder.encode(&mut buf).unwrap();
        assert_eq!(size, CONTENT_SHORT.len() );
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), CONTENT_SHORT_ANS);
    }

    #[test]
    // Buffer length is odd and it is bigger that the file
    fn buf_odd_file_odd() {
        let reader = CONTENT_SHORT_ODD.as_bytes();
        let mut encoder = crate::PlayfairEncoder::new(TEST_KEY, reader);
        let mut buf = [0u8; 63];
        let size = encoder.encode(&mut buf).unwrap();
        assert_eq!(size, CONTENT_SHORT_ODD.len() + 1);
        assert_eq!(std::str::from_utf8(&buf[..size]).unwrap(), CONTENT_SHORT_ODD_ANS);
    }
}
