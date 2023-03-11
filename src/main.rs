use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::BufReader;

use std::cmp::min;
use std::str::from_utf8;

use std::fs;
use std::env;
use std::iter::Iterator;

const EMPTY: usize = 25usize;

#[derive(Debug)]
struct Cipherer {
    letters_mtx: [u8; 25],
    positions_mtx: [usize; 25]
}

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
        if buf.len() == 0 {
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

            if internal_buf.len() == 0 {
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

impl Cipherer {
    fn get_position(chr: u8) -> usize {
        if chr >= b'j' { (chr - 1 - b'a') as usize }
        else { (chr - b'a') as usize }
    }

    fn with(key: &[u8]) -> Self {
        let mut c = 0; // iterator saying how many fields have been written to the matrix
        let mut letters_mtx = [0u8; 25];
        let mut positions_mtx = [EMPTY; 25];
        for &i in key.iter().chain((b'a'..=b'z').collect::<Vec<u8>>().iter()) {
            if c == 25 { break; }
            let x = if i == b'j' { b'i' }
            else { i };
            let y = Self::get_position(x);
            if positions_mtx[y] != EMPTY {
                continue;
            }
            letters_mtx[c] = x;
            positions_mtx[y] = c;
            c+=1;
        }
        Self {
            letters_mtx,
            positions_mtx
        }
    }

    pub fn cipher(&self, chr1: u8, chr2: u8) -> (u8, u8) {
        let chr1_pos = self.positions_mtx[Self::get_position(chr1)];
        let chr2_pos = self.positions_mtx[Self::get_position(chr2)];
        // same row
        if chr1_pos / 5 == chr2_pos / 5 {
            let letter = |chr_pos: usize| -> u8 {
                self.letters_mtx[if (chr_pos + 1) / 5 != chr_pos / 5 {
                    chr_pos - 4
                } else {
                    chr_pos + 1
                }]
            };
            (letter(chr1_pos), letter(chr2_pos))
        } else if chr1_pos % 5 == chr2_pos % 5 {
            let letter = |chr_pos: usize| -> u8 {
                self.letters_mtx[if chr_pos + 5 > 24 {
                    chr_pos - 20
                } else {
                    chr_pos + 5
                }]
            };
            (letter(chr1_pos), letter(chr2_pos))
        } else {
            let ch1 = chr1_pos / 5 * 5 + chr2_pos % 5;
            let ch2 = chr2_pos / 5 * 5 + chr1_pos % 5;
            (self.letters_mtx[ch1 as usize], self.letters_mtx[ch2 as usize])
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

#[cfg(test)]
mod cipher_tests {
    fn init() -> crate::Cipherer {
        crate::Cipherer::with("playfairexample".as_bytes())
    }

    #[test]
    fn rectangle_tests() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'o', b'l'), (b'n', b'a'));
        assert_eq!(cipherer.cipher(b'e', b'g'), (b'x', b'd'));
        assert_eq!(cipherer.cipher(b't', b'h'), (b'z', b'b'));
        assert_eq!(cipherer.cipher(b'h', b'i'), (b'b', b'm'));
    }

    #[test]
    fn same_row_tests() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'p', b'l'), (b'l', b'a'));
        assert_eq!(cipherer.cipher(b'y', b'f'), (b'f', b'p'));
        assert_eq!(cipherer.cipher(b'y', b'f'), (b'f', b'p'));
        assert_eq!(cipherer.cipher(b'a', b'f'), (b'y', b'p'));
        assert_eq!(cipherer.cipher(b'k', b's'), (b'n', b'k'));
        assert_eq!(cipherer.cipher(b'u', b'z'), (b'v', b't'));
    }

    #[test]
    fn same_column_test() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'p', b'i'), (b'i', b'b'));
        assert_eq!(cipherer.cipher(b'b', b't'), (b'k', b'p'));
        assert_eq!(cipherer.cipher(b'e', b'd'), (b'd', b'o'));
        assert_eq!(cipherer.cipher(b'f', b's'), (b'm', b'z'));
        assert_eq!(cipherer.cipher(b'n', b'u'), (b'u', b'l'));
        assert_eq!(cipherer.cipher(b'x', b'w'), (b'g', b'y'));
    }
}
