use std::io;
use std::io::Read;
use std::io::Write;

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
    reader: T,
    carry: Option<u8>
}

impl<T: Read> PlayfairEncoder<T> {
    fn new(key: &str, stream: T) -> Self {
        Self {
            cipherer: Cipherer::with(key.as_bytes()),
            reader: stream,
            carry: None
        }
    }

    fn encode(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 256];
        let mut size = 0;
        let mut lock = io::stdout().lock();
        loop {
            let size_ = self.reader.read(&mut buf)?;
            size += size_;
            if size_ == 0 {
                if let Some(byte) = self.carry {
                    let (x, y) = self.cipherer.cipher(byte, b'x');
                    write!(lock, "{}{}", x, y)?;
                }
                break;
            }
            for i in (0..size_ - (size_ & 1)).step_by(2) {
                let (x, y) = self.cipherer.cipher(buf[i], buf[i+1]);
                write!(lock, "{}{}", x, y)?;
            }
            if size_ & 1 == 1 {
                self.carry = Some(buf[size_-1]);
            }
            io::stdout().flush()?;
        }
        return Ok(size)
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
    enc.encode()?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
