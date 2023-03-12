const EMPTY: usize = 25usize;

pub enum PlayfairOutcome {
    Normal((u8, u8)),
    Duplicate((u8, u8)),
}

impl PlayfairOutcome {
    pub fn unwrap(&self) -> (u8, u8) {
        match self {
            Self::Normal((x, y)) => (*x, *y),
            Self::Duplicate((x, y)) => (*x, *y),
        }
    }

    pub fn is_duplicate(&self) -> bool {
        !matches!(self, Self::Normal(_))
    }
}

pub struct Cipherer {
    letters_mtx: [u8; 25],
    positions_mtx: [usize; 25],
}

// For now any character that is not a letter is replaced with 'x'
fn lowercase(chr: u8) -> Option<u8> {
    if chr.is_ascii_lowercase() {
        Some(chr)
    } else if chr.is_ascii_uppercase() {
        Some(chr + 32)
    } else {
        None
    }
}

fn get_position(chr: u8) -> usize {
    if let Some(chr_) = lowercase(chr) {
        if chr_ >= b'j' {
            (chr_ - 1 - b'a') as usize
        } else {
            (chr_ - b'a') as usize
        }
    } else {
        (b'x' - b'a' - 1) as usize
    }
}

impl Cipherer {
    pub fn with(key: &[u8]) -> Self {
        let mut c = 0; // iterator saying how many fields have been written to the matrix
        let mut letters_mtx = [0u8; 25];
        let mut positions_mtx = [EMPTY; 25];
        for &i in key.iter().chain((b'a'..=b'z').collect::<Vec<u8>>().iter()) {
            if c == 25 {
                break;
            }

            let chr = if let Some(lowercase_chr) = lowercase(i) {
                if lowercase_chr == b'j' || lowercase_chr == b'J' {
                    b'i'
                } else {
                    lowercase_chr
                }
            } else {
                break;
            };

            let ind = get_position(chr);
            if positions_mtx[ind] != EMPTY {
                continue;
            }
            letters_mtx[c] = chr;
            positions_mtx[ind] = c;
            c += 1;
        }
        #[cfg(debug_assertions)]
        letters_mtx.chunks(5).for_each(|x| {
            x.iter().for_each(|&y| {
                eprint!("{} ", y as char);
            });
            eprintln!();
        });
        Self {
            letters_mtx,
            positions_mtx,
        }
    }

    pub fn cipher(&self, chr1: u8, chr2: u8) -> PlayfairOutcome {
        let chr1_pos = self.positions_mtx[get_position(chr1)];

        let chr2_pos_ = self.positions_mtx[get_position(chr2)];
        let chr2_pos = if chr2_pos_ == chr1_pos {
            if self.letters_mtx[chr1_pos] == b'x' {
                self.positions_mtx[get_position(b'q')]
            } else {
                self.positions_mtx[get_position(b'x')]
            }
        } else {
            chr2_pos_
        };
        // same row
        let tuple = if chr1_pos / 5 == chr2_pos / 5 {
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
            (self.letters_mtx[ch1], self.letters_mtx[ch2])
        };
        if chr1 == chr2 {
            PlayfairOutcome::Duplicate(tuple)
        } else {
            PlayfairOutcome::Normal(tuple)
        }
    }
}

#[cfg(test)]
mod cipher_tests {
    use crate::cipherer::Cipherer;
    fn init() -> Cipherer {
        Cipherer::with("playfairexample".as_bytes())
    }

    #[test]
    fn duplicate_tests() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'x', b'x').unwrap(), (b'g', b'w'));
        assert_eq!(cipherer.cipher(b'r', b'r').unwrap(), (b'e', b'm'));
        assert_eq!(cipherer.cipher(b'n', b'n').unwrap(), (b'q', b'r'));
        assert_eq!(cipherer.cipher(b'q', b'q').unwrap(), (b'w', b'g'));
    }

    #[test]
    fn rectangle_tests() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'o', b'l').unwrap(), (b'n', b'a'));
        assert_eq!(cipherer.cipher(b'e', b'g').unwrap(), (b'x', b'd'));
        assert_eq!(cipherer.cipher(b't', b'h').unwrap(), (b'z', b'b'));
        assert_eq!(cipherer.cipher(b'h', b'i').unwrap(), (b'b', b'm'));
    }

    #[test]
    fn same_row_tests() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'p', b'l').unwrap(), (b'l', b'a'));
        assert_eq!(cipherer.cipher(b'y', b'f').unwrap(), (b'f', b'p'));
        assert_eq!(cipherer.cipher(b'y', b'f').unwrap(), (b'f', b'p'));
        assert_eq!(cipherer.cipher(b'a', b'f').unwrap(), (b'y', b'p'));
        assert_eq!(cipherer.cipher(b'k', b's').unwrap(), (b'n', b'k'));
        assert_eq!(cipherer.cipher(b'u', b'z').unwrap(), (b'v', b't'));
    }

    #[test]
    fn same_column_test() {
        let cipherer = init();
        assert_eq!(cipherer.cipher(b'p', b'i').unwrap(), (b'i', b'b'));
        assert_eq!(cipherer.cipher(b'b', b't').unwrap(), (b'k', b'p'));
        assert_eq!(cipherer.cipher(b'e', b'd').unwrap(), (b'd', b'o'));
        assert_eq!(cipherer.cipher(b'f', b's').unwrap(), (b'm', b'z'));
        assert_eq!(cipherer.cipher(b'n', b'u').unwrap(), (b'u', b'l'));
        assert_eq!(cipherer.cipher(b'x', b'w').unwrap(), (b'g', b'y'));
    }
}
