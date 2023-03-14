const EMPTY: usize = 25usize;

#[derive(PartialEq, Debug)]
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
        Self {
            letters_mtx,
            positions_mtx,
        }
    }

    pub fn cipher(&self, chr1: u8, chr2: u8, reverse: bool) -> PlayfairOutcome {
        let rev: isize = if reverse { -1 } else { 1 };
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
                self.letters_mtx[if ((chr_pos as isize + rev) as usize) / 5 != chr_pos / 5 {
                    (chr_pos as isize - 4 * rev) as usize
                } else {
                    (chr_pos as isize + rev) as usize
                }]
            };
            (letter(chr1_pos), letter(chr2_pos))
        } else if chr1_pos % 5 == chr2_pos % 5 {
            let letter = |chr_pos: usize| -> u8 {
                self.letters_mtx[if (chr_pos as isize + 5 * rev) as usize > 24 {
                    (chr_pos as isize - 20 * rev) as usize
                } else {
                    (chr_pos as isize + 5 * rev) as usize
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
    use crate::cipherer::{Cipherer, PlayfairOutcome};
    fn init() -> Cipherer {
        Cipherer::with("playfairexample".as_bytes())
    }

    #[test]
    fn duplicate_tests() {
        let cipherer = init();
        // Ciphering and deciphering identical pairs is not symmetrical
        // I'm 99% sure it is impossible to get an identical pair after
        // ciphering so we won't test it
        assert_eq!(
            cipherer.cipher(b'x', b'x', false),
            PlayfairOutcome::Duplicate((b'g', b'w'))
        );
        assert_eq!(
            cipherer.cipher(b'r', b'r', false),
            PlayfairOutcome::Duplicate((b'e', b'm'))
        );
        assert_eq!(
            cipherer.cipher(b'n', b'n', false),
            PlayfairOutcome::Duplicate((b'q', b'r'))
        );
        assert_eq!(
            cipherer.cipher(b'q', b'q', false),
            PlayfairOutcome::Duplicate((b'w', b'g'))
        );
    }

    #[test]
    fn rectangle_tests() {
        let cipherer = init();
        [
            (b'o', b'l', b'n', b'a'),
            (b't', b'h', b'z', b'b'),
            (b'e', b'g', b'x', b'd'),
            (b'h', b'i', b'b', b'm'),
        ]
        .iter()
        .for_each(|&(a, b, c, d)| {
            assert_eq!(
                cipherer.cipher(a, b, false),
                PlayfairOutcome::Normal((c, d))
            );
            assert_eq!(cipherer.cipher(c, d, true), PlayfairOutcome::Normal((a, b)));
        })
    }

    #[test]
    fn same_row_tests() {
        let cipherer = init();
        [
            (b'p', b'l', b'l', b'a'),
            (b'y', b'f', b'f', b'p'),
            (b'a', b'f', b'y', b'p'),
            (b'k', b's', b'n', b'k'),
            (b'u', b'z', b'v', b't'),
        ]
        .iter()
        .for_each(|&(a, b, c, d)| {
            assert_eq!(
                cipherer.cipher(a, b, false),
                PlayfairOutcome::Normal((c, d))
            );
            assert_eq!(cipherer.cipher(c, d, true), PlayfairOutcome::Normal((a, b)));
        })
    }

    #[test]
    fn same_column_test() {
        let cipherer = init();
        [
            (b'p', b'i', b'i', b'b'),
            (b'b', b't', b'k', b'p'),
            (b'e', b'd', b'd', b'o'),
            (b'f', b's', b'm', b'z'),
            (b'n', b'u', b'u', b'l'),
            (b'x', b'w', b'g', b'y'),
        ]
        .iter()
        .for_each(|&(a, b, c, d)| {
            assert_eq!(
                cipherer.cipher(a, b, false),
                PlayfairOutcome::Normal((c, d))
            );
            assert_eq!(cipherer.cipher(c, d, true), PlayfairOutcome::Normal((a, b)));
        })
    }
}
