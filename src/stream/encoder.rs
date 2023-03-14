use std::io;
use std::io::Read;
use super::Playfair;

pub struct PlayfairEncoder<T: Read>(Playfair<T>);

impl<T: Read> PlayfairEncoder<T> {
    pub fn new(key: &str, stream: T) -> Self {
        Self(Playfair::new(key, stream))
    }
}

impl<T: Read> Read for PlayfairEncoder<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.__read(buf, false)
    }
}
