mod cipherer;
mod encoder;

use std::io;
use std::io::Read;

use std::env;

use std::fs;

use std::str::from_utf8;

use encoder::PlayfairEncoder;

fn main() -> io::Result<()> {
    let args = env::args().collect::<Vec<String>>();
    let reader: Box<dyn io::Read> = if let Some(filename) = args.get(2) {
        Box::new(fs::File::open(filename)?)
    } else {
        Box::new(io::stdin())
    };
    let mut enc = PlayfairEncoder::new(&args[1], reader);
    let mut buf = vec![0u8; 256];
    let len = enc.read(&mut buf)?;
    print!("{}", from_utf8(&buf[..len]).unwrap());
    Ok(())
}
