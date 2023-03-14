mod cipherer;
mod encoder;

use std::fs;
use std::io;
use std::io::Read;
use std::str::from_utf8;

use encoder::{PlayfairDecoder, PlayfairEncoder};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    decode: bool,
    #[arg(short, long)]
    key: String,
    filename: Option<String>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let reader_: Box<dyn io::Read> = if let Some(filename) = args.filename {
        Box::new(fs::File::open(filename)?)
    } else {
        Box::new(io::stdin())
    };
    let mut reader: Box<dyn io::Read> = if args.decode {
        Box::new(PlayfairDecoder::new(&args.key, reader_))
    } else {
        Box::new(PlayfairEncoder::new(&args.key, reader_))
    };
    let mut buf = vec![0u8; 256];
    let len = reader.read(&mut buf)?;
    print!("{}", from_utf8(&buf[..len]).unwrap());
    Ok(())
}
