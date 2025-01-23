pub trait Keystream {
    type Word;

    fn next_key(&mut self) -> Self::Word;
}
