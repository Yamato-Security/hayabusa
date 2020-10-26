use std::fmt;

pub enum Omikuji {
    DAIKICHI,
    KICHI,
    CHUKICHI,
    SHOUKICHI,
    SUEKICHI,
    KYOU,
}

impl fmt::Display for Omikuji {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Omikuji::DAIKICHI => write!(f, "DAIKICHI.txt"),
            Omikuji::KICHI => write!(f, "KICHI.txt"),
            Omikuji::CHUKICHI => write!(f, "CHUKICHI.txt"),
            Omikuji::SHOUKICHI => write!(f, "SHOUKICHI.txt"),
            Omikuji::SUEKICHI => write!(f, "SUEKICHI.txt"),
            Omikuji::KYOU => write!(f, "KYOU.txt"),
        }
    }
}



#[test]
fn test_display() {
    assert_eq!("DAIKICHI.txt", Omikuji::DAIKICHI.to_string());
}
