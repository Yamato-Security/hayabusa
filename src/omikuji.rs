pub enum Omikuji {
    DAIKICHI,
    KICHI,
    CHUKICHI,
    SHOUKICHI,
    SUEKICHI,
    KYOU,
}

impl Omikuji {
    pub fn get_file_name(&self) -> String {
        let file_name = match *self {
            Omikuji::DAIKICHI => "DAIKICHI.txt",
            Omikuji::KICHI => "KICHI.txt",
            Omikuji::CHUKICHI => "CHUKICHI.txt",
            Omikuji::SHOUKICHI => "SHOUKICHI.txt",
            Omikuji::SUEKICHI => "SUEKICHI.txt",
            Omikuji::KYOU => "KYOU.txt",
        };
        file_name.to_string()
    }
}
