use std::{env, fs, path::PathBuf};

/// Значки exe: (номер группы в ресурсах, файл). Номера — те же, что `ICON_ON`/`ICON_OFF` в main.rs;
/// первая группа — значок exe в Проводнике.
const ICONS: [(u16, &str); 2] = [(1, "assets/little-proxy.ico"), (2, "assets/little-proxy-off.ico")];

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // WinDivert требует прав администратора, а стиль контролов — Common Controls v6.
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' \
         version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
    );
    // Значки — готовым файлом ресурсов: link.exe принимает .res напрямую, rc.exe не нужен.
    let res = PathBuf::from(env::var("OUT_DIR").unwrap()).join("icons.res");
    fs::write(&res, icons_res()).unwrap();
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

/// Файл .res: пустая запись-заголовок, затем по каждому .ico — его картинки (RT_ICON) и
/// каталог группы (RT_GROUP_ICON), который ссылается на картинки по номерам.
fn icons_res() -> Vec<u8> {
    let mut res = Vec::new();
    resource(&mut res, 0, 0, 0, &[]);
    let mut next_image = 1u16;
    for (group, path) in ICONS {
        println!("cargo:rerun-if-changed={path}");
        let ico = fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let u16_at = |at: usize| u16::from_le_bytes([ico[at], ico[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(ico[at..at + 4].try_into().unwrap());
        assert!(ico.len() >= 6 && u16_at(2) == 1, "{path}: не файл .ico");
        let count = u16_at(4);
        let mut dir = [0u16.to_le_bytes(), 1u16.to_le_bytes(), count.to_le_bytes()].concat();
        for i in 0..count as usize {
            // ICONDIRENTRY: w, h, цвета, резерв, плоскости, бит, размер, смещение — 16 байт.
            let e = 6 + i * 16;
            let (size, offset) = (u32_at(e + 8) as usize, u32_at(e + 12) as usize);
            resource(&mut res, RT_ICON, next_image, 0x1010, &ico[offset..offset + size]);
            // GRPICONDIRENTRY — то же, но вместо смещения 2-байтовый номер картинки.
            dir.extend_from_slice(&ico[e..e + 12]);
            dir.extend_from_slice(&next_image.to_le_bytes());
            next_image += 1;
        }
        resource(&mut res, RT_GROUP_ICON, group, 0x1030, &dir);
    }
    res
}

/// Запись .res с числовыми типом и именем: заголовок 32 байта, данные выровнены на 4.
fn resource(res: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    res.extend_from_slice(&(data.len() as u32).to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for id in [kind, name] {
        res.extend_from_slice(&0xFFFFu16.to_le_bytes());
        res.extend_from_slice(&id.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    res.extend_from_slice(&flags.to_le_bytes());
    res.extend_from_slice(&0u16.to_le_bytes()); // язык: нейтральный
    res.extend_from_slice(&0u32.to_le_bytes()); // Version
    res.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    res.extend_from_slice(data);
    res.resize(res.len().next_multiple_of(4), 0);
}
