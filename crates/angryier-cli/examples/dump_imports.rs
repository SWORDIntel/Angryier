//! Print the PE import list of an image in loader order (stub index order).
use angryier_loader::ImageLoader;

fn main() {
    let path = std::env::args().nth(1).expect("path");
    let bytes = std::fs::read(&path).expect("read");
    let image = angryier_loader::Pe32Loader::new().load(&bytes).expect("load");
    let imports = image.pe_imports().expect("pe imports");
    eprintln!("imports: {}", imports.len());
    for (i, imp) in imports.iter().enumerate() {
        match &imp.kind {
            angryier_loader::PeImportKind::Name(n) => {
                println!("{}\t{}\t{}", i, imp.dll, n);
            }
            angryier_loader::PeImportKind::Ordinal(o) => {
                println!("{}\t{}\t#{}", i, imp.dll, o);
            }
        }
    }
}
