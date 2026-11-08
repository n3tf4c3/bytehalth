//! Migração de uma pasta para o volume do cofre: inventário (o que impede ou exige atenção), cópia
//! fiel (dados, fluxos alternativos e atributos pelo `CopyFileEx` do `std::fs::copy`; dono e DACL pelo
//! [`SecurityCopier`]), manifesto com SHA-256 e comparação. Nada aqui apaga ou move o original.

use crate::vault::SecurityCopier;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const LISTED: usize = 10;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Impedem a migração (links, junções, arquivos na nuvem, itens ilegíveis).
    pub blocking: Vec<String>,
    /// Não impedem, mas o usuário deve saber.
    pub warnings: Vec<String>,
}

#[cfg(windows)]
fn attributes(m: &fs::Metadata) -> u32 {
    std::os::windows::fs::MetadataExt::file_attributes(m)
}
#[cfg(not(windows))]
fn attributes(_: &fs::Metadata) -> u32 {
    0
}

const REPARSE_POINT: u32 = 0x400;
const OFFLINE: u32 = 0x1000;
const RECALL_ON_OPEN: u32 = 0x4_0000;
const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('/', "\\")
}

fn push_limited(list: &mut Vec<String>, count: &mut usize, text: String) {
    *count += 1;
    if *count <= LISTED {
        list.push(text);
    }
}

/// Percorre a pasta sem seguir links. A raiz também é verificada.
pub fn scan(root: &Path) -> io::Result<Inventory> {
    let meta = fs::symlink_metadata(root)?;
    let mut inv = Inventory::default();
    if !meta.is_dir() || meta.file_type().is_symlink() || attributes(&meta) & REPARSE_POINT != 0 {
        inv.blocking.push("A pasta é um link, uma junção ou não é uma pasta.".into());
        return Ok(inv);
    }
    let (mut links, mut cloud, mut unreadable) = (0usize, 0usize, 0usize);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                push_limited(&mut inv.blocking, &mut unreadable, format!("Sem leitura: {} ({e})", rel(root, &dir)));
                continue;
            }
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            // Nomes que a cópia trata como metadados de volume seriam omitidos sem aviso.
            if dir == root && is_volume_metadata(&entry.file_name().to_string_lossy()) {
                inv.blocking.push(format!(
                    "A pasta contém \"{}\" na raiz, nome reservado do Windows que não seria copiado. Renomeie ou mova antes de criar o cofre.",
                    entry.file_name().to_string_lossy()
                ));
                continue;
            }
            let m = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    push_limited(&mut inv.blocking, &mut unreadable, format!("Sem leitura: {} ({e})", rel(root, &path)));
                    continue;
                }
            };
            let a = attributes(&m);
            if m.file_type().is_symlink() || a & REPARSE_POINT != 0 {
                if a & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE) != 0 {
                    push_limited(&mut inv.blocking, &mut cloud, format!("Arquivo só na nuvem: {}", rel(root, &path)));
                } else {
                    push_limited(&mut inv.blocking, &mut links, format!("Link ou junção: {}", rel(root, &path)));
                }
                continue;
            }
            if a & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE) != 0 {
                push_limited(&mut inv.blocking, &mut cloud, format!("Arquivo só na nuvem: {}", rel(root, &path)));
                continue;
            }
            if m.is_dir() {
                inv.dirs += 1;
                stack.push(path);
            } else {
                inv.files += 1;
                inv.bytes += m.len();
            }
        }
    }
    for (n, what) in [(links, "link(s) ou junção(ões)"), (cloud, "arquivo(s) só na nuvem"), (unreadable, "item(ns) sem leitura")] {
        if n > LISTED {
            inv.blocking.push(format!("… e mais {} {what}.", n - LISTED));
        }
    }
    if inv.files == 0 {
        inv.warnings.push("A pasta está vazia.".into());
    }
    Ok(inv)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub sha256: Option<[u8; 32]>,
}

/// Itens por caminho relativo (`a\b.txt`), sem a raiz.
pub type Manifest = BTreeMap<String, Entry>;

fn open_for_backup(path: &Path) -> io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    // FILE_FLAG_BACKUP_SEMANTICS: com SeBackupPrivilege ativo (serviço), lê mesmo sem permissão na DACL.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut o, 0x0200_0000);
    o.open(path)
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut f = open_for_backup(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Manifesto da árvore. `hash` lê todo o conteúdo (SHA-256 do fluxo principal).
pub fn manifest(root: &Path, hash: bool) -> io::Result<Manifest> {
    let mut out = Manifest::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let m = fs::symlink_metadata(&path)?;
            let name = rel(root, &path);
            // Itens que o volume cria sozinho não fazem parte do conteúdo.
            if dir == root && is_volume_metadata(&name) {
                continue;
            }
            if m.is_dir() && !m.file_type().is_symlink() {
                out.insert(name, Entry { dir: true, size: 0, modified: None, sha256: None });
                stack.push(path);
            } else {
                let sha256 = if hash { Some(hash_file(&path)?) } else { None };
                out.insert(name, Entry { dir: false, size: m.len(), modified: m.modified().ok(), sha256 });
            }
        }
    }
    Ok(out)
}

/// Algum item da raiz de `dir` tem nome reservado de metadados de volume.
pub fn has_reserved_root_names(dir: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        if is_volume_metadata(&entry?.file_name().to_string_lossy()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Pastas de sistema da raiz de um volume NTFS.
pub fn is_volume_metadata(name: &str) -> bool {
    name.eq_ignore_ascii_case("System Volume Information") || name.eq_ignore_ascii_case("$RECYCLE.BIN")
}

/// Diferenças entre origem e cópia (conteúdo, tamanho, tipo, itens faltando ou sobrando).
pub fn diff(source: &Manifest, copy: &Manifest) -> Vec<String> {
    let mut d = Vec::new();
    for (name, s) in source {
        match copy.get(name) {
            None => d.push(format!("Falta na cópia: {name}")),
            Some(c) if c.dir != s.dir => d.push(format!("Tipo diferente: {name}")),
            Some(c) if !s.dir && (c.size != s.size || (s.sha256.is_some() && c.sha256.is_some() && c.sha256 != s.sha256)) => {
                d.push(format!("Conteúdo diferente: {name}"))
            }
            _ => {}
        }
    }
    for name in copy.keys() {
        if !source.contains_key(name) {
            d.push(format!("Sobra na cópia: {name}"));
        }
    }
    d
}

/// Itens novos ou alterados (tamanho ou data) desde o manifesto `before`, e os que sumiram.
pub fn changed_since(before: &Manifest, now: &Manifest) -> (Vec<String>, Vec<String>) {
    let changed = now
        .iter()
        .filter(|(n, e)| before.get(*n).is_none_or(|b| b.dir != e.dir || b.size != e.size || b.modified != e.modified))
        .map(|(n, _)| n.clone())
        .collect();
    let gone = before.keys().filter(|n| !now.contains_key(*n)).cloned().collect();
    (changed, gone)
}

/// O que reaplicar na cópia para ficar igual à origem: itens faltando ou diferentes (tipo, tamanho,
/// SHA-256) e itens que sobram.
pub fn to_resync(source: &Manifest, copy: &Manifest) -> (Vec<String>, Vec<String>) {
    let differs = |s: &Entry, c: &Entry| c.dir != s.dir || c.size != s.size || c.sha256 != s.sha256;
    let changed = source.iter().filter(|(n, s)| copy.get(*n).is_none_or(|c| differs(s, c))).map(|(n, _)| n.clone()).collect();
    let gone = copy.keys().filter(|n| !source.contains_key(*n)).cloned().collect();
    (changed, gone)
}

/// Progresso da cópia em bytes.
pub type Progress<'a> = &'a (dyn Fn(u64) + Sync);

/// Copia o conteúdo de `src` para `dst` (pasta existente, normalmente a raiz do volume do cofre).
/// A segurança da raiz de `src` vai para `dst`; cada item leva a sua.
pub fn copy_tree(src: &Path, dst: &Path, security: &dyn SecurityCopier, progress: Progress) -> io::Result<u64> {
    let mut done = 0u64;
    let mut dirs: Vec<(PathBuf, PathBuf)> = vec![(src.to_path_buf(), dst.to_path_buf())];
    let mut stack: Vec<(PathBuf, PathBuf)> = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        for entry in fs::read_dir(&from)? {
            let path = entry?.path();
            let name = path.file_name().ok_or_else(|| io::Error::other("nome inválido"))?;
            // Na raiz de um volume (cópia de volta do cofre), as pastas de sistema ficam (vista na VM).
            if from == src && is_volume_metadata(&name.to_string_lossy()) {
                continue;
            }
            let target = to.join(name);
            done += copy_item(&path, &target, security)?;
            progress(done);
            if fs::symlink_metadata(&path)?.is_dir() {
                dirs.push((path.clone(), target.clone()));
                stack.push((path, target));
            }
        }
    }
    // Segurança das pastas por último (da mais funda para a raiz): uma pasta restrita não impede
    // a gravação do que está dentro dela.
    // A raiz (primeira da lista) recebe a segurança como raiz de volume.
    for (i, (from, to)) in dirs.iter().enumerate().rev() {
        if i == 0 { security.copy_root(from, to)? } else { security.copy(from, to)? }
    }
    Ok(done)
}

/// Copia um item (pasta vazia, sem a segurança, ou arquivo com a segurança). Recusa links: o
/// inventário já os barrou.
fn copy_item(path: &Path, target: &Path, security: &dyn SecurityCopier) -> io::Result<u64> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() || attributes(&m) & REPARSE_POINT != 0 {
        return Err(io::Error::other(format!("Link ou junção na origem: {}", path.display())));
    }
    if m.is_dir() {
        match fs::create_dir(target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && target.is_dir() => {}
            Err(e) => return Err(e),
        }
        Ok(0)
    } else {
        let n = fs::copy(path, target)?;
        security.copy(path, target)?;
        Ok(n)
    }
}

/// Reaplica na cópia os itens que mudaram na origem depois da cópia inicial.
pub fn resync(src: &Path, dst: &Path, changed: &[String], gone: &[String], security: &dyn SecurityCopier) -> io::Result<()> {
    // Pastas antes dos arquivos (ordem lexicográfica põe o pai antes do filho).
    let mut changed = changed.to_vec();
    changed.sort();
    let mut dirs = Vec::new();
    for name in &changed {
        let from = src.join(name);
        let to = dst.join(name);
        let is_dir = fs::symlink_metadata(&from)?.is_dir();
        if to.is_file() && is_dir {
            fs::remove_file(&to)?;
        } else if to.is_dir() && !is_dir {
            fs::remove_dir_all(&to)?;
        }
        copy_item(&from, &to, security)?;
        if is_dir {
            dirs.push((from, to));
        }
    }
    for (from, to) in dirs.iter().rev() {
        security.copy(from, to)?;
    }
    let mut gone = gone.to_vec();
    gone.sort_by(|a, b| b.cmp(a));
    for name in &gone {
        let p = dst.join(name);
        if p.is_dir() {
            fs::remove_dir_all(&p)?;
        } else if p.exists() {
            fs::remove_file(&p)?;
        }
    }
    Ok(())
}

/// Fluxos alternativos por item (caminho relativo; `""` é a raiz): nome do fluxo → SHA-256.
/// Só itens com algum fluxo aparecem.
pub type Streams = BTreeMap<String, BTreeMap<String, [u8; 32]>>;

fn item(root: &Path, name: &str) -> PathBuf {
    if name.is_empty() { root.to_path_buf() } else { root.join(name) }
}

fn stream_path(p: &Path, stream: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(":");
    s.push(stream);
    PathBuf::from(s)
}

/// Fluxos alternativos da raiz e de cada item do manifesto (listados pela plataforma, lidos aqui).
pub fn streams(root: &Path, manifest: &Manifest, security: &dyn SecurityCopier) -> io::Result<Streams> {
    let mut out = Streams::new();
    for name in std::iter::once("").chain(manifest.keys().map(String::as_str)) {
        let path = item(root, name);
        let mut found = BTreeMap::new();
        for s in security.streams(&path)? {
            found.insert(s.clone(), hash_file(&stream_path(&path, &s))?);
        }
        if !found.is_empty() {
            out.insert(name.to_owned(), found);
        }
    }
    Ok(out)
}
/// Itens cujos fluxos alternativos diferem (nomes, conteúdo, faltando ou sobrando).
pub fn stream_diff(source: &Streams, copy: &Streams) -> Vec<String> {
    let mut names: Vec<&String> = source.keys().chain(copy.keys()).collect();
    names.sort();
    names.dedup();
    names.into_iter().filter(|n| source.get(*n) != copy.get(*n)).map(|n| format!("Fluxos alternativos diferentes: {n}")).collect()
}

/// Deixa os fluxos alternativos da cópia iguais aos da origem. Arquivo: copiado de novo por inteiro
/// (dados, fluxos e segurança). Pasta ou raiz: cada fluxo é regravado e os que sobram, removidos.
pub fn sync_streams(src: &Path, dst: &Path, manifest: &Manifest, source: &Streams, copy: &Streams, security: &dyn SecurityCopier) -> io::Result<()> {
    let empty = BTreeMap::new();
    let mut names: Vec<&String> = source.keys().chain(copy.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let (want, have) = (source.get(name).unwrap_or(&empty), copy.get(name).unwrap_or(&empty));
        if want == have {
            continue;
        }
        let (from, to) = (item(src, name), item(dst, name));
        if manifest.get(name).is_some_and(|e| !e.dir) {
            fs::remove_file(&to)?;
            copy_item(&from, &to, security)?;
            continue;
        }
        for stream in have.keys().filter(|s| !want.contains_key(*s)) {
            fs::remove_file(stream_path(&to, stream))?;
        }
        for (stream, hash) in want {
            if have.get(stream) != Some(hash) {
                let mut r = open_for_backup(&stream_path(&from, stream))?;
                let mut w = fs::File::create(stream_path(&to, stream))?;
                io::copy(&mut r, &mut w)?;
                w.sync_all()?;
            }
        }
    }
    Ok(())
}

/// Reaplica dono e DACL da origem em TODOS os itens da cópia, inclusive os de conteúdo inalterado:
/// uma permissão revogada depois da preparação não muda tamanho nem SHA-256. Pastas da mais funda
/// para a raiz; a raiz como raiz de volume.
pub fn reapply_security(src: &Path, dst: &Path, manifest: &Manifest, security: &dyn SecurityCopier) -> io::Result<()> {
    for (name, _) in manifest.iter().filter(|(_, e)| !e.dir) {
        security.copy(&src.join(name), &dst.join(name))?;
    }
    for (name, _) in manifest.iter().rev().filter(|(_, e)| e.dir) {
        security.copy(&src.join(name), &dst.join(name))?;
    }
    security.copy_root(src, dst)
}

/// Fluxos iguais entre origem e cópia, regravando o que diferir e conferindo de novo. `items` é o
/// manifesto da origem; a comparação de conteúdo já garantiu que a cópia tem os mesmos itens.
pub fn verify_streams(src: &Path, dst: &Path, items: &Manifest, security: &dyn SecurityCopier) -> Result<(), String> {
    let read = |p: &Path, what: &str| streams(p, items, security).map_err(|e| format!("Ler os fluxos alternativos {what}: {e}"));
    let (a, b) = (read(src, "do original")?, read(dst, "da cópia")?);
    if stream_diff(&a, &b).is_empty() {
        return Ok(());
    }
    sync_streams(src, dst, items, &a, &b, security).map_err(|e| format!("Atualizar os fluxos alternativos: {e}"))?;
    let again = stream_diff(&read(src, "do original")?, &read(dst, "da cópia")?);
    if !again.is_empty() {
        return Err(format!(
            "Os fluxos alternativos da cópia não conferem ({} item(ns)): {}",
            again.len(),
            again.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::NoSecurity;

    fn tree(root: &Path) {
        fs::create_dir_all(root.join("sub\\fundo")).unwrap();
        fs::write(root.join("a.txt"), b"alfa").unwrap();
        fs::write(root.join("sub\\b.bin"), vec![7u8; 300_000]).unwrap();
        fs::write(root.join("sub\\fundo\\c.txt"), b"").unwrap();
        fs::create_dir(root.join("vazia")).unwrap();
    }

    #[test]
    fn inventario_conta_e_copia_fica_identica() {
        let t = tempfile::tempdir().unwrap();
        let (src, dst) = (t.path().join("src"), t.path().join("dst"));
        tree(&src);
        fs::create_dir(&dst).unwrap();
        let inv = scan(&src).unwrap();
        assert_eq!((inv.files, inv.dirs, inv.bytes), (3, 3, 300_004));
        assert!(inv.blocking.is_empty(), "{:?}", inv.blocking);
        let copied = copy_tree(&src, &dst, &NoSecurity, &|_| {}).unwrap();
        assert_eq!(copied, 300_004);
        let (a, b) = (manifest(&src, true).unwrap(), manifest(&dst, true).unwrap());
        assert_eq!(a.len(), 6);
        assert!(diff(&a, &b).is_empty(), "{:?}", diff(&a, &b));
    }

    #[test]
    fn diferenca_de_conteudo_e_itens_faltando_sao_detectados() {
        let t = tempfile::tempdir().unwrap();
        let (src, dst) = (t.path().join("src"), t.path().join("dst"));
        tree(&src);
        fs::create_dir(&dst).unwrap();
        copy_tree(&src, &dst, &NoSecurity, &|_| {}).unwrap();
        fs::write(dst.join("a.txt"), b"ALFA").unwrap(); // mesmo tamanho, conteúdo diferente
        fs::remove_file(dst.join("sub\\fundo\\c.txt")).unwrap();
        fs::write(dst.join("extra.txt"), b"x").unwrap();
        let d = diff(&manifest(&src, true).unwrap(), &manifest(&dst, true).unwrap());
        assert!(d.iter().any(|x| x.contains("Conteúdo diferente: a.txt")), "{d:?}");
        assert!(d.iter().any(|x| x.contains("Falta na cópia: sub\\fundo\\c.txt")), "{d:?}");
        assert!(d.iter().any(|x| x.contains("Sobra na cópia: extra.txt")), "{d:?}");
    }

    #[test]
    fn alteracoes_depois_da_copia_sao_ressincronizadas() {
        let t = tempfile::tempdir().unwrap();
        let (src, dst) = (t.path().join("src"), t.path().join("dst"));
        tree(&src);
        fs::create_dir(&dst).unwrap();
        copy_tree(&src, &dst, &NoSecurity, &|_| {}).unwrap();
        let before = manifest(&src, false).unwrap();
        fs::write(src.join("a.txt"), b"alfa alterado").unwrap();
        fs::create_dir(src.join("nova")).unwrap();
        fs::write(src.join("nova\\d.txt"), b"d").unwrap();
        fs::remove_file(src.join("sub\\b.bin")).unwrap();
        let (changed, gone) = changed_since(&before, &manifest(&src, false).unwrap());
        assert!(changed.contains(&"a.txt".to_string()) && changed.contains(&"nova\\d.txt".to_string()), "{changed:?}");
        assert_eq!(gone, vec!["sub\\b.bin".to_string()]);
        resync(&src, &dst, &changed, &gone, &NoSecurity).unwrap();
        assert!(diff(&manifest(&src, true).unwrap(), &manifest(&dst, true).unwrap()).is_empty());
    }

    #[test]
    fn metadados_do_volume_nao_contam_nem_sao_copiados() {
        let t = tempfile::tempdir().unwrap();
        let (src, dst) = (t.path().join("raiz"), t.path().join("volta"));
        fs::create_dir_all(src.join("System Volume Information")).unwrap();
        fs::create_dir_all(src.join("$RECYCLE.BIN")).unwrap();
        fs::write(src.join("x.txt"), b"x").unwrap();
        fs::create_dir(&dst).unwrap();
        assert_eq!(manifest(&src, false).unwrap().keys().collect::<Vec<_>>(), vec!["x.txt"]);
        copy_tree(&src, &dst, &NoSecurity, &|_| {}).unwrap();
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 1, "só x.txt volta");
    }

    #[cfg(windows)]
    #[test]
    fn juncao_dentro_da_pasta_impede_a_migracao() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        tree(&src);
        let target = t.path().join("fora");
        fs::create_dir(&target).unwrap();
        // Junção não exige privilégio (mklink /J).
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(src.join("link"))
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let inv = scan(&src).unwrap();
        assert!(inv.blocking.iter().any(|b| b.contains("link")), "{:?}", inv.blocking);
        assert!(copy_item(&src.join("link"), &t.path().join("x"), &NoSecurity).is_err());
    }

    // Achado de auditoria #7: em pasta comum, nomes reservados de volume não podem sumir da cópia.
    #[test]
    fn nome_reservado_na_raiz_de_pasta_comum_impede_a_migracao() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        tree(&src);
        fs::create_dir_all(src.join("System Volume Information")).unwrap();
        fs::write(src.join("System Volume Information").join("notas.txt"), b"dados do usuario").unwrap();
        let inv = scan(&src).unwrap();
        assert!(inv.blocking.iter().any(|b| b.contains("System Volume Information")), "pasta com nome reservado foi aceita: {:?}", inv.blocking);
    }
}
