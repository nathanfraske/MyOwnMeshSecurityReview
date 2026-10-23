//! No extraction subprocess or filesystem writes: one bounded regular member.
use std::io::{Cursor, Read};
use std::time::{Duration, Instant};

use crate::bounded::{self, DeadlineReader, ExpandedReader};
use crate::{Error, Result};

#[derive(Clone, Copy)]
struct Limits {
    encoded: usize,
    member: usize,
    expanded: usize,
    metadata: usize,
    headers: usize,
    time: Duration,
}

const LIMITS: Limits = Limits {
    encoded: bounded::ARTIFACT_BYTES,
    member: bounded::BINARY_BYTES,
    expanded: 272 * 1024 * 1024,
    metadata: 64 * 1024,
    headers: 16,
    time: Duration::from_secs(30),
};

pub(crate) fn extract(bytes: &[u8], binary_name: &str) -> Result<Box<[u8]>> {
    extract_with_limits(bytes, binary_name, LIMITS)
}

fn extract_with_limits(bytes: &[u8], binary_name: &str, limits: Limits) -> Result<Box<[u8]>> {
    if bytes.len() > limits.encoded {
        return Err(Error::msg("updater encoded archive byte limit exceeded"));
    }
    let deadline = Instant::now()
        .checked_add(limits.time)
        .ok_or_else(|| Error::msg("invalid updater archive deadline"))?;
    bounded::check_deadline(deadline)?;
    let result = if bytes.starts_with(b"PK\x03\x04") {
        extract_zip(bytes, binary_name, limits, deadline)
    } else {
        extract_tar(bytes, binary_name, limits, deadline)
    }?;
    bounded::check_deadline(deadline)?;
    Ok(result.into_boxed_slice())
}

fn tar_reader(
    bytes: &[u8],
    limits: Limits,
    deadline: Instant,
) -> ExpandedReader<DeadlineReader<Box<dyn Read + '_>>> {
    let input = DeadlineReader {
        inner: Cursor::new(bytes),
        deadline,
    };
    let reader: Box<dyn Read + '_> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(input))
    } else {
        Box::new(input)
    };
    ExpandedReader {
        inner: DeadlineReader {
            inner: reader,
            deadline,
        },
        remaining: limits.expanded,
    }
}

fn extract_tar(bytes: &[u8], name: &str, limits: Limits, deadline: Instant) -> Result<Vec<u8>> {
    // Inspect raw headers first: the tar library must never materialize an
    // unbounded GNU/PAX extension before its actual metadata size is checked.
    let mut raw = tar::Archive::new(tar_reader(bytes, limits, deadline));
    let mut metadata = 0usize;
    let mut headers = 0usize;
    let mut files = 0usize;
    for entry in raw.entries()?.raw(true) {
        bounded::check_deadline(deadline)?;
        let entry = entry?;
        headers += 1;
        if headers > limits.headers {
            return Err(Error::msg("updater archive header limit exceeded"));
        }
        let kind = entry.header().entry_type();
        let size = usize::try_from(entry.size())
            .map_err(|_| Error::msg("updater archive size overflow"))?;
        if kind.is_file() {
            files += 1;
            if files != 1 || size == 0 || size > limits.member {
                return Err(Error::msg(
                    "updater archive member count/byte limit exceeded",
                ));
            }
        } else if kind.is_gnu_longname() || kind.is_pax_local_extensions() {
            metadata = metadata
                .checked_add(size)
                .ok_or_else(|| Error::msg("archive metadata overflow"))?;
            if metadata > limits.metadata {
                return Err(Error::msg("updater archive metadata byte limit exceeded"));
            }
        } else {
            return Err(Error::msg(
                "archive member is not a regular file or bounded path metadata",
            ));
        }
    }
    if files != 1 {
        return Err(Error::msg("archive must contain exactly one regular file"));
    }
    // Count even trailing padding and concatenated gzip members against the
    // expansion budget. Extra data after the tar terminator cannot hide a
    // second archive; only zero padding is accepted.
    let mut tail = raw.into_inner();
    let mut buffer = [0; 8192];
    loop {
        let count = tail.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(Error::msg("archive has non-padding trailing data"));
        }
    }
    // Parse the now-bounded extensions for the logical path. Both passes use
    // one absolute deadline, and neither writes anything into the filesystem.
    let mut archive = tar::Archive::new(tar_reader(bytes, limits, deadline));
    let mut entries = archive.entries()?;
    let mut entry = entries
        .next()
        .ok_or_else(|| Error::msg("archive is empty"))??;
    if !entry.header().entry_type().is_file()
        || entry.path_bytes().as_ref() != name.as_bytes()
        || entry.size() == 0
        || entry.size() > limits.member as u64
    {
        return Err(Error::msg(format!(
            "archive must contain exactly the flat regular `{name}` member"
        )));
    }
    let expected = entry.size();
    let result = bounded::read(&mut entry, limits.member)?;
    if result.len() as u64 != expected {
        return Err(Error::msg("truncated archive member"));
    }
    drop(entry);
    if entries.next().transpose()?.is_some() {
        return Err(Error::msg("archive contains extra members"));
    }
    Ok(result)
}

fn zip_directory_preflight(bytes: &[u8], limits: Limits, deadline: Instant) -> Result<()> {
    // Guard the count BEFORE ZipArchive allocates its central-directory map.
    // ZIP64 is unnecessary for this one-file, sub-4-GiB release format.
    let start = bytes.len().saturating_sub(22 + u16::MAX as usize);
    let end = bytes[start..]
        .windows(4)
        .rposition(|part| part == b"PK\x05\x06")
        .map(|pos| pos + start)
        .ok_or_else(|| Error::msg("ZIP end record missing"))?;
    let record = bytes
        .get(end..end + 22)
        .ok_or_else(|| Error::msg("truncated ZIP end record"))?;
    let u16_at = |offset| u16::from_le_bytes([record[offset], record[offset + 1]]);
    let u32_at = |offset| u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
    let directory_bytes = u32_at(12) as usize;
    let offset = u32_at(16) as usize;
    if u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(8) != 1
        || u16_at(10) != 1
        || directory_bytes > limits.metadata
        || u16_at(20) as usize > limits.metadata
        || offset.checked_add(directory_bytes) != Some(end)
        || end.checked_add(22 + u16_at(20) as usize) != Some(bytes.len())
        || (end >= 20 && &bytes[end - 20..end - 16] == b"PK\x06\x07")
    {
        return Err(Error::msg(
            "updater ZIP directory count/metadata limit exceeded",
        ));
    }
    let header = bytes
        .get(offset..offset + 46)
        .ok_or_else(|| Error::msg("truncated ZIP directory entry"))?;
    let field_len = |at| u16::from_le_bytes([header[at], header[at + 1]]) as usize;
    if &header[..4] != b"PK\x01\x02"
        || 46 + field_len(28) + field_len(30) + field_len(32) != directory_bytes
    {
        return Err(Error::msg(
            "ZIP directory must describe exactly one bounded entry",
        ));
    }
    // zip 4.6.1 retries EARLIER EOCDs if this directory cannot be parsed,
    // allocating from their counts before returning an archive. Known(0)
    // below fixes central-header lookup at the recorded offset; reject every
    // other end record that could reach that allocation path. Scan the whole
    // input, not just the standard comment window: the dependency does too.
    // A literal signature in a stored executable is not by itself a record.
    for (chunk_index, chunk) in bytes.chunks(8192).enumerate() {
        bounded::check_deadline(deadline)?;
        let base = chunk_index * 8192;
        for within in 0..chunk.len() {
            let position = base + within;
            if position != end && zip_alternate_end_record(bytes, position) {
                return Err(Error::msg("ambiguous ZIP end records are not supported"));
            }
        }
    }
    Ok(())
}

fn zip_alternate_end_record(bytes: &[u8], position: usize) -> bool {
    let Some(record) = bytes.get(position..).and_then(|tail| tail.get(..22)) else {
        return false;
    };
    if &record[..4] != b"PK\x05\x06" {
        return false;
    }
    let field = |at| u16::from_le_bytes([record[at], record[at + 1]]);
    // The pinned parser permits trailing bytes after an end-record comment.
    if field(20) as usize > bytes.len() - position - 22 {
        return false;
    }
    let offset = u32::from_le_bytes(record[16..20].try_into().unwrap());
    if (field(10) == u16::MAX || offset == u32::MAX)
        && position >= 20
        && &bytes[position - 20..position - 16] == b"PK\x06\x07"
    {
        // Fail closed before ZIP64 parsing can allocate extensible metadata.
        return true;
    }
    if field(4) != field(6) {
        return false; // read_central_header refuses disk mismatch before allocation.
    }
    if field(10) == 0 {
        // Even an apparently empty EOCD can carry a different on-disk count,
        // which is the count used by the dependency's ZIP32 allocation.
        return true;
    }
    let offset = offset as usize;
    offset < position
        && position - offset >= 4
        && bytes.get(offset..offset + 4) == Some(b"PK\x01\x02".as_slice())
}

fn extract_zip(bytes: &[u8], name: &str, limits: Limits, deadline: Instant) -> Result<Vec<u8>> {
    zip_directory_preflight(bytes, limits, deadline)?;
    let input = DeadlineReader {
        inner: Cursor::new(bytes),
        deadline,
    };
    let mut archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        input,
    )
    .map_err(|error| Error::msg(format!("invalid ZIP: {error}")))?;
    if archive.len() != 1 {
        return Err(Error::msg("archive contains extra members"));
    }
    let entry = archive
        .by_index_raw(0)
        .map_err(|error| Error::msg(format!("invalid ZIP member: {error}")))?;
    let mode = entry.unix_mode().map(|mode| mode & 0o170000).unwrap_or(0);
    if entry.encrypted()
        || !entry.is_file()
        || !matches!(mode, 0 | 0o100000)
        || entry.name_raw() != name.as_bytes()
        || entry.size() == 0
        || entry.size() > limits.member as u64
        || !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        )
    {
        return Err(Error::msg(format!(
            "archive must contain exactly the flat regular `{name}` member within its byte limit"
        )));
    }
    let expected = entry.size();
    drop(entry);
    // Check algorithm and declared size before initializing a decoder, even
    // if another dependency enables extra ZIP features in a unified build.
    let mut entry = archive
        .by_index(0)
        .map_err(|error| Error::msg(format!("invalid ZIP member: {error}")))?;
    let expanded = ExpandedReader {
        inner: &mut entry,
        remaining: limits.expanded,
    };
    let output = bounded::read(
        DeadlineReader {
            inner: expanded,
            deadline,
        },
        limits.member,
    )?;
    if output.len() as u64 != expected {
        return Err(Error::msg("ZIP member size mismatch"));
    }
    Ok(output)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn tar_fixture(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        for (name, bytes, kind) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            // Raw fixture header permits deliberate traversal/link cases that
            // the safe Builder::append_data path constructor would reject.
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            archive.append(&header, *bytes).unwrap();
        }
        archive.into_inner().unwrap()
    }

    pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn zip_fixture(names: &[&str], bytes: &[u8]) -> Vec<u8> {
        zip_fixture_with_method(names, bytes, zip::CompressionMethod::Deflated)
    }

    fn zip_fixture_with_method(
        names: &[&str],
        bytes: &[u8],
        method: zip::CompressionMethod,
    ) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            archive
                .start_file(
                    *name,
                    zip::write::SimpleFileOptions::default()
                        .compression_method(method)
                        .unix_permissions(0o755),
                )
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    #[test]
    fn updater_budget_zip_alternate_eocd_refused_before_dependency_fallback() {
        for names in [vec!["myownmesh"], vec!["myownmesh", "extra"]] {
            let mut bytes = zip_fixture(&names, b"earlier body");
            let final_zip = zip_fixture(&["myownmesh"], b"final body");
            let end = final_zip.len() - 22;
            let central =
                u32::from_le_bytes(final_zip[end + 16..end + 20].try_into().unwrap()) as usize;
            let mut final_directory = final_zip[central..end].to_vec();
            // A structurally bounded one-entry directory which the dependency
            // rejects while parsing metadata (AES method without AES extra).
            final_directory[10..12].copy_from_slice(&99u16.to_le_bytes());
            let final_offset = bytes.len() as u32;
            bytes.extend(final_directory);
            let mut final_end = final_zip[end..].to_vec();
            final_end[16..20].copy_from_slice(&final_offset.to_le_bytes());
            bytes.extend(final_end);

            // Safe small-count witness: the locked dependency actually retries
            // the earlier directory, including its count=2. Our predecessor's
            // final-EOCD-only preflight accepted this layout before allocating.
            let mut fallback = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
            assert_eq!(fallback.len(), names.len());
            let mut body = Vec::new();
            fallback
                .by_index(0)
                .unwrap()
                .read_to_end(&mut body)
                .unwrap();
            assert_eq!(body, b"earlier body");
            let error =
                zip_directory_preflight(&bytes, LIMITS, Instant::now() + Duration::from_secs(30))
                    .unwrap_err();
            assert!(error.to_string().contains("ambiguous ZIP end records"));
            assert!(extract(&bytes, "myownmesh").is_err());
        }
    }

    #[test]
    fn updater_budget_zip_literal_signatures_allowed_but_zip64_alternative_refused() {
        // A valid stored binary may contain ZIP magic. This incomplete end
        // record has an impossible comment and cannot be a fallback candidate.
        let mut body = b"prefixPK\x05\x06".to_vec();
        body.extend([0; 16]);
        body.extend(u16::MAX.to_le_bytes());
        body.extend(b"suffixPK\x01\x02PK\x06\x07");
        let mut bytes =
            zip_fixture_with_method(&["myownmesh"], &body, zip::CompressionMethod::Stored);
        assert_eq!(&*extract(&bytes, "myownmesh").unwrap(), body.as_slice());
        let end = bytes.len() - 22;
        let comment = b"ordinary release ZIP comment";
        bytes[end + 20..end + 22].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        bytes.extend(comment);
        assert_eq!(&*extract(&bytes, "myownmesh").unwrap(), body.as_slice());

        // Reject ZIP64 locator candidates before the dependency can parse
        // their extensible data or use their 64-bit entry count.
        let mut body = vec![0; 20 + 22];
        body[..4].copy_from_slice(b"PK\x06\x07");
        body[20..24].copy_from_slice(b"PK\x05\x06");
        body[30..32].copy_from_slice(&u16::MAX.to_le_bytes());
        let bytes = zip_fixture_with_method(&["myownmesh"], &body, zip::CompressionMethod::Stored);
        assert!(
            zip_directory_preflight(&bytes, LIMITS, Instant::now() + Duration::from_secs(30),)
                .is_err()
        );
    }

    #[test]
    fn updater_budget_tar_gzip_member_and_total_expansion_exact_fit() {
        let raw = tar_fixture(&[("myownmesh", b"body", tar::EntryType::Regular)]);
        let compressed = gzip(&raw);
        let limits = Limits {
            encoded: compressed.len(),
            member: 4,
            expanded: raw.len(),
            ..LIMITS
        };
        assert_eq!(
            &*extract_with_limits(&compressed, "myownmesh", limits).unwrap(),
            b"body"
        );
        assert_eq!(&*extract(&raw, "myownmesh").unwrap(), b"body");
        for limits in [
            Limits {
                encoded: compressed.len() - 1,
                ..limits
            },
            Limits {
                member: 3,
                ..limits
            },
            Limits {
                expanded: raw.len() - 1,
                ..limits
            },
            Limits {
                headers: 0,
                ..limits
            },
            Limits {
                time: Duration::ZERO,
                ..limits
            },
        ] {
            assert!(extract_with_limits(&compressed, "myownmesh", limits).is_err());
        }
    }

    #[test]
    fn updater_budget_tar_metadata_paths_links_and_hidden_archives_refused() {
        for entries in [
            vec![("../myownmesh", &b"body"[..], tar::EntryType::Regular)],
            vec![("myownmesh", &b""[..], tar::EntryType::Symlink)],
            vec![
                ("myownmesh", &b"body"[..], tar::EntryType::Regular),
                ("extra", &b"x"[..], tar::EntryType::Regular),
            ],
            vec![
                ("pax", &b"01234567890123456789"[..], tar::EntryType::XHeader),
                ("myownmesh", &b"body"[..], tar::EntryType::Regular),
            ],
        ] {
            let bytes = gzip(&tar_fixture(&entries));
            assert!(extract_with_limits(
                &bytes,
                "myownmesh",
                Limits {
                    metadata: 16,
                    ..LIMITS
                }
            )
            .is_err());
        }
        let raw = tar_fixture(&[("myownmesh", b"body", tar::EntryType::Regular)]);
        let mut hidden = gzip(&raw);
        hidden.extend(gzip(&raw));
        assert!(extract(&hidden, "myownmesh").is_err());
    }

    #[test]
    fn updater_budget_zip_directory_member_and_crc_refusal() {
        let bytes = zip_fixture(&["myownmesh"], b"body");
        assert_eq!(
            &*extract_with_limits(
                &bytes,
                "myownmesh",
                Limits {
                    member: 4,
                    expanded: 4,
                    ..LIMITS
                }
            )
            .unwrap(),
            b"body"
        );
        for limits in [
            Limits {
                member: 3,
                ..LIMITS
            },
            Limits {
                expanded: 3,
                ..LIMITS
            },
            Limits {
                metadata: 1,
                ..LIMITS
            },
        ] {
            assert!(extract_with_limits(&bytes, "myownmesh", limits).is_err());
        }
        let mut count = bytes.clone();
        let end = count.len() - 22;
        count[end + 8..end + 12].fill(0xff);
        assert!(extract(&count, "myownmesh").is_err());
        let mut crc = bytes.clone();
        let central = crc
            .windows(4)
            .position(|part| part == b"PK\x01\x02")
            .unwrap();
        crc[central + 16] ^= 1;
        assert!(extract(&crc, "myownmesh").is_err());
        let mut symlink = bytes.clone();
        symlink[central + 5] = 3; // Unix creator; external mode is a symlink.
        symlink[central + 38..central + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
        assert!(extract(&symlink, "myownmesh").is_err());
        assert!(extract(&zip_fixture(&["../myownmesh"], b"body"), "myownmesh").is_err());
        assert!(extract(&zip_fixture(&["myownmesh", "extra"], b"body"), "myownmesh").is_err());
    }
}
