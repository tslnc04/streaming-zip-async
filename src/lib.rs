use chrono::{offset::Utc, DateTime, Datelike, NaiveDateTime, Timelike};
use crc::{Crc, Digest};
use miniz_oxide::{
    deflate::{core::CompressorOxide, stream::deflate},
    DataFormat, MZFlush, MZStatus,
};
use std::{
    io::{Error, ErrorKind, Result},
    os::unix::ffi::OsStringExt,
    path::Path,
};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

#[derive(Debug, Clone, Default)]
struct DataDescriptor {
    crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
}

impl DataDescriptor {
    async fn write<W: AsyncWrite + Unpin>(
        &self,
        handle: &mut W,
        with_signature: bool,
        u64_fields: bool,
        is_zip64: bool,
    ) -> Result<usize> {
        let mut written = 0;
        if with_signature {
            handle.write_all(b"PK\x07\x08").await?; // data descriptor signature
            written += 4;
        }
        handle.write_all(&self.crc.to_le_bytes()).await?;
        written += 4;
        if u64_fields {
            handle
                .write_all(&self.compressed_size.to_le_bytes())
                .await?;
            written += 8;
            handle
                .write_all(&self.uncompressed_size.to_le_bytes())
                .await?;
            written += 8;
        } else if is_zip64 {
            handle.write_all(&u32::MAX.to_le_bytes()).await?;
            written += 4;
            handle.write_all(&u32::MAX.to_le_bytes()).await?;
            written += 4;
        } else {
            handle
                .write_all(&(self.compressed_size as u32).to_le_bytes())
                .await?;
            written += 4;
            handle
                .write_all(&(self.uncompressed_size as u32).to_le_bytes())
                .await?;
            written += 4;
        }
        Ok(written)
    }
}

#[derive(Debug, Clone)]
struct FileHeader {
    name: Vec<u8>,
    last_modified: NaiveDateTime,
    data_descriptor: Option<DataDescriptor>,
    file_header_start: u64,
    compression: CompressionMode,
    is_zip64: bool,
}

impl FileHeader {
    async fn write<W: AsyncWrite + Unpin>(
        &self,
        handle: &mut W,
        is_central: bool,
    ) -> Result<usize> {
        let mut written = 0;
        if is_central {
            handle.write_all(b"PK\x01\x02").await?; // Central directory file header signature
            written += 4;
        } else {
            handle.write_all(b"PK\x03\x04").await?; // Local file header signature
            written += 4;
        }
        if is_central {
            if self.is_zip64 {
                handle.write_all(&45u16.to_le_bytes()).await?; // Version made by => 4.5
                written += 2;
            } else {
                handle.write_all(&10u16.to_le_bytes()).await?; // Version made by => 1.0
                written += 2;
            }
        }
        if self.is_zip64 {
            handle.write_all(&45u16.to_le_bytes()).await?; // Version needed to extract (minimum) => 4.5
            written += 2;
        } else {
            handle.write_all(&10u16.to_le_bytes()).await?; // Version needed to extract (minimum) => 1.0
            written += 2;
        }
        handle.write_all(&0b0000_1000u16.to_le_bytes()).await?; // General purpose bit flag => enable data descriptor
        written += 2;
        let compression_num: u16 = match self.compression {
            CompressionMode::Store => 0,
            CompressionMode::Deflate(_) => 8,
        };
        handle.write_all(&compression_num.to_le_bytes()).await?; // Compression method
        written += 2;
        let timepart = ((self.last_modified.second() as u16) >> 1)
            | ((self.last_modified.minute() as u16) << 5)
            | ((self.last_modified.hour() as u16) << 11);
        let datepart = (self.last_modified.day() as u16)
            | ((self.last_modified.month() as u16) << 5)
            | ((self.last_modified.year() as u16 - 1980) << 9);
        handle.write_all(&timepart.to_le_bytes()).await?; // File last modification time
        written += 2;
        handle.write_all(&datepart.to_le_bytes()).await?; // File last modification date
        written += 2;
        written += self
            .data_descriptor
            .clone()
            .unwrap_or_default()
            .write(handle, false, false, self.is_zip64)
            .await?;
        handle
            .write_all(&(self.name.len() as u16).to_le_bytes())
            .await?; // File name length
        written += 2;
        if self.is_zip64 {
            handle.write_all(&28u16.to_le_bytes()).await?; // Extra field length
            written += 2;
        } else {
            handle.write_all(&0u16.to_le_bytes()).await?; // Extra field length
            written += 2;
        }
        if is_central {
            handle.write_all(&0u16.to_le_bytes()).await?; // File comment length
            written += 2;
            handle.write_all(&0u16.to_le_bytes()).await?; // Disk number where file starts
            written += 2;
            handle.write_all(&0u16.to_le_bytes()).await?; // Internal file attributes
            written += 2;
            handle.write_all(&0u32.to_le_bytes()).await?; // External file attributes
            written += 4;
            if self.is_zip64 {
                handle.write_all(&u32::MAX.to_le_bytes()).await?; // Relative offset of local file header
                written += 4;
            } else {
                handle
                    .write_all(&(self.file_header_start as u32).to_le_bytes())
                    .await?; // Relative offset of local file header
                written += 4;
            }
        }
        handle.write_all(&self.name).await?; // File name
        written += self.name.len();
        if self.is_zip64 {
            handle.write_all(&1u16.to_le_bytes()).await?; // Extra field header
            written += 2;
            handle.write_all(&24u16.to_le_bytes()).await?; // Size of the extra field chunk
            written += 2;
            let dd = self.data_descriptor.clone().unwrap_or_default();
            handle
                .write_all(&dd.uncompressed_size.to_le_bytes())
                .await?; // Original uncompressed file size
            written += 8;
            handle.write_all(&dd.compressed_size.to_le_bytes()).await?; // Size of compressed data
            written += 8;
            handle
                .write_all(&self.file_header_start.to_le_bytes())
                .await?; // Offset of local header record
            written += 8;
        }
        Ok(written)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CompressionMode {
    Store,
    Deflate(u8),
}

pub struct Archive<W: AsyncWrite + Unpin> {
    compressed_buf: [u8; 4096],
    files: Vec<FileHeader>,
    written: usize,
    inner: W,
    intermediate_digest: Option<Digest<'static, u32>>,
    intermediate_compressor: Option<CompressorOxide>,
    intermediate_uncompressed_size: u64,
    intermediate_compressed_size: u64,
}

impl<W: AsyncWrite + Unpin> Archive<W> {
    pub fn new(inner: W) -> Archive<W> {
        Archive {
            compressed_buf: [0; 4096],
            files: Vec::new(),
            written: 0,
            inner,
            intermediate_digest: None,
            intermediate_compressor: None,
            intermediate_uncompressed_size: 0,
            intermediate_compressed_size: 0,
        }
    }

    pub async fn start_new_file(
        &mut self,
        name: Vec<u8>,
        last_modified: NaiveDateTime,
        compression: CompressionMode,
        use_zip64: bool,
    ) -> Result<()> {
        let file = FileHeader {
            name,
            last_modified,
            data_descriptor: None,
            file_header_start: self.written as u64,
            compression,
            is_zip64: use_zip64 || self.written > (u32::MAX as usize),
        };
        self.written += file.write(&mut self.inner, false).await?;
        self.files.push(file);
        self.intermediate_digest = Some(CRC32.digest());
        match compression {
            CompressionMode::Store => self.intermediate_compressor = None,
            CompressionMode::Deflate(level) => {
                let mut compressor = CompressorOxide::default();
                compressor.set_format_and_level(DataFormat::Raw, level);
                self.intermediate_compressor = Some(compressor);
            }
        }
        self.intermediate_uncompressed_size = 0;
        self.intermediate_compressed_size = 0;

        Ok(())
    }

    pub async fn append_data(&mut self, content: &[u8]) -> Result<()> {
        match self.intermediate_compressor {
            Some(_) => self.append_data_deflate(content).await,
            None => self.append_data_store(content).await,
        }
    }

    pub async fn finish_file(&mut self) -> Result<()> {
        if self.intermediate_compressor.is_some() {
            self.finish_data_deflate().await?;
            self.intermediate_compressor = None;
        }
        let digest = self
            .intermediate_digest
            .take()
            .ok_or(Error::new(ErrorKind::InvalidData, "missing digest"))?;
        let crc = digest.finalize();
        let dd = DataDescriptor {
            crc,
            uncompressed_size: self.intermediate_uncompressed_size,
            compressed_size: self.intermediate_compressed_size,
        };
        let file = self
            .files
            .last_mut()
            .ok_or(Error::new(ErrorKind::InvalidData, "missing file header"))?;
        self.written += dd
            .write(&mut self.inner, true, file.is_zip64, false)
            .await?;
        file.data_descriptor = Some(dd);

        Ok(())
    }

    async fn append_data_deflate(&mut self, content: &[u8]) -> Result<()> {
        let compressor = self.intermediate_compressor.as_mut().unwrap();
        let digest = self
            .intermediate_digest
            .as_mut()
            .ok_or(Error::new(ErrorKind::InvalidData, "missing digest"))?;
        digest.update(content);
        self.intermediate_uncompressed_size += content.len() as u64;

        let mut in_buf = content;
        loop {
            let res = deflate(compressor, in_buf, &mut self.compressed_buf, MZFlush::None);
            match res.status {
                Ok(MZStatus::Ok) => (),
                Ok(status) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("deflate unexpected status: {:?}", status),
                    ))
                }
                Err(status) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("deflate error: {:?}", status),
                    ))
                }
            }

            self.intermediate_compressed_size += res.bytes_written as u64;
            self.inner
                .write_all(&self.compressed_buf[..res.bytes_written])
                .await?;
            self.written += res.bytes_written;
            in_buf = &in_buf[res.bytes_consumed..];
            if in_buf.is_empty() {
                break;
            }
        }

        Ok(())
    }

    async fn finish_data_deflate(&mut self) -> Result<()> {
        loop {
            let compressor = self.intermediate_compressor.as_mut().unwrap();
            let res = deflate(compressor, &[], &mut self.compressed_buf, MZFlush::Finish);
            let status = match res.status {
                Ok(MZStatus::Ok) => MZStatus::Ok,
                Ok(MZStatus::StreamEnd) => MZStatus::StreamEnd,
                Ok(status) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("deflate unexpected status: {:?}", status),
                    ))
                }
                Err(status) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("deflate error: {:?}", status),
                    ))
                }
            };
            self.intermediate_compressed_size += res.bytes_written as u64;
            self.inner
                .write_all(&self.compressed_buf[..res.bytes_written])
                .await?;
            self.written += res.bytes_written;
            if let MZStatus::StreamEnd = status {
                break;
            }
        }

        Ok(())
    }

    async fn append_data_store(&mut self, content: &[u8]) -> Result<()> {
        let digest = self
            .intermediate_digest
            .as_mut()
            .ok_or(Error::new(ErrorKind::InvalidData, "missing digest"))?;
        digest.update(content);
        self.intermediate_uncompressed_size += content.len() as u64;
        self.intermediate_compressed_size += content.len() as u64;
        self.inner.write_all(content).await?;
        self.written += content.len();
        Ok(())
    }

    pub async fn add_file<R: AsyncRead + Unpin>(
        &mut self,
        name: Vec<u8>,
        last_modified: NaiveDateTime,
        compression: CompressionMode,
        content: &mut R,
        use_zip64: bool,
    ) -> Result<()> {
        self.start_new_file(name, last_modified, compression, use_zip64)
            .await?;
        let mut buf = [0; 4096];
        match compression {
            CompressionMode::Store => {
                while let Ok(bytes_read) = content.read(&mut buf).await {
                    if bytes_read == 0 {
                        break;
                    }
                    self.append_data_store(&buf[..bytes_read]).await?;
                }
            }
            CompressionMode::Deflate(_) => {
                while let Ok(bytes_read) = content.read(&mut buf).await {
                    if bytes_read == 0 {
                        break;
                    }
                    self.append_data_deflate(&buf[..bytes_read]).await?;
                }
            }
        }
        self.finish_file().await?;

        Ok(())
    }

    pub async fn add_file_from_path<R: AsRef<Path>, S: AsRef<Path>>(
        &mut self,
        path: R,
        src_path: S,
        compression: CompressionMode,
        use_zip64: bool,
    ) -> Result<()> {
        let mut file = File::open(src_path).await?;
        let modified = DateTime::<Utc>::from(file.metadata().await?.modified()?).naive_local();
        self.add_file(
            path.as_ref().to_path_buf().into_os_string().into_vec(),
            modified,
            compression,
            &mut file,
            use_zip64,
        )
        .await?;
        Ok(())
    }

    pub async fn add_dir_all<R: AsRef<Path>, S: AsRef<Path>>(
        &mut self,
        path: R,
        src_path: S,
        compression: CompressionMode,
        use_zip64: bool,
    ) -> Result<()> {
        let mut stack = vec![(src_path.as_ref().to_path_buf(), None)];
        while let Some((src, modified_if_file)) = stack.pop() {
            let dest = path.as_ref().join(src.strip_prefix(&src_path).unwrap());
            match modified_if_file {
                None => {
                    for entry in std::fs::read_dir(&src)? {
                        let entry = entry?;
                        let file_type = entry.file_type()?;
                        if !file_type.is_symlink() {
                            let modified_if_file = match file_type.is_dir() {
                                true => None,
                                false => Some(
                                    DateTime::<Utc>::from(entry.metadata()?.modified()?)
                                        .naive_local(),
                                ),
                            };
                            stack.push((entry.path(), modified_if_file));
                        }
                    }
                }
                Some(modified) => {
                    self.add_file(
                        dest.into_os_string().into_vec(),
                        modified,
                        compression,
                        &mut File::open(src).await?,
                        use_zip64,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<W> {
        let mut is_zip64 = self.files.len() > u16::MAX.into();
        let central_directory_start = self.written;
        for file in &self.files {
            self.written += file.write(&mut self.inner, true).await?;
            if file.is_zip64 {
                is_zip64 = true
            }
        }
        let central_directory_size = self.written - central_directory_start;

        if is_zip64 {
            self.inner.write_all(b"PK\x06\x06").await?; // Zip64 end of central directory signature
            self.inner.write_all(&44u64.to_le_bytes()).await?; // Size of EOCD64 minus 12
            self.inner.write_all(&45u16.to_le_bytes()).await?; // Version made by
            self.inner.write_all(&45u16.to_le_bytes()).await?; // Version needed to extract (minimum)
            self.inner.write_all(&0u32.to_le_bytes()).await?; // Number of this disk
            self.inner.write_all(&0u32.to_le_bytes()).await?; // Disk where central directory starts
            self.inner
                .write_all(&(self.files.len() as u64).to_le_bytes())
                .await?; // Number of central directory records on this disk
            self.inner
                .write_all(&(self.files.len() as u64).to_le_bytes())
                .await?; // Total number of central directory records
            self.inner
                .write_all(&(central_directory_size as u64).to_le_bytes())
                .await?; // Size of central directory
            self.inner
                .write_all(&(central_directory_start as u64).to_le_bytes())
                .await?; // Offset of start of central directory

            self.inner.write_all(b"PK\x06\x07").await?; // Zip64 end of central directory locator signature
            self.inner.write_all(&0u32.to_le_bytes()).await?; // Number of the disk with the start of the Zip64 end of central directory record
            self.inner
                .write_all(&(self.written as u64).to_le_bytes())
                .await?; // Relative offset of the Zip64 end of central directory record
            self.inner.write_all(&1u32.to_le_bytes()).await?; // Total number of disks

            self.inner.write_all(b"PK\x05\x06").await?; // End of central directory signature
            self.inner.write_all(&u16::MAX.to_le_bytes()).await?; // Number of this disk
            self.inner.write_all(&u16::MAX.to_le_bytes()).await?; // Disk where central directory starts
            if self.files.len() > (u16::MAX as usize) {
                self.inner.write_all(&u16::MAX.to_le_bytes()).await?; // Number of central directory records on this disk
                self.inner.write_all(&u16::MAX.to_le_bytes()).await?; // Total number of central directory records
            } else {
                self.inner
                    .write_all(&(self.files.len() as u16).to_le_bytes())
                    .await?; // Number of central directory records on this disk
                self.inner
                    .write_all(&(self.files.len() as u16).to_le_bytes())
                    .await?; // Total number of central directory records
            }
            self.inner.write_all(&u32::MAX.to_le_bytes()).await?; // Size of central directory
            self.inner.write_all(&u32::MAX.to_le_bytes()).await?; // Offset of start of central directory
            self.inner.write_all(&0u16.to_le_bytes()).await?; // Comment length
        } else {
            self.inner.write_all(b"PK\x05\x06").await?; // End of central directory signature
            self.inner.write_all(&0u16.to_le_bytes()).await?; // Number of this disk
            self.inner.write_all(&0u16.to_le_bytes()).await?; // Disk where central directory starts
            self.inner
                .write_all(&(self.files.len() as u16).to_le_bytes())
                .await?; // Number of central directory records on this disk
            self.inner
                .write_all(&(self.files.len() as u16).to_le_bytes())
                .await?; // Total number of central directory records
            self.inner
                .write_all(&(central_directory_size as u32).to_le_bytes())
                .await?; // Size of central directory
            self.inner
                .write_all(&(central_directory_start as u32).to_le_bytes())
                .await?; // Offset of start of central directory
            self.inner.write_all(&0u16.to_le_bytes()).await?; // Comment length
        }

        Ok(self.inner)
    }
}
