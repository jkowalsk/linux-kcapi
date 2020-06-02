//! This module is mainly intended for internal usage, as it provides function without particular input checking.
//! It is exposed for being able to use any algorithm which may not be exposed by a convenient API from this crate.
//!
use crate::err::Error;
use libc::c_int;
use nix::sys::socket;
use nix::sys::socket::SetSockOpt;
use nix::unistd;
use std::os::unix::io::RawFd;

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn logical_cpus() -> usize {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } == 0
    {
        let mut count: u32 = 0;
        for i in 0..libc::CPU_SETSIZE as usize {
            if unsafe { libc::CPU_ISSET(i, &set) } {
                count += 1
            }
        }
        count as usize
    } else {
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if cpus < 1 {
            1
        } else {
            cpus as usize
        }
    }
}

lazy_static::lazy_static! {
  static ref PARALLEL_JOBS: usize =  logical_cpus();
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn get_page_size() -> usize {
    let sysconf_val = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sysconf_val == -1 {
        // return default value
        4096
    } else {
        sysconf_val as usize
    }
}

lazy_static::lazy_static! {
  static ref PAGE_SIZE: usize =  get_page_size();
}

#[derive(Debug, Clone)]
/// Encryption direction
pub enum Direction {
    /// Perform encryption
    Encrypt,
    /// Perform decryption
    Decrypt,
}

impl Into<c_int> for Direction {
    fn into(self) -> c_int {
        match self {
            Direction::Encrypt => 1,
            Direction::Decrypt => 0,
        }
    }
}

/// Entry struct to linux kernel crypto api
pub struct KcApi {
    fd: RawFd,
    opfd: RawFd,
}

impl KcApi {
    /// New from algorithm name and type.
    /// # Errors
    /// Same as returned by socket() or bind() system calls
    pub fn new(alg_type: &str, alg_name: &str) -> Result<Self, Error> {
        let adr = socket::SockAddr::Alg(socket::AlgAddr::new(alg_type, alg_name));
        let fd = socket::socket(
            socket::AddressFamily::Alg,
            socket::SockType::SeqPacket,
            socket::SockFlag::empty(),
            None,
        )
        .map_err(|e| {
            log::debug!(
                "Socket opening failed for type {} and name {}",
                alg_type,
                alg_name
            );
            e
        })?;
        socket::bind(fd, &adr).map_err(|e| {
            log::debug!(
                "Socket bind failed for type {} and name {}",
                alg_type,
                alg_name
            );
            e
        })?;
        Ok(Self { fd, opfd: -1 })
    }

    /// Set Cipher key.
    /// See [KCAPI setsockopt](https://www.kernel.org/doc/html/v4.10/crypto/userspace-if.html#setsockopt-interface)
    /// # Errors
    /// Same as setsockopt() system call
    pub fn set_key<T>(&self, key: &T) -> Result<(), Error>
    where
        T: AsRef<[u8]> + Clone,
    {
        let opt = socket::sockopt::AlgSetKey::<T>::default();
        opt.set(self.fd, key)?;
        Ok(())
    }

    /// Set authentication tag size for AEAD ciphers.
    /// See [KCAPI setsockopt](https://www.kernel.org/doc/html/v4.10/crypto/userspace-if.html#setsockopt-interface)
    /// # Errors
    /// Same as setsockopt() system call
    pub fn set_aead_auth_size(&self, size: usize) -> Result<(), Error> {
        socket::sockopt::AlgSetAeadAuthSize.set(self.fd, &size)?;
        Ok(())
    }

    /// Accept connexion to get operation socket
    /// Eventually close current connexion
    /// # Errors
    /// Same as close() or accept() system call
    pub fn init(&mut self) -> Result<(), Error> {
        if nix::fcntl::fcntl(self.opfd, nix::fcntl::FcntlArg::F_GETFD).is_ok() {
            unistd::close(self.opfd)?;
        }

        self.opfd = socket::accept(self.fd)?;
        Ok(())
    }

    /// Close current connexion
    /// # Errors
    /// Same as close() system call
    pub fn finish(&mut self) -> Result<(), Error> {
        unistd::close(self.opfd)?;
        self.opfd = -1;
        Ok(())
    }

    /// Set cipher option
    /// See [KCAPI symmetric-cipher-api](https://www.kernel.org/doc/html/v4.10/crypto/userspace-if.html#symmetric-cipher-api)
    /// and
    /// See [KCAPI aead-cipher-api](https://www.kernel.org/doc/html/v4.10/crypto/userspace-if.html#aead-cipher-api)
    /// # Errors
    /// Same as sendmsg() system call
    pub fn set_option(
        &self,
        iv: Option<&[u8]>,
        aad: Option<u32>,
        dir: Option<Direction>,
    ) -> Result<(), Error> {
        let mut message: Vec<socket::ControlMessage> = Vec::new();
        #[allow(unused_assignments)]
        let (mut aad_len, mut direction) = (0, 0);
        if let Some(d) = iv {
            message.push(socket::ControlMessage::AlgSetIv(d));
        }
        if let Some(d) = aad {
            aad_len = d;
            message.push(socket::ControlMessage::AlgSetAeadAssoclen(&aad_len));
        }
        if let Some(d) = dir {
            direction = d.into();
            message.push(socket::ControlMessage::AlgSetOp(&direction));
        }
        socket::sendmsg(
            self.opfd,
            &[],
            message.as_slice(),
            socket::MsgFlags::empty(),
            None,
        )?;
        Ok(())
    }

    /// Get processed data.
    /// # Errors
    /// Same as read() system call
    pub fn read(&self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(unistd::read(self.opfd, out)?)
    }

    /// Send data to be processed.
    /// # Errors
    /// Same as sendmsg() system call
    pub fn send_data_with_option(
        &self,
        iv: Option<&[u8]>,
        aad: Option<u32>,
        dir: Option<Direction>,
        data: &[u8],
        more_data: bool,
    ) -> Result<usize, Error> {
        let mut message: Vec<socket::ControlMessage> = Vec::new();
        #[allow(unused_assignments)]
        let (mut aad_len, mut direction) = (0, 0);
        if let Some(d) = iv {
            message.push(socket::ControlMessage::AlgSetIv(d));
        }
        if let Some(d) = aad {
            aad_len = d;
            message.push(socket::ControlMessage::AlgSetAeadAssoclen(&aad_len));
        }
        if let Some(d) = dir {
            direction = d.into();
            message.push(socket::ControlMessage::AlgSetOp(&direction));
        }
        let flags = if more_data {
            unsafe { socket::MsgFlags::from_bits_unchecked(libc::MSG_MORE) }
        } else {
            socket::MsgFlags::empty()
        };

        let r = socket::sendmsg(
            self.opfd,
            &[nix::sys::uio::IoVec::from_slice(data)],
            message.as_slice(),
            flags,
            None,
        )?;
        Ok(r)
    }

    /// Send data to be processed.
    /// # Errors
    /// Same as send() system call
    pub fn send_data(&self, data: &[u8], more_data: bool) -> Result<usize, Error> {
        let flags = if more_data {
            unsafe { socket::MsgFlags::from_bits_unchecked(libc::MSG_MORE) }
        } else {
            socket::MsgFlags::empty()
        };
        let r = socket::send(self.opfd, data, flags)?;
        Ok(r)
    }

    /// Send data to be processed.
    /// # Errors
    /// Any returned by pipe(), vmsplice() by splice() system call
    pub fn send_data_no_copy(&self, data: &[u8], more_data: bool) -> Result<usize, Error> {
        let mut osize = 0;
        let (pipe0, pipe1) = unistd::pipe()?;

        let flag = if more_data {
            nix::fcntl::SpliceFFlags::SPLICE_F_MORE
        } else {
            nix::fcntl::SpliceFFlags::empty()
        };

        // kernel processes input data with max size of one page
        let mut chunks = data.chunks(*PAGE_SIZE).peekable();
        while let Some(chunk) = chunks.next() {
            let iov = [nix::sys::uio::IoVec::from_slice(chunk)];
            let more_flag = flag
                | if chunks.peek().is_some() {
                    nix::fcntl::SpliceFFlags::SPLICE_F_MORE
                } else {
                    nix::fcntl::SpliceFFlags::empty()
                };
            let sz =
                nix::fcntl::vmsplice(pipe1, &iov, nix::fcntl::SpliceFFlags::SPLICE_F_GIFT | flag)?;

            osize += nix::fcntl::splice(pipe0, None, self.opfd, None, sz, more_flag)?;
        }
        unistd::close(pipe0)?;
        unistd::close(pipe1)?;
        Ok(osize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAX_PAGES: usize = 16;

    #[test]
    fn new() -> Result<(), Error> {
        let _ = env_logger::try_init();
        let _ = KcApi::new("rng", "stdrng")?;
        let bad = KcApi::new("badtype", "stdrng");
        assert!(bad.is_err());
        Ok(())
    }

    #[test]
    fn lazy_static_init() {
        println!("Number of CPU : {} ", *PARALLEL_JOBS);
        println!("Page size : {} ", *PAGE_SIZE);
    }

    // The kernel generates at most 128 bytes in one call.
    const MAX_TEST_READ_LEN: usize = 128;

    #[test]
    fn init_close() -> Result<(), Error> {
        let mut rng = KcApi::new("rng", "stdrng")?;

        assert!(rng.finish().is_err());
        rng.init()?;
        assert!(rng.finish().is_ok());
        Ok(())
    }

    #[test]
    fn set_key() -> Result<(), Error> {
        let mut rng = KcApi::new("rng", "stdrng")?;
        let mut dst = [0_u8; 16];
        rng.init()?;
        assert!(rng.read(&mut dst).is_err());

        rng.finish()?;
        rng.set_key(&[0_u8; 16])?;
        rng.init()?;
        assert!(rng.read(&mut dst).is_ok());

        Ok(())
    }

    #[test]
    fn read() -> Result<(), Error> {
        let mut rng = KcApi::new("rng", "stdrng")?;
        let zero = [0_u8; MAX_TEST_READ_LEN];
        // for tests, rng must be seeded
        rng.set_key(&[0_u8; 16])?;
        rng.init()?;
        for read_len in 4..=MAX_TEST_READ_LEN {
            let reference = &zero[0..read_len];
            let mut dst = Vec::from(reference);
            rng.read(dst.as_mut_slice())?;
            assert_ne!(reference, dst.as_slice());
        }
        Ok(())
    }

    #[test]
    fn set_option() -> Result<(), Error> {
        let mut cip = KcApi::new("aead", "gcm(aes)")?;
        let zero = [0_u8; 32];
        let mut dst = [0_u8; 32];

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;

        // error shall occur if no direction  is set
        cip.init()?;
        cip.send_data(&zero, false)?;
        assert!(cip.read(&mut dst).is_err());

        // if set, shall be ok
        cip.set_option(None, None, Some(Direction::Encrypt))?;
        cip.send_data(&zero, false)?;
        assert!(cip.read(&mut dst).is_ok());

        // dst shall be non zero
        assert_ne!(zero, dst);

        Ok(())
    }

    #[test]
    fn write() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let mut zero = Vec::new();

        let mut dst = Vec::new();

        let long_len = MAX_PAGES * *PAGE_SIZE * 3;

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        // iov split at block size ok
        zero.resize(long_len, 0);
        dst.resize(long_len, 0);
        cip.send_data(&zero, false)?;
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(long_len, read_res.unwrap());

        // iov not split at block size
        zero.resize(16, 0);
        dst.resize(16, 0);
        assert_eq!(16, cip.send_data(&zero, false).unwrap());
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(16, read_res.unwrap());

        Ok(())
    }

    #[test]
    fn more_data() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let mut zero = Vec::new();

        let mut dst = Vec::new();
        let mut dst_spl = Vec::new();

        let len = 256;

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        zero.resize(len, 0);
        dst.resize(len, 0);
        dst_spl.resize(len, 0);
        assert_eq!(len, cip.send_data(&zero, false)?);
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(len, read_res.unwrap());

        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;
        assert_eq!(len / 2, cip.send_data(&zero[..len / 2], true)?);
        assert_eq!(len / 2, cip.send_data(&zero[len / 2..], false)?);
        let read_res = cip.read(&mut dst_spl);
        assert!(read_res.is_ok());
        assert_eq!(len, read_res.unwrap());

        assert_eq!(dst, dst_spl);

        assert_eq!(
            len / 2,
            cip.send_data_with_option(
                Some(&[0_u8; 16]),
                None,
                Some(Direction::Encrypt),
                &zero[..len / 2],
                true
            )?
        );
        assert_eq!(len / 2, cip.send_data(&zero[len / 2..], false)?);
        let read_res = cip.read(&mut dst_spl);
        assert!(read_res.is_ok());
        assert_eq!(len, read_res.unwrap());

        assert_eq!(dst, dst_spl);

        Ok(())
    }

    #[test]
    fn more_data_zero_copy() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let mut zero = Vec::new();

        let mut dst = Vec::new();
        let mut dst_spl = Vec::new();

        let len = 256;

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        zero.resize(len, 0);
        dst.resize(len, 0);
        dst_spl.resize(len, 0);
        assert_eq!(len, cip.send_data(&zero, false)?);
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(len, read_res.unwrap());

        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;
        assert_eq!(len / 2, cip.send_data_no_copy(&zero[..len / 2], true)?);
        assert_eq!(len / 2, cip.send_data_no_copy(&zero[len / 2..], false)?);
        let read_res = cip.read(&mut dst_spl);
        assert!(read_res.is_ok());
        assert_eq!(len, read_res.unwrap());

        assert_eq!(dst, dst_spl);

        Ok(())
    }

    #[test]
    fn write_long() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let mut zero = Vec::new();

        let mut dst = Vec::new();

        let long_len = MAX_PAGES * *PAGE_SIZE * 3;

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        zero.resize(long_len, 0);
        dst.resize(long_len, 0);
        assert_eq!(long_len, cip.send_data(&zero, false)?);
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(long_len, read_res.unwrap());

        Ok(())
    }

    #[test]
    fn send_data_no_copy() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let mut zero = Vec::new();

        let mut dst = Vec::new();

        let long_len = MAX_PAGES * *PAGE_SIZE * 3;

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        zero.resize(long_len, 0);
        dst.resize(long_len, 0);
        assert_eq!(long_len, cip.send_data_no_copy(&zero, false)?);
        let read_res = cip.read(&mut dst);
        assert!(read_res.is_ok());
        assert_eq!(long_len, read_res.unwrap());

        Ok(())
    }

    const BENCH_TEST_SZ: usize = 32;
    #[repr(C)]
    pub struct Aligned([u8; BENCH_TEST_SZ]);

    fn new_aligned() -> Aligned {
        Aligned([0; BENCH_TEST_SZ])
    }

    use std::time::SystemTime;

    #[test]
    fn bench_send_data_no_copy() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let zero = new_aligned();
        let mut dst = [0; 32];

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        let mut duration = 0;

        for _ in 0..4096 {
            let now = SystemTime::now();
            cip.send_data_no_copy(&zero.0, false)?;
            cip.read(&mut dst)?;
            duration += now.elapsed().unwrap().as_micros()
        }
        println!("Elapsed {} microsec", duration);
        Ok(())
    }

    #[test]
    fn bench_write() -> Result<(), Error> {
        let mut cip = KcApi::new("skcipher", "ctr(aes)")?;
        let zero = new_aligned();
        let mut dst = [0; 32];

        // cipher must be keyed
        cip.set_key(&[0_u8; 16])?;
        cip.init()?;
        cip.set_option(Some(&[0_u8; 16]), None, Some(Direction::Encrypt))?;

        let mut duration = 0;

        for _ in 0..4096 {
            let now = SystemTime::now();
            cip.send_data(&zero.0, false)?;
            cip.read(&mut dst)?;
            duration += now.elapsed().unwrap().as_micros()
        }
        println!("Elapsed {}", duration);
        Ok(())
    }
}
