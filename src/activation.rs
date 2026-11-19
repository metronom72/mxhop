use std::io;
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};

pub const FIRST_FD: RawFd = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    None,
    NotForUs { pid: u32 },
    Malformed,
    Sockets(usize),
}

pub fn offer(listen_fds: Option<&str>, listen_pid: Option<&str>, me: u32) -> Offer {
    let Some(fds) = listen_fds else {
        return Offer::None;
    };
    let Ok(count) = fds.trim().parse::<usize>() else {
        return Offer::Malformed;
    };
    if count == 0 {
        return Offer::None;
    }
    if let Some(pid) = listen_pid {
        match pid.trim().parse::<u32>() {
            Ok(theirs) if theirs == me => {}
            Ok(theirs) => return Offer::NotForUs { pid: theirs },
            Err(_) => return Offer::Malformed,
        }
    }
    Offer::Sockets(count)
}

pub fn take_first() -> io::Result<TcpListener> {
    let listener = unsafe { TcpListener::from_raw_fd(FIRST_FD) };
    listener.set_nonblocking(true)?;
    unsafe { clear_cloexec(FIRST_FD) }?;
    Ok(listener)
}

unsafe fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    unsafe extern "C" {
        fn fcntl(fd: RawFd, cmd: i32, ...) -> i32;
    }
    const F_SETFD: i32 = 2;
    if unsafe { fcntl(fd, F_SETFD, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_variables_at_all_means_nothing_was_handed_over() {
        assert_eq!(offer(None, None, 7), Offer::None);
    }

    #[test]
    fn a_socket_meant_for_this_process_is_taken() {
        assert_eq!(offer(Some("1"), Some("7"), 7), Offer::Sockets(1));
        assert_eq!(offer(Some(" 2 "), Some(" 7 "), 7), Offer::Sockets(2));
    }

    #[test]
    fn a_socket_meant_for_another_process_is_left_alone() {
        assert_eq!(
            offer(Some("1"), Some("9"), 7),
            Offer::NotForUs { pid: 9 },
            "systemd sets LISTEN_PID so that a child which inherited the \
             environment does not steal its parent's socket"
        );
    }

    #[test]
    fn zero_sockets_is_the_same_as_none() {
        assert_eq!(offer(Some("0"), Some("7"), 7), Offer::None);
    }

    #[test]
    fn anything_unreadable_is_refused_rather_than_guessed_at() {
        assert_eq!(offer(Some("two"), Some("7"), 7), Offer::Malformed);
        assert_eq!(offer(Some("1"), Some("later"), 7), Offer::Malformed);
    }

    #[test]
    fn a_count_without_a_pid_is_taken() {
        assert_eq!(
            offer(Some("1"), None, 7),
            Offer::Sockets(1),
            "LISTEN_PID is systemd's; a test harness or another supervisor may \
             hand a socket over without it"
        );
    }
}
