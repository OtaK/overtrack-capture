use log::{error, info};
use sysinfo::{SystemExt as _, ProcessExt as _};

const OVERTRACK_SHMEM_NAME: &str = "overtrack\0";

#[derive(Debug)]
#[repr(C)]
struct OvertrackScreenshotHeader {
    width: u32,
    height: u32,
    linesize: u32,
    index: u32,
}

impl OvertrackScreenshotHeader {
    pub fn as_slice(&self) -> &[u8] {
        &[
            self.width.to_ne_bytes(),
            self.height.to_ne_bytes(),
            self.linesize.to_ne_bytes(),
            self.index.to_ne_bytes(),
        ].concat()
    }
}

#[derive(Debug)]
pub struct OvertrackScreenshot<'a> {
    header: &'a OvertrackScreenshotHeader,
    data: &'a mut [u8]
}

impl std::ops::Deref for OvertrackScreenshot<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for OvertrackScreenshot<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl OvertrackScreenshot<'_> {
    pub fn as_slice(&self) -> &[u8] {
        &[self.header.as_slice(), self.data].concat()
    }
}

fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    let overtrack_numa_node = get_overtrack_numa_node()?;

    use std::os::windows::ffi::OsStrExt as _;
    let mut shmem_name = std::ffi::OsStr::new(OVERTRACK_SHMEM_NAME).encode_wide().collect::<Vec<u16>>();

    let display = scrap::Display::primary()?;
    let shmem_size = display.width() * display.height();
    let overtrack_ss_header = OvertrackScreenshotHeader {
        height: display.height() as _,
        width: display.width() as _,
        linesize: display.width() as _,
        index: 0,
    };

    let shmem_hwnd: winapi::um::winnt::HANDLE = unsafe { winapi::um::memoryapi::CreateFileMappingNumaW(
        winapi::um::handleapi::INVALID_HANDLE_VALUE,
        0 as _,
        winapi::um::winnt::PAGE_READWRITE,
        0,
        shmem_size as _,
        shmem_name.as_mut_ptr(),
        overtrack_numa_node as _
    ) };

    if shmem_hwnd == winapi::shared::ntdef::NULL {
        return Err(std::io::Error::last_os_error());
    }

    info!("Created named memory \"{}\" as hwnd = {:?}", OVERTRACK_SHMEM_NAME, shmem_hwnd);

    let shmem_mmap = unsafe { winapi::um::winbase::MapViewOfFileExNuma(
        shmem_hwnd,
        winapi::um::memoryapi::FILE_MAP_ALL_ACCESS,
        0,
        0,
        shmem_size as _,
        winapi::shared::ntdef::NULL,
        overtrack_numa_node as _
    ) };

    if shmem_mmap == winapi::shared::ntdef::NULL {
        unsafe { winapi::um::handleapi::CloseHandle(shmem_hwnd); }
        return Err(std::io::Error::last_os_error());
    }

    info!("Opened named memory buffer at {:?}", shmem_mmap);

    // TODO: winapi::um::winnt::RtlCopyMemory
    // Scrap display buffer to shared memory, profit
    let mut capturer = scrap::Capturer::new(display)?;
    let capture_delay = std::time::Duration::from_secs(1);
    let mut screenshot_data: Vec<u8> = Vec::with_capacity(shmem_size * 4);
    let mut screenshot = OvertrackScreenshot {
        header: &overtrack_ss_header,
        data: &mut screenshot_data,
    };

    loop {
        let frame = match capturer.frame() {
            Ok(frame) => frame,
            Err(e) => {
                error!("{}", e);
                break;
            }
        };
        // let mut rgba = frame
        //     .chunks(4)
        //     .flat_map(|bgra| (bgra[2], bgra[1], bgra[0], bgra[3]));
        screenshot.data.copy_from_slice(&*frame);

        info!("Captured frame: {:#?}", screenshot);

        unsafe { winapi::um::winnt::RtlCopyMemory(shmem_mmap, screenshot.as_slice().as_ptr() as _, 16 + frame.len()) };

        std::thread::sleep(capture_delay);
    }

    unsafe {
        winapi::um::memoryapi::UnmapViewOfFile(shmem_mmap);
        winapi::um::handleapi::CloseHandle(shmem_hwnd);

        info!("Freed all handles");
    }

    Ok(())
}


fn get_overtrack_numa_node() -> std::io::Result<usize> {
    let mut system = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::default().with_processes());
    system.refresh_processes();
    let mut maybe_overtrack = system.get_processes().iter().find(|(_, process)| {
        if let Some(exe_name) = process.exe().file_name().and_then(std::ffi::OsStr::to_str) {
            exe_name.contains("overtrack_client")
        } else {
            false
        }
    });
    if maybe_overtrack.is_none() {
        error!("Overtrack Client not running, exiting...");
        return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    }
    let (overtrack_pid, overtrack_process) = maybe_overtrack.take().unwrap();
    info!("Found overtrack at: [{}] -> {}", overtrack_pid, overtrack_process.exe().display());
    let overtrack_hwnd = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_QUERY_INFORMATION,
            0,
            *overtrack_pid as _
        )
    };

    if overtrack_hwnd == winapi::shared::ntdef::NULL {
        return Err(std::io::Error::last_os_error());
    }

    info!("Opened overtrack hwnd: {:?}", overtrack_hwnd);
    let mut ws_info: winapi::um::psapi::PSAPI_WORKING_SET_EX_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe { winapi::um::psapi::QueryWorkingSetEx(overtrack_hwnd, &mut ws_info as *mut _ as _, std::mem::size_of::<winapi::um::psapi::PSAPI_WORKING_SET_EX_INFORMATION>() as _) };
    if result != winapi::shared::minwindef::TRUE {
        let err = std::io::Error::last_os_error();
        error!("QueryWorkingSetEx() -> {}", std::io::Error::last_os_error());
        unsafe { winapi::um::handleapi::CloseHandle(overtrack_hwnd) };
        return Err(err);
    }

    info!("Found overtrack NUMA node: {}", ws_info.VirtualAttributes.Node());
    let overtrack_numa_node = ws_info.VirtualAttributes.Node();
    unsafe { winapi::um::handleapi::CloseHandle(overtrack_hwnd) };
    Ok(overtrack_numa_node)
}
