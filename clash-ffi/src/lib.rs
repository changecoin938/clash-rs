use clash_lib::{Config, Options, TokioRuntime, shutdown, start_scaffold};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    path::PathBuf,
    sync::Mutex,
    thread,
};

static LAST_ERROR: Lazy<Mutex<HashMap<u32, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static LOG_PATH: Lazy<Mutex<HashMap<u32, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn set_last_error(id: u32, err: String) {
    if let Ok(mut map) = LAST_ERROR.lock() {
        map.insert(id, err);
    }
}

fn clear_last_error(id: u32) {
    if let Ok(mut map) = LAST_ERROR.lock() {
        map.remove(&id);
    }
}

fn set_log_path(id: u32, path: String) {
    if let Ok(mut map) = LOG_PATH.lock() {
        map.insert(id, path);
    }
}

fn get_log_path(id: u32) -> Option<String> {
    LOG_PATH.lock().ok().and_then(|map| map.get(&id).cloned())
}

//
//
//     /// # Safety
//     /// This function is unsafe because it dereferences raw pointers.
//     #[unsafe(no_mangle)]
//     pub unsafe extern "C" fn clash_start(
//         id: u32,
//         config: *const c_char,
//         log: *const c_char,
//         cwd: *const c_char,
//         multithread: c_int,
//     ) ->*mut c_char{
//     unsafe {
//         let config_str = CStr::from_ptr(config)
//             .to_str()
//             .unwrap_or_default()
//             .to_string();
//         let log_str = CStr::from_ptr(log).to_str().unwrap_or_default().to_string();
//         let cwd_str = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();
//
//         let rt = if multithread != 0 {
//             Some(TokioRuntime::MultiThread)
//         } else {
//             Some(TokioRuntime::SingleThread)
//         };
//
//         let options = Options {
//             config: Config::Str(config_str),
//             cwd: Some(cwd_str),
//             rt,
//             log_file: Some(log_str),
//         };
//
//         match start_scaffold(id,options) {
//             Ok(_) => CString::new("").unwrap().into_raw(),
//             Err(e) => CString::new(format!("Error: {e}")).unwrap().into_raw(),
//         }
//     }
// }
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_start(
    id: u32,
    config: *const c_char,
    // log: *const c_char,
    cwd: *const c_char,
    multithread: c_int,
) {
    unsafe {
        if config.is_null() {
            set_last_error(id, "config pointer is null".to_owned());
            return;
        }
        if cwd.is_null() {
            set_last_error(id, "cwd pointer is null".to_owned());
            return;
        }

        let config_str = CStr::from_ptr(config)
            .to_str()
            .unwrap_or_default()
            .to_string();
        // let log_str = CStr::from_ptr(log).to_str().unwrap_or_default().to_string();
        let cwd_str = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();

        let rt = if multithread != 0 {
            Some(TokioRuntime::MultiThread)
        } else {
            Some(TokioRuntime::SingleThread)
        };

        // Validate config early so config errors are surfaced (instead of failing silently
        // in the background thread).
        if let Err(e) = Config::Str(config_str.clone()).try_parse() {
            set_last_error(id, format!("config parse error: {e}"));
            return;
        }

        // Store logs in a stable location (parent of cwd), since the per-session
        // cwd directory may be deleted by the iOS app between starts.
        let log_path = PathBuf::from(&cwd_str)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&cwd_str))
            .join("clashrs.log");
        let _ = std::fs::create_dir_all(
            log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path);
        let log_path_str = log_path.to_string_lossy().into_owned();
        set_log_path(id, log_path_str.clone());

        let options = Options {
            config: Config::Str(config_str),
            cwd: Some(cwd_str),
            rt,
            log_file: Some(log_path_str),
        };

        thread::spawn(move || {
            match start_scaffold(id, options) {
                Ok(()) => clear_last_error(id),
                Err(e) => set_last_error(id, format!("start error: {e}")),
            }
        });
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn clash_shutdown( id: u32) -> c_int {
    if shutdown(id) {
        clear_last_error(id);
        1 // Success
    } else {
        0 // Failure
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_last_error(id: u32) -> *mut c_char {
    let msg = LAST_ERROR
        .lock()
        .ok()
        .and_then(|map| map.get(&id).cloned())
        .unwrap_or_default();
    CString::new(msg).unwrap_or_else(|_| CString::new("").unwrap()).into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_log_path(id: u32) -> *mut c_char {
    let msg = get_log_path(id).unwrap_or_default();
    CString::new(msg).unwrap_or_else(|_| CString::new("").unwrap()).into_raw()
}


/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unused_must_use)]
pub unsafe extern "C" fn clash_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(s);
    }
}
