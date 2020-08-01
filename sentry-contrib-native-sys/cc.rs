use crate::Backend;
use anyhow::{Context, Result};
use cc::Build;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

// These are the only targets supported by sentry atm
#[derive(Copy, Clone, PartialEq)]
enum TargetOs {
    Windows,
    Mac,
    Linux,
    Android,
}

use self::TargetOs::*;

fn srcs(b: &mut Build, root: &Path, files: &[&str]) {
    b.files(files.iter().map(|f| format!("{}/{}", root.display(), f)));
}

/// Build `sentry_native` with `cc`.
pub fn build(source: &Path, install: Option<&Path>, backend: Backend) -> Result<PathBuf> {
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    // A few sources are determined by the target architecture, so we just grab it once
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;

    let target_os = match target_os.as_ref() {
        "windows" => Windows,
        "macos" => Mac,
        "linux" => Linux,
        "android" | "androideabi" => Android,
        other => anyhow::bail!("unsupported TARGET_OS '{}'", other),
    };

    build_sentry(source, backend, target_os, &target_arch)?;

    // Sentry only allows a single backend at a time, so compile the chosen one
    match backend {
        Backend::Crashpad => build_crashpad(source, target_os, &target_arch),
        Backend::Breakpad => build_breakpad(source, target_os),
        _ => Ok(()),
    }?;

    unimplemented!()
}

fn build_sentry(
    source: &Path,
    backend: Backend,
    target_os: TargetOs,
    target_arch: &str,
) -> Result<()> {
    let mut build = Build::new();

    let sentry_src_root = source.join("src");
    // Core source files
    srcs(
        &mut build,
        &sentry_src_root,
        &[
            "sentry_alloc.c",
            "sentry_backend.c",
            "sentry_core.c",
            "sentry_database.c",
            "sentry_envelope.c",
            "sentry_json.c",
            "sentry_logger.c",
            "sentry_options.c",
            "sentry_random.c",
            "sentry_ratelimiter.c",
            "sentry_scope.c",
            "sentry_session.c",
            "sentry_slice.c",
            "sentry_string.c",
            "sentry_sync.c",
            "sentry_transport.c",
            "sentry_utils.c",
            "sentry_uuid.c",
            "sentry_value.c",
            "path/sentry_path.c",
            "transports/sentry_disk_transport.c",
            "transports/sentry_function_transport.c",
            "unwinder/sentry_unwinder.c",
        ],
    );

    build.file(sentry_src_root.join(format!(
        "backends/sentry_backend_{}",
        match backend {
            Backend::Crashpad => "crashpad.cpp",
            Backend::Breakpad => "breakpad.cpp",
            Backend::InProc => "inproc.c",
            Backend::None => "none.c",
        }
    )));

    match target_os {
        Windows => {
            srcs(
                &mut build,
                &sentry_src_root,
                &[
                    "modulefinder/sentry_modulefinder_windows.c",
                    "unwinder/sentry_unwinder_dbghelp.c",
                    "path/sentry_path_windows.c",
                ],
            );

            if cfg!(feature = "transport-default") {
                build.file(sentry_src_root.join("transports/sentry_transport_winhttp.c"));
            }
        }
        not_windows => {
            build.file(sentry_src_root.join("path/sentry_path_unix.c"));

            // Android is the outlier among non-windows platforms
            if not_windows == Android {
                build_libunwindstack(source, target_arch);

                build.file(sentry_src_root.join("unwinder/sentry_unwinder_libunwindstack.cpp"));

                if cfg!(feature = "transport-default") {
                    build.file(sentry_src_root.join("transports/sentry_transport_none.c"));
                }
            } else {
                build.file(sentry_src_root.join("unwinder/sentry_unwinder_libbacktrace.c"));

                if cfg!(feature = "transport-default") {
                    build.file(sentry_src_root.join("transports/sentry_transport_curl.c"));
                }
            }

            build.file(sentry_src_root.join(if not_windows == Mac {
                "modulefinder/sentry_modulefinder_apple.c"
            } else {
                "modulefinder/sentry_modulefinder_linux.c"
            }));
        }
    }

    // MSVC uses different symbolication than all other targets
    if let Some("msvc") = env::var("CARGO_CFG_TARGET_ENV").ok().as_deref() {
        srcs(
            &mut build,
            &sentry_src_root,
            &[
                "sentry_windows_dbghelp.c",
                "symbolizer/sentry_symbolizer_windows.c",
            ],
        );
    } else {
        srcs(
            &mut build,
            &sentry_src_root,
            &[
                "sentry_unix_pageallocator.c",
                "symbolizer/sentry_symbolizer_unix.c",
            ],
        );
    }

    Ok(())
}

fn build_libunwindstack(source: &Path, target_arch: &str) -> Result<()> {
    let src_root = source.join("external/libunwindstack-ndk");

    let mut build = Build::new();

    srcs(
        &mut build,
        &src_root,
        &[
            "ArmExidx.cpp",
            "DwarfCfa.cpp",
            "DwarfDebugFrame.cpp",
            "DwarfEhFrame.cpp",
            "DwarfMemory.cpp",
            "DwarfOp.cpp",
            "DwarfSection.cpp",
            "Elf.cpp",
            "ElfInterface.cpp",
            "Log.cpp",
            "MapInfo.cpp",
            "Maps.cpp",
            "Memory.cpp",
            "Regs.cpp",
            "Symbols.cpp",
            "ElfInterfaceArm.cpp",
            "android-base/stringprintf.cpp",
            "RegsArm.cpp",
            "RegsArm64.cpp",
            "RegsX86.cpp",
            "RegsX86_64.cpp",
            "DwarfEhFrameWithHdr.cpp",
        ],
    );

    // libunwind has an x86 and x86_64 assembly if not targetting arm*
    match target_arch {
        "x86_64" => {
            build.file(src_root.join("AsmGetRegsX86_64.S"));
        }
        "x86" => {
            build.file(src_root.join("AsmGetRegsX86.S"));
        }
        _ => {}
    }

    build
        .flag("-std=c++11")
        .cpp(true)
        .try_compile("unwindstack")
        .context("failed to compile libunwindstack for android")
}

fn build_crashpad(source: &Path, target_os: TargetOs, target_arch: &str) -> Result<()> {
    let mut build = Build::new();
    build.cpp(true);

    // if build.get_compiler().is_like_msvc() {
    //     build.flag("/std:c++14");
    // } else {
    //     build.flag("-std=c++14");
    // }

    build
        .define("CRASHPAD_ZLIB_SOURCE_EMBEDDED", "1")
        .define("_M_X64", "1")
        .include(source.join("external/crashpad"));

    if target_os == Windows {
        // Common defines shared by all crashpad code so that we don't get
        // warning spam and all the code "works"
        build
            .define("NOMINMAX", "1")
            .define("UNICODE", "1")
            .define("WIN32_LEAN_AND_MEAN", "1")
            .define("_CRT_SECURE_NO_WARNINGS", "1")
            .define("_HAS_EXCEPTIONS", "0")
            .define("_UNICODE", "1");
    }

    // When building crashpad, we actually generate several artifacts, several
    // libraries we statically link, as well as the crashpad_handler executable
    // which is spawned to monitor the process at runtime

    // compat
    // when targetting mac, there are actually no source files compiled, only
    // headers, so we just ignore it
    if target_os != Mac {
        let mut build = build.clone();
        let cs = source.join("external/crashpad/compat");

        match target_os {
            Windows => {
                let win = cs.join("win");
                build.include(&win);
                srcs(&mut build, &win, &["strings.cc", "time.cc"]);
            }
            Linux => {
                build.file(cs.join("linux/sys/mman.cc"));
            }
            Android => {
                build.file(cs.join("linux/sys/mman.cc"));

                srcs(
                    &mut build,
                    &cs.join("android"),
                    &[
                        "android/api-level.cc",
                        "dlfcn_internal.cc",
                        "sys/epoll.cc",
                        "sys/mman.cc",
                    ],
                );
            }
            _ => unreachable!(),
        }

        build.compile("crashpad_compat");
    }

    // zlib
    // crashpad cmake also supports using the system zlib, but the source
    // is already local and it's just cleaner
    {
        let mut build = Build::new();
        let zs = source.join("external/crashpad/third_party/zlib");

        srcs(
            &mut build,
            &zs,
            &[
                "zlib/adler32.c",
                "zlib/compress.c",
                "zlib/crc32.c",
                "zlib/deflate.c",
                "zlib/gzclose.c",
                "zlib/gzlib.c",
                "zlib/gzread.c",
                "zlib/gzwrite.c",
                "zlib/infback.c",
                "zlib/inffast.c",
                "zlib/inflate.c",
                "zlib/inftrees.c",
                "zlib/trees.c",
                "zlib/uncompr.c",
                "zlib/zutil.c",
            ],
        );

        if target_arch == "x86" || target_arch == "x86_64" {
            // These sources require SSE instructions
            build.flag("-msse4.2").flag("-mpclmul");

            srcs(
                &mut build,
                &zs,
                &["zlib/crc_folding.c", "zlib/fill_window_sse.c"],
            );
        }

        if build.get_compiler().is_like_msvc() {
            build
                .flag("/wd4131")
                .flag("/wd4244")
                .flag("/wd4245")
                .flag("/wd4267")
                .flag("/wd4324")
                .flag("/wd4702");
        }

        build
            .define("CRASHPAD_ZLIB_SOURCE_EMBEDDED", "1")
            .define("_CRT_SECURE_NO_WARNINGS", "1")
            .define("_CRT_NONSTDC_NO_WARNINGS", "1")
            .define("ZLIB_CONST", "1")
            .define("HAVE_STDARG_H", "1");
        build.compile("crashpad_zlib");
    }

    // util
    {
        let mut build = build.clone();
        let us = source.join("external/crashpad/util");

        srcs(
            &mut build,
            &us,
            &[
                "file/delimited_file_reader.cc",
                "file/file_io.cc",
                "file/file_reader.cc",
                "file/file_seeker.cc",
                "file/file_writer.cc",
                "file/output_stream_file_writer.cc",
                "file/scoped_remove_file.cc",
                "file/string_file.cc",
                "misc/initialization_state_dcheck.cc",
                "misc/lexing.cc",
                "misc/metrics.cc",
                "misc/pdb_structures.cc",
                "misc/random_string.cc",
                "misc/range_set.cc",
                "misc/reinterpret_bytes.cc",
                "misc/scoped_forbid_return.cc",
                "misc/time.cc",
                "misc/uuid.cc",
                "misc/zlib.cc",
                "net/http_body.cc",
                "net/http_body_gzip.cc",
                "net/http_multipart_builder.cc",
                "net/http_transport.cc",
                "net/url.cc",
                "numeric/checked_address_range.cc",
                "process/process_memory.cc",
                "process/process_memory_range.cc",
                "stdlib/aligned_allocator.cc",
                "stdlib/string_number_conversion.cc",
                "stdlib/strlcpy.cc",
                "stdlib/strnlen.cc",
                "stream/base94_output_stream.cc",
                "stream/file_encoder.cc",
                "stream/file_output_stream.cc",
                "stream/log_output_stream.cc",
                "stream/zlib_output_stream.cc",
                "string/split_string.cc",
                "thread/thread.cc",
                "thread/thread_log_messages.cc",
                "thread/worker_thread.cc",
            ],
        );

        match target_os {
            Windows => {
                srcs(
                    &mut build,
                    &us,
                    &[
                        "file/directory_reader_win.cc",
                        "file/file_io_win.cc",
                        "file/filesystem_win.cc",
                        "misc/clock_win.cc",
                        "misc/paths_win.cc",
                        "misc/time_win.cc",
                        "net/http_transport_win.cc",
                        "process/process_memory_win.cc",
                        "synchronization/semaphore_win.cc",
                        "thread/thread_win.cc",
                        "win/command_line.cc",
                        "win/critical_section_with_debug_info.cc",
                        "win/exception_handler_server.cc",
                        "win/get_function.cc",
                        "win/get_module_information.cc",
                        "win/handle.cc",
                        "win/initial_client_data.cc",
                        "win/loader_lock.cc",
                        "win/module_version.cc",
                        "win/nt_internals.cc",
                        "win/ntstatus_logging.cc",
                        "win/process_info.cc",
                        "win/registration_protocol_win.cc",
                        "win/scoped_handle.cc",
                        "win/scoped_local_alloc.cc",
                        "win/scoped_process_suspend.cc",
                        "win/scoped_set_event.cc",
                        "win/session_end_watcher.cc",
                        "misc/capture_context_win.asm",
                        "win/safe_terminate_process.asm",
                    ],
                );
            }
            not_windows => {
                srcs(
                    &mut build,
                    &us,
                    &[
                        "file/directory_reader_posix.cc",
                        "file/file_io_posix.cc",
                        "file/filesystem_posix.cc",
                        "misc/clock_posix.cc",
                        "posix/close_stdio.cc",
                        "posix/scoped_dir.cc",
                        "posix/scoped_mmap.cc",
                        "posix/signals.cc",
                        "synchronization/semaphore_posix.cc",
                        "thread/thread_posix.cc",
                        "posix/close_multiple.cc",
                        "posix/double_fork_and_exec.cc",
                        "posix/drop_privileges.cc",
                        "posix/symbolic_constants_posix.cc",
                    ],
                );

                if not_windows == Mac {
                    srcs(
                        &mut build,
                        &us,
                        &[
                            "mac/launchd.mm",
                            "mac/mac_util.cc",
                            "mac/service_management.cc",
                            "mac/xattr.cc",
                            "mach/child_port_handshake.cc",
                            "mach/child_port_server.cc",
                            "mach/composite_mach_message_server.cc",
                            "mach/exc_client_variants.cc",
                            "mach/exc_server_variants.cc",
                            "mach/exception_behaviors.cc",
                            "mach/exception_ports.cc",
                            "mach/exception_types.cc",
                            "mach/mach_extensions.cc",
                            "mach/mach_message.cc",
                            "mach/mach_message_server.cc",
                            "mach/notify_server.cc",
                            "mach/scoped_task_suspend.cc",
                            "mach/symbolic_constants_mach.cc",
                            "mach/task_for_pid.cc",
                            "misc/capture_context_mac.S",
                            "misc/clock_mac.cc",
                            "misc/paths_mac.cc",
                            "net/http_transport_mac.mm",
                            "posix/process_info_mac.cc",
                            "process/process_memory_mac.cc",
                            "synchronization/semaphore_mac.cc",
                        ],
                    );
                } else {
                    srcs(
                        &mut build,
                        &us,
                        &[
                            "net/http_transport_socket.cc",
                            "linux/auxiliary_vector.cc",
                            "linux/direct_ptrace_connection.cc",
                            "linux/exception_handler_client.cc",
                            "linux/exception_handler_protocol.cc",
                            "linux/memory_map.cc",
                            "linux/proc_stat_reader.cc",
                            "linux/proc_task_reader.cc",
                            "linux/ptrace_broker.cc",
                            "linux/ptrace_client.cc",
                            "linux/ptracer.cc",
                            "linux/scoped_pr_set_dumpable.cc",
                            "linux/scoped_pr_set_ptracer.cc",
                            "linux/scoped_ptrace_attach.cc",
                            "linux/socket.cc",
                            "linux/thread_info.cc",
                            "misc/capture_context_linux.S",
                            "misc/paths_linux.cc",
                            "posix/process_info_linux.cc",
                            "process/process_memory_linux.cc",
                            "process/process_memory_sanitized.cc",
                        ],
                    );

                    if not_windows == Android {
                        build.file(us.join("linux/initial_signal_dispositions.cc"));
                    }
                }
            }
        }

        match target_os {
            Windows => {
                build.include(source.join("external/crashpad/compat/win"));
            }
            _ => unimplemented!(),
        }

        build.include(source.join("external/crashpad/third_party/mini_chromium/mini_chromium"));
        build.compile("crashpad_util");
    }

    // minidump
    {
        let mut build = build.clone();
        let md = source.join("external/crashpad/minidump");

        srcs(
            &mut build,
            &md,
            &[
                "minidump_annotation_writer.cc",
                "minidump_byte_array_writer.cc",
                "minidump_context_writer.cc",
                "minidump_crashpad_info_writer.cc",
                "minidump_exception_writer.cc",
                "minidump_extensions.cc",
                "minidump_file_writer.cc",
                "minidump_handle_writer.cc",
                "minidump_memory_info_writer.cc",
                "minidump_memory_writer.cc",
                "minidump_misc_info_writer.cc",
                "minidump_module_crashpad_info_writer.cc",
                "minidump_module_writer.cc",
                "minidump_rva_list_writer.cc",
                "minidump_simple_string_dictionary_writer.cc",
                "minidump_stream_writer.cc",
                "minidump_string_writer.cc",
                "minidump_system_info_writer.cc",
                "minidump_thread_id_map.cc",
                "minidump_thread_writer.cc",
                "minidump_unloaded_module_writer.cc",
                "minidump_user_extension_stream_data_source.cc",
                "minidump_user_stream_writer.cc",
                "minidump_writable.cc",
                "minidump_writer_util.cc",
            ],
        );

        match target_os {
            Windows => {
                build.include(source.join("external/crashpad/compat/win"));
            }
            _ => unimplemented!(),
        }

        build.include(source.join("external/crashpad/third_party/mini_chromium/mini_chromium"));
        build.compile("crashpad_minidump");
    }

    // mini_chromium
    {
        let mut build = build.clone();
        let mc = source.join("external/crashpad/third_party/mini_chromium/mini_chromium/base");

        srcs(
            &mut build,
            &mc,
            &[
                "debug/alias.cc",
                "files/file_path.cc",
                "files/scoped_file.cc",
                "logging.cc",
                "process/memory.cc",
                "rand_util.cc",
                "strings/string16.cc",
                "strings/string_number_conversions.cc",
                "strings/stringprintf.cc",
                "strings/utf_string_conversions.cc",
                "strings/utf_string_conversion_utils.cc",
                "synchronization/lock.cc",
                "third_party/icu/icu_utf.cc",
                "threading/thread_local_storage.cc",
            ],
        );

        if target_os == Windows {
            srcs(
                &mut build,
                &mc,
                &[
                    "process/process_metrics_win.cc",
                    "scoped_clear_last_error_win.cc",
                    "strings/string_util_win.cc",
                    "synchronization/lock_impl_win.cc",
                    "threading/thread_local_storage_win.cc",
                ],
            );
        } else {
            srcs(
                &mut build,
                &mc,
                &[
                    "files/file_util_posix.cc",
                    "posix/safe_strerror.cc",
                    "process/process_metrics_posix.cc",
                    "synchronization/condition_variable_posix.cc",
                    "synchronization/lock_impl_posix.cc",
                    "threading/thread_local_storage_posix.cc",
                ],
            );

            if target_os == Mac {
                srcs(
                    &mut build,
                    &mc,
                    &[
                        "mac/close_nocancel.cc",
                        "mac/foundation_util.mm",
                        "mac/mach_logging.cc",
                        "mac/scoped_mach_port.cc",
                        "mac/scoped_mach_vm.cc",
                        "mac/scoped_nsautorelease_pool.mm",
                        "strings/sys_string_conversions_mac.mm",
                    ],
                );
            }
        }

        build.include(source.join("external/crashpad/third_party/mini_chromium/mini_chromium"));
        build.compile("mini_chromium");
    }

    // client
    {
        let mut build = build.clone();
        let c = source.join("external/crashpad/client");

        srcs(
            &mut build,
            &c,
            &[
                "annotation.cc",
                "annotation_list.cc",
                "crash_report_database.cc",
                "crashpad_info.cc",
                "prune_crash_reports.cc",
                "settings.cc",
            ],
        );

        let target_srcs: &[&str] = match target_os {
            Windows => &["crash_report_database_win.cc", "crashpad_client_win.cc"],
            Mac => &[
                "crash_report_database_mac.mm",
                "crashpad_client_mac.cc",
                "simulate_crash_mac.cc",
            ],
            Android | Linux => &[
                "crashpad_client_linux.cc",
                "client_argv_handling.cc",
                "crashpad_info_note.S",
                "crash_report_database_generic.cc",
            ],
        };

        srcs(&mut build, &c, target_srcs);
    }

    unimplemented!()
}

fn build_breakpad(source: &Path, target_os: TargetOs) -> Result<()> {
    unimplemented!()
}
