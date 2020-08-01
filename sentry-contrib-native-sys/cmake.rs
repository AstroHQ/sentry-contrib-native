use crate::Backend;
use anyhow::{Context, Result};
use cmake::Config;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

/// Build `sentry_native` with `CMake`.
pub fn build(source: &Path, install: Option<&Path>, backend: Backend) -> Result<PathBuf> {
    let mut cmake_config = Config::new(source);
    cmake_config
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("SENTRY_BUILD_TESTS", "OFF")
        .define("SENTRY_BUILD_EXAMPLES", "OFF")
        .generator("Ninja")
        .profile("RelWithDebInfo");

    if let Some(install) = install {
        fs::create_dir_all(install).expect("failed to create install directory");
        cmake_config.out_dir(install);
    }

    if cfg!(not(feature = "transport-default")) {
        cmake_config.define("SENTRY_TRANSPORT", "none");
    }

    cmake_config.define("SENTRY_BACKEND", backend.as_ref());

    if cfg!(target_feature = "crt-static") {
        cmake_config.define("SENTRY_BUILD_RUNTIMESTATIC", "ON");
    }

    // If we're targetting android, we need to set the CMAKE_TOOLCHAIN_FILE
    // which properly sets up the build environment, and we also need to set
    // ANDROID_ABI based on our target-triple. It seems there is not really
    // a good standard for the NDK, so we try several environment variables to
    // find it
    // See https://developer.android.com/ndk/guides/cmake for details
    let target_os = env::var("CARGO_CFG_TARGET_OS").context("TARGET_OS not set")?;

    match target_os.as_ref() {
        "android" | "androideabi" => {
            let ndk_root = env::var("ANDROID_NDK_ROOT")
                .or_else(|_| env::var("ANDROID_NDK_HOME"))
                .context("unable to find ANDROID_NDK_ROOT nor ANDROID_NDK_HOME")?;

            let mut toolchain = PathBuf::from(ndk_root);
            toolchain.push("build/cmake/android.toolchain.cmake");

            if !toolchain.exists() {
                anyhow::bail!(
                    "Unable to find cmake toolchain file {}",
                    toolchain.display()
                );
            }

            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").context("TARGET_ARCH not set")?;
            let abi = match target_arch.as_ref() {
                "aarch64" => "arm64-v8a",
                "arm" | "armv7" => "armeabi-v7a",
                "thumbv7neon" => "armeabi-v7a with NEON",
                "x86_64" => "x86_64",
                "i686" => "x86",
                arch => anyhow::bail!("Unknown Android TARGET_ARCH: {}", arch),
            };

            cmake_config
                .define("CMAKE_TOOLCHAIN_FILE", toolchain)
                .define("ANDROID_ABI", abi);
        }
        "windows" => {
            // Several CMake files use these defines, which aren't set correctly
            // in cross compilation scenarios for whatever reason
            cmake_config.define("WIN32", "True");

            if env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
                cmake_config.define("MSVC", "True");
            }
        }
        _ => {}
    }

    Ok(cmake_config.build())
}
