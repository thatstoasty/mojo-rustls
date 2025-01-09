
## Start of bash preamble
if [ -z ${CONDA_BUILD+x} ]; then
    source /Users/lukas/dev/mojo-rustls/output/bld/rattler-build_mojo-rustls-ffi_1726516100/work/build_env.sh
fi
# enable debug mode for the rest of the script
set -x
## End of preamble

mkdir -p ${PREFIX}/share/mojo-rustls-ffi
git clone --depth=1 git@github.com:rustls/rustls-ffi.git
cd rustls-ffi && cargo install --library-type=cdylib --destdir=${PREFIX}/share/mojo-rustls-ffi/librustls.dylib
cd .. && rm -R rustls-ffi