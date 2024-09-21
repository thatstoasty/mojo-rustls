
## Start of bash preamble
if [ -z ${CONDA_BUILD+x} ]; then
    source /Users/lukas/dev/mojo-rustls/output/bld/rattler-build_mojo-rustls_1726682138/work/build_env.sh
fi
# enable debug mode for the rest of the script
set -x
## End of preamble

mkdir -p ${PREFIX}/share/mojo-rustls
git clone --depth=1 git@github.com:rustls/rustls-ffi.git
cd rustls-ffi && cargo cinstall --library-type=cdylib --destdir=./output
ls -la output/usr/local/lib
cp output/usr/local/lib/librustls.dylib ${PREFIX}/share/mojo-rustls/librustls.dylib
cd .. && rm -R rustls-ffi