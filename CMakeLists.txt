project(CommonCrypto)

add_compile_options(
	-nostdinc
	-Wno-unused-command-line-argument
	-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports.exp-in
)

add_definitions(
	-DNDEBUG
	-DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/libcn
	${CMAKE_CURRENT_SOURCE_DIR}/lib
)


set(DYLIB_CURRENT_VERSION "60092.50.5")
set(DYLIB_COMPATIBILITY_VERSION "1.0.0")

set(DYLIB_INSTALL_NAME "/usr/lib/system/libcommonCrypto.dylib")
add_circular(commonCrypto FAT
	SOURCES

	libcn/adler32.c
	libcn/crc16-a.c
	libcn/crc16-b.c
	libcn/crc16-ccitt-false.c
	libcn/crc16-ccitt-true.c
	libcn/crc16-dect-r.c
	libcn/crc16-dect-x.c
	libcn/crc16-icode.c
	libcn/crc16-usb.c
	libcn/crc16-verifone.c
	libcn/crc16-xmodem.c
	libcn/crc16.c
	libcn/crc32-bzip2.c
	lib/ccGlobals.c
	lib/ccDispatch.c
	libcn/crc32-castagnoli.c
	libcn/crc32-mpeg-2.c
	libcn/crc32-posix.c
	libcn/crc32-xfer.c
	libcn/crc32.c
	libcn/crc64-ecma-182.c
	lib/CommonKeyDerivationSPI.c
	libcn/crc8-icode.c
	libcn/crc8-itu.c
	libcn/crc8-rohc.c
	libcn/crc8-wcdma.c
	libcn/crc8.c
	libcn/gen_std_crc_table.c
	libcn/normal_crc.c
	libcn/reflect.c
	libcn/reverse_crc.c
	libcn/reverse_poly.c
	lib/CommonBigNum.c
	lib/CommonCMAC.c
	lib/CommonCryptor.c
	lib/CommonDH.c
	lib/CommonDigest.c
	lib/CommonECCryptor.c
	lib/CommonCryptorGCM.c
	lib/CommonHMAC.c
	lib/CommonKeyDerivation.c
	lib/CommonRandom.c
	lib/CommonRSACryptor.c
	lib/CommonSymmetricKeywrap.c
	lib/corecryptoSymmetricBridge.c
	lib/CommonCryptorRC4.c
	lib/CommonCryptorDES.c
	libcn/CommonCRC.c
	libcn/CommonBaseXX.c
	libcn/CommonBuffering.c
	lib/CommonCollabKeyGen.c

	SIBLINGS
		system_dyld
		compiler_rt
		system_kernel
		platform
		system_malloc
		system_c
		system_blocks
		system_pthread
		macho
		libdispatch_shared
		corecrypto
		system_trace
)
make_fat(commonCrypto)

target_link_options(commonCrypto PRIVATE
	-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports.exp-in
)

install(TARGETS commonCrypto DESTINATION libexec/darling/usr/lib/system)
