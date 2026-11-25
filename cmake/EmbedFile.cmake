# cmake -DIN=<file> -DOUT=<file.cpp> -DNS=<namespace> -DNAME=<symbol> -P EmbedFile.cmake
# Writes a C++ source defining `const char NS::NAME[]` (the bytes of IN, not
# NUL-terminated) and `const std::size_t NS::NAMESize`. A byte array, not a
# string literal, so MSVC's literal length limit does not apply.
file(READ "${IN}" _hex HEX)
string(LENGTH "${_hex}" _len)
math(EXPR _size "${_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "'\\\\x\\1'," _bytes "${_hex}")
# ~32 bytes per line
string(REGEX REPLACE "(('[^']*',){32})" "\\1\n" _bytes "${_bytes}")
file(WRITE "${OUT}.tmp" "// Generated from ${IN} by cmake/EmbedFile.cmake. Do not edit.\n#include <cstddef>\nnamespace ${NS} {\nextern const char ${NAME}[];\nextern const std::size_t ${NAME}Size;\nconst char ${NAME}[] = {\n${_bytes}\n'\\0'};\nconst std::size_t ${NAME}Size = ${_size};\n}  // namespace ${NS}\n")
configure_file("${OUT}.tmp" "${OUT}" COPYONLY)
file(REMOVE "${OUT}.tmp")
