cmake_minimum_required(VERSION 3.20)
project(aegisbpf VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)
find_program(BASH bash REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(SYSTEMD QUIET libsystemd)

set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/aegis.bpf.o)
set(SKELETON_HEADER ${CMAKE_CURRENT_BINARY_DIR}/aegis.skel.h)
set(VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)

set(BPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR})
list(APPEND BPF_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIRS})
set(BPF_INCLUDE_FLAGS "")
foreach(dir IN LISTS BPF_INCLUDE_DIRS)
    list(APPEND BPF_INCLUDE_FLAGS -I${dir})
endforeach()

set(BPF_TARGET_ARCH)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(BPF_TARGET_ARCH x86)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(BPF_TARGET_ARCH arm64)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(BPF_TARGET_ARCH arm)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "ppc64le")
    set(BPF_TARGET_ARCH powerpc)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
    set(BPF_TARGET_ARCH s390)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    set(BPF_TARGET_ARCH riscv)
else()
    set(BPF_TARGET_ARCH ${CMAKE_SYSTEM_PROCESSOR})
endif()

add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    COMMAND ${BASH} -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}"
    VERBATIM
)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_TARGET_ARCH} ${BPF_INCLUDE_FLAGS} -c ${BPF_SOURCE} -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE} ${VMLINUX_HEADER}
    VERBATIM
)

add_custom_command(
    OUTPUT ${SKELETON_HEADER}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${BPF_OBJECT} > ${SKELETON_HEADER}"
    DEPENDS ${BPF_OBJECT}
    VERBATIM
)

set_source_files_properties(${SKELETON_HEADER} PROPERTIES GENERATED TRUE)

add_custom_target(bpf_skel DEPENDS ${SKELETON_HEADER})

add_executable(aegisbpf src/main.cpp ${SKELETON_HEADER})
add_dependencies(aegisbpf bpf_skel)
target_include_directories(aegisbpf PRIVATE ${LIBBPF_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
target_link_directories(aegisbpf PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf PRIVATE ${LIBBPF_LIBRARIES})
if (SYSTEMD_FOUND)
    target_compile_definitions(aegisbpf PRIVATE HAVE_SYSTEMD)
    target_include_directories(aegisbpf PRIVATE ${SYSTEMD_INCLUDE_DIRS})
    target_link_directories(aegisbpf PRIVATE ${SYSTEMD_LIBRARY_DIRS})
    target_link_libraries(aegisbpf PRIVATE ${SYSTEMD_LIBRARIES})
endif()
target_compile_definitions(aegisbpf PRIVATE AEGIS_BPF_OBJ_PATH="${BPF_OBJECT}")

install(TARGETS aegisbpf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${BPF_OBJECT} DESTINATION ${CMAKE_INSTALL_LIBDIR}/aegisbpf)
install(FILES packaging/systemd/aegisbpf.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
install(FILES packaging/systemd/aegisbpf.env DESTINATION /etc/default RENAME aegisbpf)
install(FILES config/policy.example DESTINATION /etc/aegisbpf)

set(CPACK_PACKAGE_NAME "aegisbpf")
set(CPACK_PACKAGE_VENDOR "AegisBPF")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AegisBPF runtime security agent")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "aegisbpf@localhost")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_GENERATOR "TGZ")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf1 | libbpf0")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_REQUIRES "libbpf")
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __brp_strip /bin/true\n%global __brp_strip_static_archive /bin/true")
include(CPack)
