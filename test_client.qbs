import qbs

CppApplication {
    type: "application"
    Group {
        name: 'Test Session Connection'
        files: ['src/test_session.c']
        cpp.includePaths: ["../libtee/include"]
        cpp.libraryPaths: ["../libtee-build/qtc_Desktop-debug"]
        cpp.dynamicLibraries: ["libtee"]
    }

   // files: "src/raw_socket.c"
}
