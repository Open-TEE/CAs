import qbs

CppApplication {
    type: "application"
    name: "test_session"
    Depends { name: "tee" }

    files: ['src/test_session.c']
}

//CppApplication {
//    type: "application"
//    name: "test_write_sock"
//    Depends { name: "tee" }
//    files: "src/raw_socket.c"
//}
