import qbs

CppApplication {
    type: "application"
    name: "test_session"
    Depends { name: "tee" }
    consoleApplication: true

    files: ['src/conn_test_app.c']
}

//CppApplication {
//    type: "application"
//    name: "test_write_sock"
//    Depends { name: "tee" }
//    files: "src/raw_socket.c"
//}
