import qbs

CppApplication {
    type: "application"
    name: "tester_app"
    consoleApplication:true
    destinationDirectory: '.'

    Depends { name: "tee" }
    Depends { name: "cpp" }
    cpp.cppFlags: "-std=c++11"

    files: [
        "tester_app.cpp",
        "tester.h",
        "tester.cpp"
    ]
}

