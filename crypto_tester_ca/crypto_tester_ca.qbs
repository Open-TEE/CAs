import qbs

CppApplication {
    type: "application"
    name: "crypto_tester"
    consoleApplication:true
    destinationDirectory: '.'

    Depends { name: "tee" }

    files: ["crypto_tester_ca.c"]
}

