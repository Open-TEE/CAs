import qbs

CppApplication {
    type: "application"
    name: "crypto_tester_ca"
    consoleApplication:true
    destinationDirectory: '.'

    Depends { name: "tee" }

    files: ["crypto_tester_ca.c"]
}

