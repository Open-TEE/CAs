import qbs

Project {
    name: "ClientApplications"
    references: [
        "conn_test_app/conn_test_app.qbs",
        "test_session/test_session.qbs",
	"smoke_test_CAs/smoke_test_CAs.qbs",
	"example_sha1_ca/example_sha1_ca.qbs",
	"crypto_tester_ca/crypto_tester_ca.qbs"
    ]
}

