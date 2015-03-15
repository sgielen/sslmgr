use Test::More tests => 3;
use Test::Directory;
use Sslmgr;

my $dir = Test::Directory->new();
$dir->create("test.crt", content => <<EOF);
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJAOFxb7RxkyLEMA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV
BAMMD3d3dy5leGFtcGxlLmNvbTAeFw0xNTAzMTAwMDM3MTZaFw0yNTAzMDcwMDM3
MTZaMBoxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMk1Tm3GbKHdmfzZQvzHpbY+dSXaO3Gkf2EOYJA86Vrb
/9T/PUePGyWvrwtSnpXCp4YURE8c0ZflKtoPMYhbRZueSHhInDdnvSrw3mzTlaMf
4EaatwcFEY7VBkpiTf12u4c/EYn+6Ygu4IU8ytlm8noMsCBn9B3SpAF6vNoJ1R6A
ABY4yPQRV/qAqYzsDeedoEZAO38pnCfg2yi9cAeCq2C43gMPIAjUvA9dlYYIHBID
7MRFALS46KxbcklLdyFzEMBsT50evJKAt6bOz88AveOYx0tTFhIKCrBJe7L1LyfK
KJ4MOKketTBl7X8spASNs0GIN8KGLHOCbE7aigif/NcCAwEAAaNQME4wHQYDVR0O
BBYEFB6UCeDLACmu1xElVMkvRVl2KtkCMB8GA1UdIwQYMBaAFB6UCeDLACmu1xEl
VMkvRVl2KtkCMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAIp3QGlC
bjsBxCcYHjt2K1V/v+i10L+MQaU5aWWQfIoJkIBPsH/4ONMtT6f3a2Foh+Krcp/u
dY8N5avYpzchpKddXFBrwfGZt0gf1kw5kSPQW79D6ue4V9Dv2jmUmv9Xh7xG/vGj
QmXWq94O4q8NA4vJaUY+5R2htWvTIIVXWBLXndMJC2jBnWlZO8boIHs1aCgx9cgP
UoxJiS3eOa/Nf0jUSUTk6+5D/4OQUz0Zd71alBtEGyKxiGTc0CDDZzg9vYCVsWVD
Wm/134zb+Md+On4wvXC3gb+/5DojinQmZMCq8s8Hat+okc3asqrAeIG94UoV599Y
PRkgx3SBN+jiZK8=
-----END CERTIFICATE-----
EOF
$dir->create("textfile.txt", content => "This is just a random text file.");

is(Sslmgr::is_trusted_root_cert($dir->path, 'CN=www.example.com'), 1, "CA is trusted root");
is(Sslmgr::is_trusted_root_cert($dir->path, 'CN=www.example.org'), 0, "Negative trusted root check");

$dir->is_ok("no missing or new files");
