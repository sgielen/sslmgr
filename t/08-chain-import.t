use Test::More tests => 34;
use Test::Directory;
use Sslmgr;

my $root = Test::Directory->new();
$root->create("root.crt", content => root_crt());

my $ssl = Test::Directory->new();
$ssl->create("www.simple.com.key", content => simple_key());
$ssl->create("www.example.com.key", content => example_key());

# Simple.rt is signed by root.crt, so chain should be immediately buildable
ok(!Sslmgr::has_chain($ssl->path, "www.simple.com"), "No chain initially");
my $build_result = [Sslmgr::import_certificate($ssl->path, $root->path, simple_crt())];
is(scalar @$build_result, 1, "One chain rebuild was attempted");
$build_result = $build_result->[0];

$ssl->has("www.simple.com.crt", "Certificate imported correctly");
is($build_result->{'built'}, 1, "Build chain succeeded");
is(scalar @{$build_result->{'chain'}}, 1, "Chain consists of only one cert");
is($build_result->{'chain'}[0]->subject,
	"C=NL, ST=Gelderland, L=Nijmegen, O=N.V. My Organization, CN=www.simple.com",
	"Chain consists of right certificate");
ok(Sslmgr::has_chain($ssl->path, "www.simple.com"), "Chain built succesfully");
$ssl->has("www.simple.com.chain.crt", "Chain built succesfully");
$ssl->has("www.simple.com.chainonly.crt", "Chainonly built succesfully");
$root->is_ok("no missing or new files");
$ssl->is_ok("no missing or new files");

# Example is signed by an intermediary, which is signed by root.crt
ok(!Sslmgr::has_chain($ssl->path, "www.example.com"), "No chain initially");
$build_result = [Sslmgr::import_certificate($ssl->path, $root->path, example_crt())];
is(scalar @$build_result, 1, "One chain rebuild was attempted");
$build_result = $build_result->[0];

$ssl->has("www.example.com.crt", "Certificate imported correctly");
is($build_result->{'built'}, 0, "Build chain failed");
is(scalar @{$build_result->{'chain'}}, 1, "Chain consists of only one cert");
is($build_result->{'chain'}[0]->subject,
	"C=NL, ST=Gelderland, L=Nijmegen, O=N.V. My Organization, CN=www.example.com",
	"Chain consists of right certificate");
is($build_result->{'missing_subject'},
	"C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
	"Chain requires the right certificate");
ok(!Sslmgr::has_chain($ssl->path, "www.example.com"), "Still no chain built");
$root->is_ok("no missing or new files");
$ssl->is_ok("no missing or new files");

# Import the intermediary and re-try the build
$build_result = [Sslmgr::import_certificate($ssl->path, $root->path, intermediary_crt())];
is(scalar @$build_result, 1, "One chain rebuild was attempted");
$build_result = $build_result->[0];

$ssl->has_dir(".intermediary", "Intermediary directory created");
# Two OpenSSL versions seen in the wild had different hashing algorithms...
if(-f $ssl->path(".intermediary/1987cbba.crt")) {
	$ssl->has(".intermediary/1987cbba.crt", "Intermediary imported correctly");
} else {
	$ssl->has(".intermediary/9da13359.crt", "Intermediary imported correctly");
}
$build_result = {Sslmgr::build_chain($ssl->path, $root->path, "www.example.com")};
is($build_result->{'built'}, 1, "Build chain failed");
is(scalar @{$build_result->{'chain'}}, 2, "Chain consists of two certs");
is($build_result->{'chain'}[0]->subject,
	"C=NL, ST=Gelderland, L=Nijmegen, O=N.V. My Organization, CN=www.example.com",
	"Chain starts with normal certificate");
is($build_result->{'chain'}[1]->subject,
	"C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
	"Intermediary certificate follows in chain");
ok(Sslmgr::has_chain($ssl->path, "www.example.com"), "Chain built succesfully");
$ssl->has("www.example.com.chain.crt", "Chain built succesfully");
$ssl->has("www.example.com.chainonly.crt", "Chainonly built succesfully");
$root->is_ok("no missing or new files");
$ssl->is_ok("no missing or new files");

# build_chain throws if certificate doesn't exist
undef $@;
eval { Sslmgr::build_chain($ssl->path, $root->path, "www.example.org"); };
ok($@, "build_chain throws if certificate doesn't exist");

sub root_crt {
	return <<EOF;
-----BEGIN CERTIFICATE-----
MIIFLjCCAxYCCQC+AJhvODuMWDANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJV
SzETMBEGA1UECBMKU29tZS1TdGF0ZTESMBAGA1UEBxMJQ2l0eS1OYW1lMSEwHwYD
VQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwMzE1MjAwMjIxWhcN
MTUwMzE2MjAwMjIxWjBZMQswCQYDVQQGEwJVSzETMBEGA1UECBMKU29tZS1TdGF0
ZTESMBAGA1UEBxMJQ2l0eS1OYW1lMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRz
IFB0eSBMdGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC3I9tEvGMa
C+944i+9ayPIDNM20okvLCtwP+e4BIqlI3/acZ1dx5pok5zvL7plRFCmjhxZKPVz
X0buj+2ELe6xBSip+xTp8IXtO6YuC9/fG/TzBNrHKjrWkGawHkLjJ6/Lnddtm9Zz
+DIoRFwGPPL9DSomGC4xqg+qq6jGDfnJEzIRs9XAAKyAmJiLOqPz9K6QIPu1slZ9
FE2OwI3OmuFXrvFCzE0GpoAC2u6pFEnMhmUWkoEdzzViCWQ+3YTR8ruONuUwbZPl
Tu3+mBCjSAGL98AJ0rMdxHWXsFeR/JdAGk+YhonV3uC1kP9qnw0MycAKc78EOsgp
YKVp0aVebQKcus0GdUnXQ1gwpOffjb/VyKR/Wc8HhG1jcQUAtDO4Jb6X61FVtwtK
vLlMCNJ291nZVJi9mZVIQNv3ExyCUbbnQKM5uRxVPVOCf6SxwXLc4FpdTftAh8/u
nCbcljhqI4SX2V74t2j7DH2h18nUALtRoLSEaI3S7cOgzv4i86+1vx8r92v5iBDe
8O+l85XIgGFDmwZyC9YYbl7Vm9qcJWXZR6O1MRSAq5IGABFkLm76jLYm4FmTBkjn
BgqX6GMnheC1oOdVM6TjhtOAnvPuBtwxYuW5JT+vBDQbdnrDojHlT1lT02rdr7Es
Fpb7cdwZpAR7dCRbH+M+5PfKfKrYbtqnbQIDAQABMA0GCSqGSIb3DQEBBQUAA4IC
AQCatWy8E1hb6K4Nj31Xek4mjg/+CGN5qc5Lz12nE1U7ETuF/wKYilMfeKvGbjIT
Cd+JfnJtSBHF6QLrLJG3oQgKV+m0UJ04aGx1/cS6D2S91zqg9QCpUy7trSYZ6DXU
G2abs/m1ZIgIwxISud8DWq+D4IFgmqzK6iNGsKdggqTI1/zuAkGEmpf+M7P1obBI
Vr3/L/GeFgAmM/oogrCWXAGXNkrEE4CLwRATROfcsFm3pFMUekbV35cNBP9YzJZR
ynXtK1nFDezv7zGfUOXjooRUs7bjY0AMUIGOxz11QOYSuTABfPabzYPkHqZUDqJ7
CkOhXtH0au5TMwnR+f2zSXeT9FlO9UQsUB1UIBYmHxP3mbA+/Mx1PgFrATUQMv6+
lsF0bUi3xjCkACCOXluh1vMXtLYucRERbC1LCLJGzvKLCiuv7Dx/y05uUKnQ0oNq
Gem7JNGgMO9UlKZW4+mTiApSPDFPCMAb//RnbyeAncdI+ivXUCUJsIWx51yo3mU2
T08c/wlVUiix19FaMPdNMAQl8TVFnAlSJ1qdyEgVHXUCPaqttY1ITpNp6Y/3Tya1
RdlTc/2vxX8tJPUza70rXOqIf2pWbTLtc4G36itGxuysh8OGpcAWIkEut4wyQl8J
uwiFarHZVAgCpuKzU99cIqyyEbD80puu5P8nWGXAz5hPlA==
-----END CERTIFICATE-----
EOF
}

sub intermediary_crt {
	return <<EOF;
-----BEGIN CERTIFICATE-----
MIIEGjCCAgICCQCYbaOhEsC/CjANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJV
SzETMBEGA1UECBMKU29tZS1TdGF0ZTESMBAGA1UEBxMJQ2l0eS1OYW1lMSEwHwYD
VQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwMzE1MjEwMTMyWhcN
MTUwMzE2MjEwMTMyWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0
ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Go/UoyijLvE5NXrLukhYkohH0OjMxWMcJKy
0AnNaWNm3hECgdaPGWDRCxXEl+fL0iM6pH+7NklymVq4P0/1s6bqO6nOLknVJTO0
1G3pCHMCx1hGqlVLf8GXzuOm30WDEg74PB5YVFFLdjdHDLY8XhPzrS2+BGjnJ2UM
GZdqR3k2P7h3ZiVN0DFtcqebsbZw4+JOsv3guHy7FDIJ7kb/EP22FrSHhCioKgou
lH6hq0xUWYYByy8YvBb4iTYraIxQ1AYdPve5run8dlYvfIFXMCdxYn803w/vhRis
8Wuu6gzbx8BsvPTIsEBcPxTWh2xiHLjP+ftM4wTutHMekmN9GwIDAQABMA0GCSqG
SIb3DQEBBQUAA4ICAQCQeJF6Mw8YvmGUpSS2jDasmGmEzH/lHoVK7u9lv7ugPDEK
v29BBTMXWQhr38Nuy/oXBZziF1YTAl1iB0VrpEe3sNfRLgdyPoFqFEoHG1yut4VR
6PEMVSVlW6uduRNjQauOCog5KymXhQe65TOH30JGlEHEXEmQb52WUADkZGrD/5F7
K75rC430ef5R9JN81bPvZIGCl6eknHBCSoibNQrIhpQ+YXs88kA2DvnCgyIoYjVP
MBR7osvYx3cQ5vVt1lStL8ae12l7+0OgrbqaUKtS52JEugV07tKpj+TQWOxKd+Sv
kVnbGHlCkuwvfXWlEwQX9pTXCX6S5A6LarKEMTrG1tQZlMSauB5T4Dlm98Dy5SLB
6ckArstfbrfGtuY2OQVV5CoIvmdJX315txwtDaEQ51kHnDjtiZ6DRhjSsoPIhbA7
VXd3UyPi6aqHaHug10xisyJyy7vN13A++HS4ccWSAqpjKQnvt7bUDD3ZbAZlvmW9
OAOmpW1rCdKP0r9aJz2jPf25238+Bih00qcBJBrueCoUfFGx0qbwIXrh2fZUo3pj
DCN/J0O4Kk8ncbusUkTCB+6wDviWI7wkOQ4gMEfeimiQ8h3JOHu+t02EqN8caq91
yJqQ2PsCF1GwJQw5ssF0PfuN3oRkcPnk8E6QaicYc0JCY1Z2W0uKOfP7/+WrTw==
-----END CERTIFICATE-----
EOF
}

sub simple_key {
	return <<EOF;
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
EOF
}

sub simple_crt {
	return <<EOF;
-----BEGIN CERTIFICATE-----
MIIFQjCCAyoCCQCYbaOhEsC/CTANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJV
SzETMBEGA1UECBMKU29tZS1TdGF0ZTESMBAGA1UEBxMJQ2l0eS1OYW1lMSEwHwYD
VQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwMzE1MjEwMDM0WhcN
MTUwMzE2MjEwMDM0WjBtMQswCQYDVQQGEwJOTDETMBEGA1UECAwKR2VsZGVybGFu
ZDERMA8GA1UEBwwITmlqbWVnZW4xHTAbBgNVBAoMFE4uVi4gTXkgT3JnYW5pemF0
aW9uMRcwFQYDVQQDDA53d3cuc2ltcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAMfUL6kCGilPGfLuarqry4uWRSWAF4V8bsFIKpIlpRAT7vnd
0S7bFGvBactat01TgiGzv0rQ1MJ+bV0r0mHTgmErZz+QDGJo7gMwcFejdV7lgfFA
vCK8FuawH5W4uz4n29TwuHz1GM9lorNWdcUpDFWWNmX+3Y4ovZ4inoPYh04/znju
Xwder30FV+iKTm1v9nQ0ieKLXbShh97BpQeRkR0pLx7eJpPESYczTepsnBsNSnwd
8vfSsSXhG+3gAgL4F4/vaLmVYRm4dXGODtd7TRPs479bB6lyKBDzd5ioV8BNHWcR
Uoq4hc8PFdBO+rhAZBVGgeR+8IudyKLJ6D8ArYRIWGm8+o2ELlW8RCtPfAlepSmH
NjvLTGbcJ3WjaDSAixW38pnoDewjj+RQNSvdbWalfq9TCOv8a8bE5GRRKcGfXQJF
AM6JuA6q/5fnIPlimd3OZgcshU2hTQIM13sF66p7MAUfeUI9Plm5dRFhXGORl/bb
Ofk2GEoj8EwNwPmRt/kLDasBtd8GDXBWuexaFNlMpYxz0RjRfsDB5+bDgBBVRJ+B
+xWHaWktGrO+vEzLTuV3RptKioTTa3UAZh3dQpW1Zlv5KEYLg9hvDXDuUmMgfLLc
jxDl2Lql6K2Zq3pwx44KpNwvE8ZpYNGtoH3WDtFGShT+KMR8sWOjuaztmEQjAgMB
AAEwDQYJKoZIhvcNAQEFBQADggIBAEmvJisKTGPr56STVvRQGghqcdjVW/DBNnGE
F0+fjj4UDBxDYumZvAxspy4JToH6XTED6+2h2lbvIYtwN4ywnCleEbOzaf0zU7aH
j9EqffGUX4Vwefo3VtbzNvfhDHwIIShJDQ0gCR0L24OAfcO0GDaa28DAYjo44pXm
E9WfSUUauTzGYwdqEDJAOaW5xJa1oDDLF1KhHxp16VR9e7ooarXC5+BtdYhqPq47
S0UrUZyRXz7XyDK40lqkXqmcXMy77BPfqhfH035/cyyJ0xfBerIH9J5lhq7YGdV7
gZiHdeMYMfNv3zDayeR4V2xznlqM85cDAzuHnDCzVULDannlu4VyQGYmdZK1z2CN
1i3ECJbM01+ImLKBaZb9WbZC9OLdxXNQWvvV78s4kFXvFNEJbSPAKPn8w2t2U0nA
9aH1FZfTpPkYZjM9QxwXRnCwHsttL6CfN2RHhlRqFDgo3F1kitByIfw2MkPdqa83
fqE6XeQk12eoGxKgNDGWY1oEDL+DTlVzSI49MFQaf48Eehs23GwRqsXF+uXUX+5Z
xWVwFRVnDpwnieBS9Q8iEXynHkgpk+POrR26zavC4eWIW8Qw/rHo4P+wYYdAeiYH
UjMWSYT4DVwP/eKPA0ZRdcQeEl1YwGtdFb+SyEKjyv3XKbsg2WucNNf1E3QzOMSq
BQgDlwN2
-----END CERTIFICATE-----
EOF
}

sub example_key {
	return <<EOF;
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
EOF
}

sub example_crt {
	return <<EOF;
-----BEGIN CERTIFICATE-----
MIIELzCCAxcCCQCJPduWsxAgpjANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMB4XDTE1MDMxNTIxMDIyMFoXDTE1MDMxNjIxMDIyMFowbjELMAkG
A1UEBhMCTkwxEzARBgNVBAgMCkdlbGRlcmxhbmQxETAPBgNVBAcMCE5pam1lZ2Vu
MR0wGwYDVQQKDBROLlYuIE15IE9yZ2FuaXphdGlvbjEYMBYGA1UEAwwPd3d3LmV4
YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8OuQWstT
yLTqMoAMKSwzkdJGFG/thUaOL898MYYNhtyHwnN7pLoGiyTUedbvjV6Td4C64rJD
f5LNV5O7+gkpQcg35jRey4JnUOtwW98NIDb1vJaW12wyD458D2egRz39Pn0emCkB
GgR3E4Xl1fvsqbdzTcQAxQzIw9n+UNBizTRUfdpKcsLt0votpH88MWCjglXLqtqY
D1nEgMK5B4j9dd58H4NbS8dMBQebtpdvMXixPS9/u+jiJ5ZvIUIAT74E1CuRrEwQ
EXdwkzw2BxGFr2wkULSgRJTaslj+ADhV1/9Xr172Cjc/JAHUEaDmrA9RILTlyzgg
zk7FMWJtnAM+c1caMdNwis7rEFcc6FBiMbKwMzZu8GFSF5cz9jBtDpZTm71RwCYn
8i9RI+Sj+KGpm6LlZ9CDmO+GyUGBOwe9H0ZE30cjzqgmZfVWJXIyS/DNN2Yq0DR/
640CdW2EQkA0T/tZpsHAKMlfrSyKbZ7j//eoDR+25mb2GGsAr9cdDjUZziY8YDC0
cX60NQV71G17yHedNiUoLQvuOPdZ5VW2X2sHL/4HQFvmcAQW9J7Pk5dVVj/iWFs4
W2/muyKPBAn9YgD0EVpi3R3rl90gBoOnKWFgVNoCdLqqnD5bGT1g0IeGS5qRDMge
Ye3LtAiR5RvIrzUD5JLPxT5nSaosclCyV/8CAwEAATANBgkqhkiG9w0BAQUFAAOC
AQEAWGGcxGNw1M0pY/VoedDDvEMGKszVvCXZpXQDMq+Vd3dHunINBXsYeOuwrn1s
vy1cplDin0EZ9Vm9A2enuCRaihWc9fDpq3GlRFDqW53x20KI+85HIcVjSLoylD5c
pbsEzkSS01V5V4JMhgbqoqoA47+Dn8kwjv5pyv6cl/Y5VsyhP3Tw/QuX/dNo6hgh
PwHdZsb/9iRqO4mHjLD/poWbqFQx/QwWhBveX0chlPI9IaVwe1trs/h5J96bxfen
AjHiL9peSxBbYvM1eWg/oIo/ECAau3IvKX7oceswr2HDYNdZOQ2kng7m99MR6Dei
Uuk+qaaH8mUBZob1HUon3/ibmg==
-----END CERTIFICATE-----
EOF
}
