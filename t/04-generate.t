use Test::More tests => 8;
use Test::Directory;
use Sslmgr;
use Fcntl ':mode';

my $dir = Test::Directory->new();
my $keydir = $dir->path;
$dir->create('openssl.cnf', content => <<EOF);
Don't touch this line
# Don't touch this either
Common name: '%COMMONNAME%'
EOF
my $file = Sslmgr::get_configfile_for_cn($keydir, "foo.bar.baz");
is(`cat $file`, <<EOF, "Correct configfile generated");
Don't touch this line
# Don't touch this either
Common name: 'foo.bar.baz'
EOF
$dir->remove_files("openssl.cnf");
$dir->is_ok("no missing or new files");

$dir->create('openssl.cnf', content => <<"EOF");
dir = $keydir

[req_distinguished_name]
# Two-letter code for your country
countryName = UK

# State or province name
stateOrProvinceName = My State

# Locality Name (eg, city)
localityName = A City

# Organization Name (eg, company)
0.organizationName = SSL Keys Ltd.

# Optionally, organizational Unit Name (eg, section)
#organizationalUnitName = 

# Don't modify this value:
commonName = %COMMONNAME%

[req]
# The number of bits for any new RSA key
default_bits = 4096

# Don't modify these values:
distinguished_name = req_distinguished_name
prompt = no
EOF

my ($keyfile, $csrfile) = Sslmgr::generate_key_and_csr($dir->path, "bar.baz.quux");
is($keyfile, "bar.baz.quux.key", "Key has expected filename");
is($csrfile, "bar.baz.quux.csr", "CSR has expected filename");
$dir->has("bar.baz.quux.key", "Key created");
$dir->has("bar.baz.quux.csr", "CSR created");
is((stat($dir->path($keyfile)))[2] & 0777, 0600, "Key is only read-writable by owner");

$dir->is_ok("no missing or new files");
