use Test::More tests => 19;
use Test::Directory;
use Sslmgr;

my $dir = Test::Directory->new();
is_deeply([Sslmgr::get_keys($dir->path)], [], "By default, get_keys is empty");
is_deeply([Sslmgr::get_certs($dir->path)], [], "By default, get_certs is empty");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)}, {}, "By default, get_keys_and_certs is empty");

$dir->touch("foo.bar.baz.key");
is_deeply([Sslmgr::get_keys($dir->path)], ["foo.bar.baz.key"], "get_keys returns new key");
is_deeply([Sslmgr::get_certs($dir->path)], [], "get_certs doesn't return keys");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)},
	{"foo.bar.baz" => ["foo.bar.baz.key", undef]}, "get_keys_and_certs returns new key");

$dir->touch("foo.bar.quux.crt");
is_deeply([Sslmgr::get_keys($dir->path)], ["foo.bar.baz.key"], "get_keys only returns key");
is_deeply([Sslmgr::get_certs($dir->path)], ["foo.bar.quux.crt"], "get_certs returns new cert");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)},
	{"foo.bar.baz" => ["foo.bar.baz.key", undef],
	 "foo.bar.quux" => [undef, "foo.bar.quux.crt"]},
	"get_keys_and_certs does not link key with new cert");

$dir->touch("quux.bar.baz.key");
$dir->touch("quux.bar.baz.crt");
is_deeply([Sslmgr::get_keys($dir->path)],
	["foo.bar.baz.key", "quux.bar.baz.key"], "get_keys returns both keys");
is_deeply([Sslmgr::get_certs($dir->path)],
	["foo.bar.quux.crt", "quux.bar.baz.crt"], "get_certs returns both certs");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)},
	{"foo.bar.baz" => ["foo.bar.baz.key", undef],
	 "foo.bar.quux" => [undef, "foo.bar.quux.crt"],
	 "quux.bar.baz" => ["quux.bar.baz.key", "quux.bar.baz.crt"]},
	"get_keys_and_certs links new key + cert");

$dir->touch("bar.baz.chain.crt");
is_deeply([Sslmgr::get_keys($dir->path)],
	["foo.bar.baz.key", "quux.bar.baz.key"], "get_keys doesn't return chain crt");
is_deeply([Sslmgr::get_certs($dir->path)],
	["foo.bar.quux.crt", "quux.bar.baz.crt"], "get_certs doesn't return chain crt");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)},
	{"foo.bar.baz" => ["foo.bar.baz.key", undef],
	 "foo.bar.quux" => [undef, "foo.bar.quux.crt"],
	 "quux.bar.baz" => ["quux.bar.baz.key", "quux.bar.baz.crt"]},
	"get_keys_and_certs doesn't return chain crt");

$dir->touch("bar.baz.txt");
is_deeply([Sslmgr::get_keys($dir->path)],
	["foo.bar.baz.key", "quux.bar.baz.key"], "get_keys doesn't return txt file");
is_deeply([Sslmgr::get_certs($dir->path)],
	["foo.bar.quux.crt", "quux.bar.baz.crt"], "get_certs doesn't return txt file");
is_deeply({Sslmgr::get_keys_and_certs($dir->path)},
	{"foo.bar.baz" => ["foo.bar.baz.key", undef],
	 "foo.bar.quux" => [undef, "foo.bar.quux.crt"],
	 "quux.bar.baz" => ["quux.bar.baz.key", "quux.bar.baz.crt"]},
	"get_keys_and_certs doesn't return txt file");

$dir->is_ok("no missing or new files");
