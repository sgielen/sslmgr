use Test::More tests => 5;
use File::Temp qw(tempfile);
use Sslmgr;

is_deeply([Sslmgr::split_marked_files("")], [], "split_marked_files on empty input.");

my $input = <<EOF;
-----BEGIN FILE-----
This is the files' contents.
-----END FILE-----
EOF
is_deeply([Sslmgr::split_marked_files($input)],
	[["FILE", <<EOF]],
-----BEGIN FILE-----
This is the files' contents.
-----END FILE-----
EOF
	"Return a simple file.");

my $input = <<EOF;
This is a comment that should not appear anywhere.
-----BEGIN FILE-----
This is the first file's contents.
-----END FILE-----
This is another comment outside of a file.
-----BEGIN FILE-----
This is the second file's contents.
-----END FILE-----
This is a third comment outside of a file.
EOF
is_deeply([Sslmgr::split_marked_files($input)],
	[["FILE", <<EOF],
-----BEGIN FILE-----
This is the first file's contents.
-----END FILE-----
EOF
	 ["FILE", <<EOF]],
-----BEGIN FILE-----
This is the second file's contents.
-----END FILE-----
EOF
	"Split two files and ignore lines outside them.");

my $input = <<EOF;
-----BEGIN FILE-----
This is part of the files' contents.
EOF
undef $@;
eval { Sslmgr::split_marked_files($input); };
ok($@, "split_marked_files on incomplete input throws");

my $input = <<EOF;
-----BEGIN FILE-----
This is part of the files' contents.
-----END FILES-----
EOF
undef $@;
eval { Sslmgr::split_marked_files($input); };
ok($@, "split_marked_files on corrupt input throws");
