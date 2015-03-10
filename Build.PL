#!env perl
use Module::Build;

Module::Build->new(
	module_name => 'Sslmgr',
	license => 'bsd',
	dist_author => 'Sjors Gielen <sjors@sjorsgielen.nl>',
	test_requires => {
		'Test::Directory' => 0,
	},
	requires => {
		'Crypt::OpenSSL::X509' => 0,
		'DateTime::Format::x509' => 0,
	},
)->create_build_script;
