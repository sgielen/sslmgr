#!env perl
use Module::Build;

Module::Build->new(
	module_name => 'Sslmgr',
	license => 'bsd',
	dist_author => 'Sjors Gielen <sjors@sjorsgielen.nl>',
	test_requires => {
		'Test::Directory' => 0,
	},
)->create_build_script;
