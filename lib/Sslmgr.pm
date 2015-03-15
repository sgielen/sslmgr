package Sslmgr;

=head1 NAME

Sslmgr - Backing library for the sslmgr tool

=cut

use strict;
use warnings;
use Crypt::OpenSSL::X509;
use DateTime::Format::x509;
use File::Temp qw(tempfile);
use IPC::Run qw(run);

our $VERSION = "0.1";
our $RELEASE_DATE = "2015-03-09";
our $LONG_VERSION = "sslmgr $VERSION ($RELEASE_DATE), Sjors Gielen";

=head1 METHODS

=head2 get_keys($keydir)

Returns an array with relative paths of all *.key files from the given keydir.

This method calls die() if the directory was unreadable.

=cut

sub get_keys {
	my ($keydir) = @_;
	opendir my $dh, $keydir or die "Failed to open keydir $keydir: $!\n";
	my @files = grep { /\.key$/ && -f "$keydir/$_" } readdir($dh);
	closedir $dh;
	return @files;
}

=head2 get_certs($keydir)

Returns an array with relative paths of all *.crt files from the given keydir,
but not .chain.crt.

This method calls die() if the directory was unreadable.

=cut

sub get_certs {
	my ($keydir) = @_;
	opendir my $dh, $keydir or die "Failed to open keydir $keydir: $!\n";
	my @files = grep { /\.crt$/ && !/\.chain\.crt$/ && -f "$keydir/$_" } readdir($dh);
	closedir $dh;
	return @files;
}

=head2 get_keys_and_certs($keydir)

Returns a hash with all corresponding keys and their certs from the given
keydir. Each key is the CN for the key, the corresponding value is an arrayref
with exactly two fields, where either one may be undef if no corresponding key
or cert was found.

This method calls die() if the directory was unreadable.

=cut

sub get_keys_and_certs {
	my ($keydir) = @_;
	my %keys;
	foreach my $keyfile (get_keys($keydir)) {
		$keyfile =~ /(?:^|\/)([^\/]+)\.key/;
		$keys{$1} = [$keyfile, undef];
	}
	foreach my $certfile (get_certs($keydir)) {
		$certfile =~ /(?:^|\/)([^\/]+)\.crt/;
		if($keys{$1}) {
			$keys{$1}[1] = $certfile;
		} else {
			$keys{$1} = [undef, $certfile];
		}
	}
	return %keys;
}

=head2 get_cert_info($keydir, $certname)

Returns a Crypt::OpenSSL::X509 object containing information on the given
certificate.

=cut

sub get_cert_info {
	my ($keydir, $certname) = @_;
	my $certpath = "$keydir/$certname";
	return Crypt::OpenSSL::X509->new_from_file($certpath);
}

=head2 get_cert_info_for_contents($certcontents)

Returns a Crypt::OpenSSL::X509 object containing information on the given
certificate.

=cut

sub get_cert_info_for_contents {
	my ($certcontents) = @_;
	return Crypt::OpenSSL::X509->new_from_string($certcontents);
}

=head2 get_cert_validity_period($keydir, $certname)

Returns two DateTimes, corresponding to the begin and end validity periods
of the given certificate.

=cut

sub get_cert_validity_period {
	my ($keydir, $certname) = @_;
	my $cert_info = get_cert_info($keydir, $certname);
	my $df = DateTime::Format::x509->new();
	my $dt_begin = $df->parse_datetime($cert_info->notBefore());
	my $dt_after = $df->parse_datetime($cert_info->notAfter());
	return ($dt_begin, $dt_after);
}

=head2 generate_key_and_csr($keydir, $cn)

Generates a new 4096 bit RSA key without a password, as well as a corresponding
CSR. Returns the path of the new key and CSR relative to the keydir.

=cut

sub generate_key_and_csr {
	my ($keydir, $cn) = @_;
	my $keyfile = $cn . '.key';
	my $csrfile = $cn . '.csr';
	my $keypath = $keydir . '/' . $keyfile;
	my $csrpath = $keydir . '/' . $csrfile;
	if(-f $csrpath) {
		unlink($csrpath);
	}

	my $configfile = get_configfile_for_cn($keydir, $cn);
	my $out = "";
	run([qw(openssl req -new -nodes -batch),
		"-keyout" => $keypath,
		"-config" => $configfile,
		"-out" => $csrpath], '>', \$out, '2>&1');
	if(! -f $keypath || ! -f $csrpath) {
		warn "Generation of key or CSR file failed:\n";
		die $out . "\n";
	}
	chmod 0600, $keypath;
	unlink($configfile);
	return ($keyfile, $csrfile);
}

=head2 get_configfile_for_cn($keydir, $cn)

Takes an openssl configuration file as '$keydir/openssl.cnf' (which can be
generated and edited using 'sslmgr config'), copies it to a temporary place
replacing any '%COMMONNAME%' with the given CN. Then, returns the path to
the temporary file.

=cut

sub get_configfile_for_cn {
	my ($keydir, $cn) = @_;
	my $configfile = $keydir . '/openssl.cnf';
	if(! -f $configfile) {
		die "No config file found. Run 'sslmgr config' first.\n";
	}
	open my $fh, '<', $configfile or die $!;
	my ($cfh, $cfile) = tempfile();
	while(<$fh>) {
		s/%COMMONNAME%/$cn/;
		print $cfh $_;
	}
	close $cfh;
	close $fh;
	return $cfile;
}

=head2 is_trusted_root_cert($rootstore, $subject)

Walks through the rootstore and finds a certificate that matches the given
subject.

=cut

sub is_trusted_root_cert {
	my ($rootstore, $subject) = @_;
	opendir my $dh, $rootstore or die "Failed to open rootstore $rootstore: $!\n";
	while((my $file = readdir($dh))) {
		if(! -r $rootstore . '/' . $file) {
			# skip file
			next;
		}
		open my $fh, '<', $rootstore . '/' . $file or die $!;
		my @certs = split_marked_files($fh);
		close $fh;
		foreach my $cert (@certs) {
			if($subject eq get_cert_info_for_contents($cert->[1])->subject) {
				return 1;
			}
		}
	}
	closedir $dh;
	return 0;
}

=head2 split_marked_files($input)

Split the given input using file markers used in PEM files. Every file in the
input starts with a '-----BEGIN <filetype>-----' marker and ends with a
'-----END <filetype>----' marker. Lines outside such markers are ignored, and
markers must match up. Returns a list of files, where every file is represented
as ["<filetype>", "file contents including markers"].

=cut

sub split_marked_files {
	my ($input) = @_;
	my $handle;
	if(ref($input) && ref($input) eq "GLOB") {
		$handle = $input;
	} else {
		open $handle, '<', \$input or die $!;
	}
	my $filetype;
	my $file = "";
	my @files;
	while(<$handle>) {
		if(/^-----END (.+)-----$/) {
			if(!$filetype || $filetype ne $1) {
				die "Corrupt input: expected end of $filetype, got end of $1\n";
			}
			push @files, [$filetype, $file . $_];
			$file = "";
			undef $filetype;
			next;
		} elsif(/^-----BEGIN (.+)-----$/) {
			$filetype = $1;
		}
		if(!$filetype) {
			# ignore lines outside a marked block
			next;
		}
		$file .= $_;
	}
	if($file ne "") {
		die "Corrupt input: expected END of $filetype.\n";
	}
	return @files;
}

=head2 has_chain($keydir, $cn)

Checks if the given CN currently has a certificate chain associated with it.
This does not check the chain validity, but assumes that a chain is valid if it
exists. Use build_chain to try to build a chain if none exists.

=cut

sub has_chain {
	my ($keydir, $cn) = @_;
	my $chainfile = $keydir . '/' . $cn . '.chain.crt';
	return -f $chainfile;
}

=head2 build_chain($keydir, $rootstore, $cn)

Builds a certificate chain for the given Common Name. This uses previously
imported intermediary certificates.

If a trusted path to a certificate in the root store can be found, this method
creates a chain certificate file with all the intermediary certificates and the
final certificate, then returns a hashmap with 'built' set to a true value and
'chain' set to the list of certificates used to build the chain.

If no path can be found, this method returns a hashmap with 'built' set to a
false value, 'chain' set to the list of certificates found so far, and
'missing_subject' conveniently set to the issuer_subject of the last
certificate in the chain.

=cut

sub build_chain {
	my ($keydir, $rootstore, $cn) = @_;

	my $certfile = $cn . '.crt';
	my $certpath = $keydir . '/' . $certfile;
	my $chainfile = $cn . '.chain.crt';
	my $chainpath = $keydir . '/' . $chainfile;
	if(! -f $certpath) {
		die "Can't build a chain for $cn: that certificate does not exist.\n";
	}

	my $cert_info = get_cert_info($keydir, $certfile);
	my @certs_in_chain = ($cert_info);

	while(1) {
		my $cert = $certs_in_chain[$#certs_in_chain];

		# do we have an intermediary cert with that hash?
		# TODO: we should use the issuer hash here, but issue #41 in
		# crypt::openssl::x509 prevents this
		if(-d "$keydir/.intermediary") {
			opendir my $dh, "$keydir/.intermediary" or die $!;
			my $intermediary_found = 0;
			while((my $file = readdir($dh))) {
				if($file =~ /\.crt$/) {
					my $path = ".intermediary/$file";
					my $i_cert_info = get_cert_info($keydir, $path);
					if($i_cert_info->subject eq $cert->issuer) {
						$intermediary_found = 1;
						push @certs_in_chain, $i_cert_info;
						last;
					}
				}
			}
			next if($intermediary_found);
			closedir $dh;
		}

		# do we have a root cert with that hash?
		if(is_trusted_root_cert($rootstore, $cert->issuer)) {
			# OK! Chain is done!
			# Note: don't include root cert in the chain.
			open my $fh, '>', $chainpath or die $!;
			foreach(reverse @certs_in_chain) {
				print $fh $_->as_string();
			}
			close $fh;
			return (
				built => 1,
				chain => \@certs_in_chain,
			);
		}

		last;
	}

	my $last_cert = $certs_in_chain[$#certs_in_chain];
	return (
		built => 0,
		chain => \@certs_in_chain,
		missing_subject => $last_cert->issuer,
	);
}
