package Sslmgr;

=head1 NAME

Sslmgr - Backing library for the sslmgr tool

=cut

use strict;
use warnings;
use Crypt::OpenSSL::X509;
use DateTime::Format::x509;

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
but not .ca.crt.

This method calls die() if the directory was unreadable.

=cut

sub get_certs {
	my ($keydir) = @_;
	opendir my $dh, $keydir or die "Failed to open keydir $keydir: $!\n";
	my @files = grep { /\.crt$/ && !/\.ca\.crt$/ && -f "$keydir/$_" } readdir($dh);
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
