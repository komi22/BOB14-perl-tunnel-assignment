#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Fcntl qw(:seek);

$| = 1;

my $IN   = "in.hex";
my $OUTF = "out.hex";

open my $OUT, ">>", $OUTF or die $!;
select((select($OUT), $|=1)[0]);
binmode($OUT);

my $sock;
my $sel = IO::Select->new();
my $in_off = 0;

sub out_line {
    my ($s) = @_;
    print $OUT $s, "\n";
}

sub conn_open {
    my ($host, $port) = @_;

    if ($sock) {
        eval { $sel->remove($sock) };
        eval { close $sock };
        undef $sock;
    }

    $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5
    );

    if ($sock) {
        binmode($sock);
        $sel->add($sock);
        out_line("c 01");
    } else {
        my $err = "$!";
        my $hhex = unpack('H*', $host);
        out_line("e CONNECT_FAIL host_hex=$hhex port=$port err=$err");
        out_line("c 00");
    }
}

while (1) {
    if ($sock && $sel->can_read(0)) {
        my $buf = '';
        my $n = sysread($sock, $buf, 8192);
        if (defined $n && $n > 0) {
            my $hex = unpack("H*", $buf);
            out_line("d " . sprintf("%08X", $n) . " $hex");
        } elsif (defined $n && $n == 0) {
            out_line("x");
            eval { $sel->remove($sock) };
            eval { close $sock };
            undef $sock;
        }
    }

    if (open my $INH, "<", $IN) {
        seek($INH, $in_off, SEEK_SET);
        while (my $line = <$INH>) {
            $in_off = tell($INH);
            chomp $line;
            next unless length $line;

            my @tok = split / /, $line;
            my $t = shift @tok;

            if ($t eq 'C') {
                next unless @tok >= 3;
                my ($hlen_hex, $host_hex, $port_hex) = @tok[0,1,2];

                $hlen_hex =~ s/[^0-9A-Fa-f]//g;
                $host_hex =~ s/[^0-9A-Fa-f]//g;
                $port_hex =~ s/[^0-9A-Fa-f]//g;

                my $host = pack("H*", $host_hex);
                my $port = hex($port_hex);

                conn_open($host, $port);

            } elsif ($t eq 'D') {
                next unless @tok >= 2 && $sock;
                my ($len_hex, $data_hex) = @tok[0,1];

                $len_hex  =~ s/[^0-9A-Fa-f]//g;
                $data_hex =~ s/[^0-9A-Fa-f]//g;

                my $raw = pack("H*", $data_hex);
                my $w = syswrite($sock, $raw);

            } elsif ($t eq 'X') {
                next unless $sock;
                shutdown($sock, 1);
            }
        }
        close $INH;
    }

    select(undef, undef, undef, 0.01);
}
