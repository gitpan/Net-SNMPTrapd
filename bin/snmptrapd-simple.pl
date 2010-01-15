#!/usr/bin/perl

use strict;
use Net::SNMPTrapd;
use Getopt::Long qw(:config no_ignore_case); #bundling
use Pod::Usage;

my %opt;
my ($opt_help, $opt_man);

GetOptions(
  'directory=s' => \$opt{'dir'},
  'interface:i' => \$opt{'interface'},
  'write+'      => \$opt{'write'},
  'help!'       => \$opt_help,
  'man!'        => \$opt_man
) or pod2usage(-verbose => 0);

pod2usage(-verbose => 1) if defined $opt_help;
pod2usage(-verbose => 2) if defined $opt_man;

# -d is a directory, if it exists, assign it
if (defined($opt{'dir'})) {

    # replace \ with / for compatibility with UNIX/Windows
    $opt{'dir'} =~ s/\\/\//g;

    # remove trailing / so we're sure it does NOT exist and we CAN put it in later
    $opt{'dir'} =~ s/\/$//;

    if (!(-e $opt{'dir'})) {
        print "$0: directory does not exist - $opt{'dir'}";
        exit 1
    }
    $opt{'write'} = 1 if (!$opt{'write'})
}

if (defined($opt{'interface'})) {
    if (!(($opt{'interface'} > 0) && ($opt{'interface'} < 65536))) {
        print "$0: port not valid - $opt{'interface'}"
    }
} else {
    $opt{'interface'} = '162'
}

my $snmptrapd = Net::SNMPTrapd->new(
                                    'LocalPort' => $opt{'interface'}
                                   );

if (!$snmptrapd) {
    printf "$0: Error creating SNMPTrapd listener: %s", Net::SNMPTrapd->error;
    exit 1
}

while (1) {
    my $trap;
    if (!($trap = $snmptrapd->get_trap())) { next }

    if (!(defined($trap->process_trap()))) {
        printf "$0: %s\n", Net::SNMPTrapd->error
    } else {
        my $p = sprintf "%s\t%i\t%i\t%s\t", 
                         $trap->peeraddr, 
                         $trap->peerport, 
                         $trap->version, 
                         $trap->community;
        if ($trap->version == 1) {
            $p .= sprintf "%s\t%s\t%s\t%s\t%s\t", 
                         $trap->ent_OID, 
                         $trap->agentaddr, 
                         $trap->generic_trap, 
                         $trap->specific_trap, 
                         $trap->timeticks
        } else {
            $p .= sprintf "%s\t%s\t%s\t", 
                         $trap->request_ID, 
                         $trap->error_status, 
                         $trap->error_index
        }
        for my $varbind (@{$trap->varbinds}) {
            for (keys(%{$varbind})) {
                $p .= sprintf "%s: %s; ", $_, $varbind->{$_}
            }
        }

        print "$p\n";

        if ($opt{'write'}) {
            my $outfile;
            if (defined($opt{'dir'})) { $outfile = $opt{'dir'} . "/" }

            $outfile .= "snmptrapd.log";
            
            if (open(OUT, ">>$outfile")) {
                print OUT $p;
                close(OUT)
            } else {
                print STDERR "$0: cannot open outfile - $outfile\n"
            }
        }
    }
}

=head1 NAME

SNMPTRAPD-SIMPLE - Simple SNMP Trap Server

=head1 SYNOPSIS

 snmptrapd-simple [options]

=head1 DESCRIPTION

Listens for SNMP traps and logs to console and optional 
file.  Can decode SNMP v1 and v2c traps.  SNMP Trap columns 
are:

        Source IP Address
        Source UDP port
        SNMP version
        SNMP community
  (Version 1)          (Version 2c)
  Enterprise OID       Request ID
  Agent IP Address     Error Status
  Trap Type            Error Index
  Specific Trap
  Timeticks
        Varbinds (OID: val; [...])

=head1 OPTIONS

 -d <dir>         Output file directory.
 --directory      DEFAULT:  (or not specified) [Current].

 -i #             UDP Port to listen on.
 --interface      DEFAULT:  (or not specified) 162.

 -w               Log to "snmptrapd.log".

=head1 LICENSE

This software is released under the same terms as Perl itself.
If you don't know what that means visit L<http://perl.com/>.

=head1 AUTHOR

Copyright (C) Michael Vincent 2010

L<http://www.VinsWorld.com>

All rights reserved

=cut
