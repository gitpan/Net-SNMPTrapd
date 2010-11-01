#! /usr/bin/perl

use strict;
use Net::SNMP qw(:ALL);
use Getopt::Long qw(:config no_ignore_case); #bundling
use Pod::Usage;

my %opt;
my ($opt_help, $opt_man);

GetOptions(
  'version=i'     => \$opt{version},
  'community=s'   => \$opt{community},
  'integer|n=i'   => \$opt{integer},
  'string=s'      => \$opt{string},
  'oid=s'         => \$opt{oid},
  'ip|A=s'        => \$opt{ip},
  'counter32|C=i' => \$opt{counter32},
  'gauge32=i'     => \$opt{gauge32},
  'timeticks=i'   => \$opt{timeticks},
  'opaque|q=s'    => \$opt{opaque},
  'I|inform!'     => \$opt{inform},
  'help!'         => \$opt_help,
  'man!'          => \$opt_man
) or pod2usage(-verbose => 0);

pod2usage(-verbose => 1) if defined $opt_help;
pod2usage(-verbose => 2) if defined $opt_man;

# Make sure at least one host was provided
if (!@ARGV) {
    $ARGV[0] = 'localhost'
}

$opt{version}   = $opt{version}   || 1;
$opt{community} = $opt{community} || 'public';
$opt{integer}   = $opt{integer}   || 1;
$opt{string}    = $opt{string}    || 'String';
$opt{oid}       = $opt{oid}       || '1.2.3.4.5.6.7.8.9';
$opt{ip}        = $opt{ip}        || '10.10.10.1';
$opt{counter32} = $opt{counter32} || 32323232;
$opt{gauge32}   = $opt{gauge32}   || 42424242;
$opt{timeticks} = $opt{timeticks} || time();
$opt{opaque}    = $opt{opaque}    || 'opaque data';
$opt{inform}    = $opt{inform}    || 0;

for my $host (@ARGV) {

    my ($session, $error) = Net::SNMP->session(
                                               -hostname  => $host,
                                               -version   => $opt{version},
                                               -community => $opt{community},
                                               -port      => SNMP_TRAP_PORT
                                              );

    if (!defined($session)) {
       printf "Error: Starting SNMP session - %s\n", $error;
       exit 1
    } 

    if ($opt{version} == 1) {
        my $result = $session->trap(
            -enterprise   => '1.3.6.1.4.1.50000',
            -generictrap  => 6,
            -specifictrap => 1,
            -timestamp    => time(),
            -varbindlist  => [
                '1.3.6.1.4.1.50000.1.3',  INTEGER,           $opt{integer},
                '1.3.6.1.4.1.50000.1.4',  OCTET_STRING,      $opt{string},
                '1.3.6.1.4.1.50000.1.5',  OBJECT_IDENTIFIER, $opt{oid},
                '1.3.6.1.4.1.50000.1.6',  IPADDRESS,         $opt{ip},
                '1.3.6.1.4.1.50000.1.7',  COUNTER32,         $opt{counter32},
                '1.3.6.1.4.1.50000.1.8',  GAUGE32,           $opt{gauge32},
                '1.3.6.1.4.1.50000.1.9',  TIMETICKS,         $opt{timeticks},
                '1.3.6.1.4.1.50000.1.10', OPAQUE,            $opt{opaque}
            ]
        )
    } elsif ($opt{version} == 2) {
        if ($opt{inform}) {
            my $result = $session->inform_request(
                -varbindlist  => [
                    '1.3.6.1.2.1.1.3.0',      TIMETICKS,         time(),
                    '1.3.6.1.6.3.1.1.4.1.0',  OBJECT_IDENTIFIER, '1.3.6.1.4.1.50000',
                    '1.3.6.1.4.1.50000.1.3',  INTEGER,           $opt{integer},
                    '1.3.6.1.4.1.50000.1.4',  OCTET_STRING,      $opt{string},
                    '1.3.6.1.4.1.50000.1.5',  OBJECT_IDENTIFIER, $opt{oid},
                    '1.3.6.1.4.1.50000.1.6',  IPADDRESS,         $opt{ip},
                    '1.3.6.1.4.1.50000.1.7',  COUNTER32,         $opt{counter32},
                    '1.3.6.1.4.1.50000.1.8',  GAUGE32,           $opt{gauge32},
                    '1.3.6.1.4.1.50000.1.9',  TIMETICKS,         $opt{timeticks},
                    '1.3.6.1.4.1.50000.1.10', OPAQUE,            $opt{opaque}
                ]
            )
        } else {
            my $result = $session->snmpv2_trap(
                -varbindlist  => [
                    '1.3.6.1.2.1.1.3.0',      TIMETICKS,         time(),
                    '1.3.6.1.6.3.1.1.4.1.0',  OBJECT_IDENTIFIER, '1.3.6.1.4.1.50000',
                    '1.3.6.1.4.1.50000.1.3',  INTEGER,           $opt{integer},
                    '1.3.6.1.4.1.50000.1.4',  OCTET_STRING,      $opt{string},
                    '1.3.6.1.4.1.50000.1.5',  OBJECT_IDENTIFIER, $opt{oid},
                    '1.3.6.1.4.1.50000.1.6',  IPADDRESS,         $opt{ip},
                    '1.3.6.1.4.1.50000.1.7',  COUNTER32,         $opt{counter32},
                    '1.3.6.1.4.1.50000.1.8',  GAUGE32,           $opt{gauge32},
                    '1.3.6.1.4.1.50000.1.9',  TIMETICKS,         $opt{timeticks},
                    '1.3.6.1.4.1.50000.1.10', OPAQUE,            $opt{opaque}
                ]
            )
        }
    } else {
        print "Error: Unknown version - $opt{version}\n";
        exit 1
    }
    $session->close()
}

=head1 NAME

SNMPTRAPD-SENDTEST - SNMP Trap Tests

=head1 SYNOPSIS

 snmptrapd-sendtest [options] [host] [...]

=head1 DESCRIPTION

Sends sample SNMP traps.  The trap format is provided based on the user 
supplied SNMP version (v1 or v2c).  The user has control over the values 
for the variable bindings.  The following varbinds are B<always> sent.  
The user can configure the values with the options.

  VARBIND OID              SNMP ASN.1 TYPE    DEFAULT
  -----------              ---------------    -------
  1.3.6.1.4.1.50000.1.3    INTEGER            1
  1.3.6.1.4.1.50000.1.4    OCTET_STRING       String
  1.3.6.1.4.1.50000.1.5    OBJECT_IDENTIFIER  1.2.3.4.5.6.7.8.9
  1.3.6.1.4.1.50000.1.6    IPADDRESS          10.10.10.1
  1.3.6.1.4.1.50000.1.7    COUNTER32          32323232
  1.3.6.1.4.1.50000.1.8    GAUGE32            42424242
  1.3.6.1.4.1.50000.1.9    TIMETICKS          [time()]
  1.3.6.1.4.1.50000.1.10   OPAQUE             opaque data

=head1 OPTIONS

 host           The host to send to.
                DEFAULT:  (or not specified) localhost.

 -A <IP_ADDR>   SNMP IPADDRESS value.
 --ip           DEFAULT:  (or not specified) 10.10.10.1

 -C #           SNMP COUNTER32 value.
 --counter32    DEFAULT:  (or not specified) 32323232

 -co <string>   SNMP community string.
 --community    DEFAULT:  (or not specified) public

 -g #           SNMP GAUGE32 value.
 --gauge32      DEFAULT:  (or not specified) 42424242

 -I #           Send SNMPv2 InformRequest instead of SNMPv2 Trap.
 --inform       Only valid with -v 2.
                DEFAULT:  (or not specified) [SNMPv1 trap]

 -in #          SNMP INTEGER value.
 --integer      DEFAULT:  (or not specified) 1

 -oi <OID>      SNMP OBJECT_IDENTIFIER value.
 --oid          DEFAULT:  (or not specified) 1.2.3.4.5.6.7.8.9

 -q <string>    SNMP OPAQUE value.
 --opaque       DEFAULT:  (or not specified) opaque data

 -s <string>    SNMP OCTET_STRING value.
 --string       DEFAULT:  (or not specified) String

 -t #           SNMP TIMETICKS value.
 --timeticks    DEFAULT:  (or not specified) [time()]

 -v #           SNMP Version (v1 or v2c).  Use '1' or '2'.
 --version      DEFAULT:  (or not specified) 1

=head1 LICENSE

This software is released under the same terms as Perl itself.
If you don't know what that means visit L<http://perl.com/>.

=head1 AUTHOR

Copyright (C) Michael Vincent 2010

L<http://www.VinsWorld.com>

All rights reserved

=cut
