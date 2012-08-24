package Net::SNMPTrapd;

########################################################
#
# AUTHOR = Michael Vincent
# www.VinsWorld.com
#
########################################################

require 5.005;

use strict;
use Exporter;

use IO::Socket::IP -register;
use Convert::ASN1;

our $VERSION     = '0.06';
our @ISA         = qw(Exporter);
our @EXPORT      = qw();
our %EXPORT_TAGS = (
                    'all' => [qw()]
                   );
our @EXPORT_OK   = (@{$EXPORT_TAGS{'all'}});

########################################################
# Start Variables
########################################################
use constant SNMPTRAPD_DEFAULT_PORT => 162;
use constant SNMPTRAPD_RFC_SIZE     => 484;   # RFC limit
use constant SNMPTRAPD_REC_SIZE     => 1472;  # Recommended size
use constant SNMPTRAPD_MAX_SIZE     => 65467; # Actual limit (65535 - IP/UDP)

our @TRAPTYPES = qw(COLDSTART WARMSTART LINKDOWN LINKUP AUTHFAIL EGPNEIGHBORLOSS ENTERPRISESPECIFIC);
our @PDUTYPES  = qw(GetRequest GetNextRequest Response SetRequest Trap GetBulkRequest InformRequest SNMPv2-Trap Report);
our $LASTERROR;
########################################################
# End Variables
########################################################

########################################################
# Start Public Module
########################################################

sub new {
    my $self = shift;
    my $class = ref($self) || $self;

    # Default parameters
    my %params = (
        'Proto'     => 'udp',
        'LocalPort' => SNMPTRAPD_DEFAULT_PORT,
        'Timeout'   => 10,
        'Family'    => AF_INET
    );

    if (@_ == 1) {
        $LASTERROR = "Insufficient number of args - @_";
        return(undef)
    } else {
        my %cfg = @_;
        for (keys(%cfg)) {
            if (/^-?localport$/i) {
                $params{'LocalPort'} = $cfg{$_}
            } elsif (/^-?localaddr$/i) {
                $params{'LocalAddr'} = $cfg{$_}
            } elsif (/^-?family$/i) {
                if ($cfg{$_} =~ /^[46]$/) {
                    if ($cfg{$_} == 4) {
                        $params{'Family'} = AF_INET
                    } else {
                        $params{'Family'} = AF_INET6
                    }
                } else {
                    $LASTERROR = "Invalid family - $cfg{$_}";
                    return(undef)
                }
            } elsif (/^-?timeout$/i) {
                if ($cfg{$_} =~ /^\d+$/) {
                    $params{'Timeout'} = $cfg{$_}
                } else {
                    $LASTERROR = "Invalid timeout - $cfg{$_}";
                    return(undef)
                }
            }
        }
    }

    if (my $udpserver = IO::Socket::IP->new(%params)) {
        return bless {
                      %params,         # merge user parameters
                      '_UDPSERVER_' => $udpserver
                     }, $class
    } else {
        $LASTERROR = "Error opening socket for listener: $@";
        return(undef)
    }
}

sub get_trap {
    my $self  = shift;
    my $class = ref($self) || $self;

    my $trap;

    foreach my $key (keys(%{$self})) {
        # everything but '_xxx_'
        $key =~ /^\_.+\_$/ and next;
        $trap->{$key} = $self->{$key}
    }

    my $datagramsize = SNMPTRAPD_MAX_SIZE;
    if (@_ == 1) {
        $LASTERROR = "Insufficient number of args: @_";
        return(undef)
    } else {
        my %args = @_;        
        for (keys(%args)) {
            # -maxsize
            if (/^-?(?:max)?size$/i) {
                if ($args{$_} =~ /^\d+$/) {
                    if (($args{$_} >= 1) && ($args{$_} <= SNMPTRAPD_MAX_SIZE)) {
                        $datagramsize = $args{$_}
                    }
                } elsif ($args{$_} =~ /^rfc$/i) {
                    $datagramsize = SNMPTRAPD_RFC_SIZE
                } elsif ($args{$_} =~ /^rec(?:ommend)?(?:ed)?$/i) {
                    $datagramsize = SNMPTRAPD_REC_SIZE
                } else {
                    $LASTERROR = "Not a valid size: $args{$_}";
                    return(undef)
                }
            # -timeout
            } elsif (/^-?timeout$/i) {
                if ($args{$_} =~ /^\d+$/) {
                    $trap->{'Timeout'} = $args{$_}
                } else {
                    $LASTERROR = "Invalid timeout - $args{$_}";
                    return(undef)
                }
            }
        }
    }

    my $Timeout = $trap->{'Timeout'};
    my $udpserver = $self->{'_UDPSERVER_'};
    my $datagram;

    # vars for IO select
    my ($rin, $rout, $ein, $eout) = ('', '', '', '');
    vec($rin, fileno($udpserver), 1) = 1;

    # check if a message is waiting
    if (select($rout=$rin, undef, $eout=$ein, $Timeout)) {
        # read the message
        if ($udpserver->recv($datagram, $datagramsize)) {

            $trap->{'_TRAP_'}{'PeerPort'} = $udpserver->peerport;
            $trap->{'_TRAP_'}{'PeerAddr'} = $udpserver->peerhost;
            $trap->{'_TRAP_'}{'datagram'} = $datagram;

            return bless $trap, $class
        } else {
            $LASTERROR = sprintf "Socket RECV error: %s", $udpserver->sockopt(SO_ERROR);
            return(undef)
        }
    } else {
        $LASTERROR = "Timed out waiting for datagram";
        return(0)
    }
}

sub process_trap {
    my $self = shift;
    my $class = ref($self) || $self;

    ### Allow to be called as subroutine
    # Net::SNMPTrapd->process_trap($data)
    if (($self eq $class) && ($class eq __PACKAGE__)) {
        my %th;
        $self = \%th;
        ($self->{'_TRAP_'}{'datagram'}) = @_
    }
    # Net::SNMPTrapd::process_trap($data)
    if ($class ne __PACKAGE__) {
        my %th;
        $self = \%th;
        ($self->{'_TRAP_'}{'datagram'}) = $class;
        $class = __PACKAGE__
    }

    my $RESPONSE = 1; # Default is to send Response PDU for InformRequest
    # If more than 1 argument, parse the options
    if (@_ != 1) {
        my %args = @_;
        for (keys(%args)) {
            # -datagram
            if ((/^-?data(?:gram)?$/i) || (/^-?pdu$/i)) {
                $self->{'_TRAP_'}{'datagram'} = $args{$_}
            # -noresponse
            } elsif (/^-?noresponse$/i) {
                if (($args{$_} =~ /^\d+$/) && ($args{$_} > 0)) {
                    $RESPONSE = 0
                }
            }
        }
    }

    my $asn = new Convert::ASN1;

    ### Process first part of PDU (excluding varbinds)
    my $trap1;
    $asn->prepare("
        PDU ::= SEQUENCE {
            version   INTEGER,
            community STRING,
            pdu_type  PDUs
        }
        PDUs ::= CHOICE {
            trap           Trap-PDU,
            inform-request InformRequest-PDU,
            snmpv2-trap    SNMPv2-Trap-PDU
        }
        Trap-PDU          ::= [4] IMPLICIT PDUv1
        InformRequest-PDU ::= [6] IMPLICIT PDUv2
        SNMPv2-Trap-PDU   ::= [7] IMPLICIT PDUv2
        PDUv1 ::= SEQUENCE {
            ent_OID         OBJECT IDENTIFIER,
            agentaddr       [APPLICATION 0] STRING,
            generic_trap    INTEGER,
            specific_trap   INTEGER,
            timeticks       [APPLICATION 3] INTEGER,
            ber_varbindlist ANY
        }
        PDUv2 ::= SEQUENCE {
            request_ID      INTEGER,
            error_status    INTEGER,
            error_index     INTEGER,
            ber_varbindlist ANY
        }
    ");
    my $found = $asn->find('PDU');
    if (!defined($trap1 = $found->decode($self->{'_TRAP_'}{'datagram'}))) {
        $LASTERROR = sprintf "Error decoding PDU - %s", (defined($asn->error) ? $asn->error : "Unknown Convert::ASN1->decode() error.  Consider $class dump()");
        return(undef)
    }
    #DEBUG: use Data::Dumper; print Dumper \$trap1;

    # Only understand SNMPv1 (0) and v2c (1)
    if ($trap1->{'version'} > 1) {
        $LASTERROR = sprintf "Unrecognized SNMP version - %i", $trap1->{'version'};
        return(undef)
    }

    # set PDU Type for later use
    my $pdutype = sprintf "%s", keys(%{$trap1->{'pdu_type'}});

    ### Process varbinds
    my $trap2;
    $asn->prepare("
        varbind SEQUENCE OF SEQUENCE {
            oid OBJECT IDENTIFIER,
            choice CHOICE {
                val_integer   INTEGER,
                val_string    STRING,
                val_OID       OBJECT IDENTIFIER,
                val_IpAddr    [APPLICATION 0] STRING,
                val_Counter32 [APPLICATION 1] INTEGER,
                val_Guage32   [APPLICATION 2] INTEGER,
                val_TimeTicks [APPLICATION 3] INTEGER,
                val_Opaque    [APPLICATION 4] STRING,
                val_Counter64 [APPLICATION 6] INTEGER
            }
        }
    ");
    if (!defined($trap2 = $asn->decode($trap1->{'pdu_type'}->{$pdutype}->{'ber_varbindlist'}))) {
        $LASTERROR = sprintf "Error decoding varbinds - %s", (defined($asn->error) ? $asn->error : "Unknown Convert::ASN1->decode() error.  Consider $class dump()");
        return(undef)
    }
    #DEBUG: use Data::Dumper; print Dumper \$trap2;

    ### Assemble decoded trap object
    # Common
    $self->{'_TRAP_'}{'version'} = $trap1->{'version'};
    $self->{'_TRAP_'}{'community'} = $trap1->{'community'};
    if ($pdutype eq 'trap') {
        $self->{'_TRAP_'}{'pdu_type'} = 4
    
    } elsif ($pdutype eq 'inform-request') {
        $self->{'_TRAP_'}{'pdu_type'} = 6;

        # send response for InformRequest
        if ($RESPONSE) {
            if ((my $r = &_InformRequest_Response(\$self, \$trap1, $pdutype)) ne 'OK') {
                $LASTERROR = sprintf "Error sending InformRequest Response - %s", $r;
                return(undef)
            }
        }

    } elsif ($pdutype eq 'snmpv2-trap') { 
        $self->{'_TRAP_'}{'pdu_type'} = 7
    }

    # v1
    if ($trap1->{'version'} == 0) {
        $self->{'_TRAP_'}{'ent_OID'}       =           $trap1->{'pdu_type'}->{$pdutype}->{'ent_OID'};
        $self->{'_TRAP_'}{'agentaddr'}     = inet_ntoa($trap1->{'pdu_type'}->{$pdutype}->{'agentaddr'});
        $self->{'_TRAP_'}{'generic_trap'}  =           $trap1->{'pdu_type'}->{$pdutype}->{'generic_trap'};
        $self->{'_TRAP_'}{'specific_trap'} =           $trap1->{'pdu_type'}->{$pdutype}->{'specific_trap'};
        $self->{'_TRAP_'}{'timeticks'}     =           $trap1->{'pdu_type'}->{$pdutype}->{'timeticks'};

    # v2c
    } elsif ($trap1->{'version'} == 1) {
        $self->{'_TRAP_'}{'request_ID'}   = $trap1->{'pdu_type'}->{$pdutype}->{'request_ID'};
        $self->{'_TRAP_'}{'error_status'} = $trap1->{'pdu_type'}->{$pdutype}->{'error_status'};
        $self->{'_TRAP_'}{'error_index'}  = $trap1->{'pdu_type'}->{$pdutype}->{'error_index'};
    }

    # varbinds
    my @varbinds;
    for my $i (0..$#{$trap2->{'varbind'}}) {
        my %oidval;
        for (keys(%{$trap2->{'varbind'}[$i]->{'choice'}})) {
            $oidval{$trap2->{'varbind'}[$i]->{'oid'}} = (
                                                         defined($trap2->{'varbind'}[$i]->{'choice'}{$_}) ? 
                                                           (($_ eq 'val_IpAddr') ? 
                                                             inet_ntoa($trap2->{'varbind'}[$i]->{'choice'}{$_}) : 
                                                           $trap2->{'varbind'}[$i]->{'choice'}{$_}) : 
                                                         ""
                                                        )
        }
        push @varbinds, \%oidval
    }
    $self->{'_TRAP_'}{'varbinds'} = \@varbinds;

    return bless $self, $class
}

sub server {
    my $self = shift;
    return $self->{'_UDPSERVER_'}
}

sub datagram {
    my ($self, $arg) = @_;

    if (defined($arg) && ($arg >= 1)) {
        return unpack ('H*', $self->{'_TRAP_'}{'datagram'})
    } else {
        return $self->{'_TRAP_'}{'datagram'}
    }
}

sub peeraddr {
    my $self = shift;
    return $self->{'_TRAP_'}{'PeerAddr'}
}

sub peerport {
    my $self = shift;
    return $self->{'_TRAP_'}{'PeerPort'}
}

sub version {
    my $self = shift;
    return $self->{'_TRAP_'}{'version'} + 1
}

sub community {
    my $self = shift;
    return $self->{'_TRAP_'}{'community'}
}

sub pdu_type {
    my ($self, $arg) = @_;

    if (defined($arg) && ($arg >= 1)) {
        return $self->{'_TRAP_'}{'pdu_type'}
    } else {
        return $PDUTYPES[$self->{'_TRAP_'}{'pdu_type'}]
    }
}

sub ent_OID {
    my $self = shift;
    return $self->{'_TRAP_'}{'ent_OID'}
}

sub agentaddr {
    my $self = shift;
    return $self->{'_TRAP_'}{'agentaddr'}
}

sub generic_trap {
    my ($self, $arg) = @_;

    if (defined($arg) && ($arg >= 1)) {
        return $self->{'_TRAP_'}{'generic_trap'}
    } else {
        return $TRAPTYPES[$self->{'_TRAP_'}{'generic_trap'}]
    }
}

sub specific_trap {
    my $self = shift;
    return $self->{'_TRAP_'}{'specific_trap'}
}

sub timeticks {
    my $self = shift;
    return $self->{'_TRAP_'}{'timeticks'}
}

sub request_ID {
    my $self = shift;
    return $self->{'_TRAP_'}{'request_ID'}
}

sub error_status {
    my $self = shift;
    return $self->{'_TRAP_'}{'error_status'}
}

sub error_index {
    my $self = shift;
    return $self->{'_TRAP_'}{'error_index'}
}

sub varbinds {
    my $self = shift;
    return $self->{'_TRAP_'}{'varbinds'}
}

sub error {
    return($LASTERROR)
}

sub dump {
    my $self = shift;
    my $class = ref($self) || $self;

    ### Allow to be called as subroutine
    # Net::SNMPTrapd->dump($datagram)
    if (($self eq $class) && ($class eq __PACKAGE__)) {
        my %th;
        $self = \%th;
        ($self->{'_TRAP_'}{'datagram'}) = @_
    }
    # Net::SNMPTrapd::dump($datagram)
    if ($class ne __PACKAGE__) {
        my %th;
        $self = \%th;
        ($self->{'_TRAP_'}{'datagram'}) = $class;
        $class = __PACKAGE__
    }

    if (defined($self->{'_TRAP_'}{'datagram'})) {
        Convert::ASN1::asn_dump($self->{'_TRAP_'}{'datagram'});
        Convert::ASN1::asn_hexdump($self->{'_TRAP_'}{'datagram'});
    } else {
        $LASTERROR = "Missing datagram to dump";
        return(undef)
    }

    return 1
}

########################################################
# End Public Module
########################################################

########################################################
# Start Private subs
########################################################

sub _InformRequest_Response {

    my ($self, $trap1, $pdutype) = @_;

    my $asn = new Convert::ASN1;
    $asn->prepare("
        PDU ::= SEQUENCE {
            version   INTEGER,
            community STRING,
            pdu_type  [2] IMPLICIT PDUv2
        }
        PDUv2 ::= SEQUENCE {
            request_ID      INTEGER,
            error_status    INTEGER,
            error_index     INTEGER,
            ber_varbindlist ANY
        }
    ");
    my $found = $asn->find('PDU');
    my $buffer = $found->encode(
        version      => $$trap1->{'version'},
        community    => $$trap1->{'community'},
        pdu_type     => {
            request_ID      => $$trap1->{'pdu_type'}->{$pdutype}->{'request_ID'},
            error_status    => $$trap1->{'pdu_type'}->{$pdutype}->{'error_status'},
            error_index     => $$trap1->{'pdu_type'}->{$pdutype}->{'error_index'},
            ber_varbindlist => $$trap1->{'pdu_type'}->{$pdutype}->{'ber_varbindlist'}
        }
    );
    if (!defined($buffer)) {
        return $asn->error
    }
    #DEBUG print "BUFFER = $buffer\n";
    if ($$self->{'_TRAP_'}->{'PeerAddr'} eq "") {
        return "Peer Addr undefined"
    }
    if ($$self->{'_TRAP_'}->{'PeerPort'} == 0) {
        return "Peer Port undefined"
    }

    my $socket = IO::Socket::IP->new(
                                     Proto     => "udp",
                                     PeerAddr  => $$self->{'_TRAP_'}->{'PeerAddr'},
                                     PeerPort  => $$self->{'_TRAP_'}->{'PeerPort'},
                                     # LocalPort should be set, but creates error.
                                     # Tried setting ReusePort on initial server,
                                     # but not implemented on Windows.  What to do?
                                     #LocalPort => SNMPTRAPD_DEFAULT_PORT,
                                     Family    => $$self->{'Family'}
                                    ) || return "Can't create Response socket";
    $socket->send($buffer);
    close $socket;
    return ("OK")
}

########################################################
# End Private subs
########################################################

1;

__END__

########################################################
# Start POD
########################################################

=head1 NAME

Net::SNMPTrapd - Perl implementation of SNMP Trap Listener

=head1 SYNOPSIS

  use Net::SNMPTrapd;

  my $snmptrapd = Net::SNMPTrapd->new()
    or die "Error creating SNMPTrapd listener: ", Net::SNMPTrapd->error;

  while (1) {
      my $trap = $snmptrapd->get_trap();

      if (!defined($trap)) {
          printf "$0: %s\n", Net::SNMPTrapd->error;
          exit 1
      } elsif ($trap == 0) {
          next
      }

      if (!defined($trap->process_trap())) {
          printf "$0: %s\n", Net::SNMPTrapd->error
      } else {
          printf "%s\t%i\t%i\t%s\n", 
                 $trap->peeraddr, 
                 $trap->peerport, 
                 $trap->version, 
                 $trap->community
      }
  }

=head1 DESCRIPTION

Net::SNMPTrapd is a class implementing a simple SNMP Trap listener in 
Perl.  Net::SNMPTrapd will accept traps on the default SNMP Trap port 
(UDP 162) and attempt to decode them.  Net::SNMPTrapd supports SNMP v1 
and v2c traps and SNMPv2 InformRequest and implements the Reponse.

Net::SNMPTrapd uses Convert::ASN1 by Graham Barr to do the decoding.

=head1 METHODS

=head2 new() - create a new Net::SNMPTrapd object

  my $snmptrapd = Net::SNMPTrapd->new([OPTIONS]);

Create a new Net::SNMPTrapd object with OPTIONS as optional parameters.
Valid options are:

  Option     Description                            Default
  ------     -----------                            -------
  -Family    Address family IPv4/IPv6                     4
             given as integer 4 or 6
  -LocalAddr Interface to bind to                       any
  -LocalPort Port to bind server to                     162
  -timeout   Timeout in seconds for socket               10
             operations and to wait for request

Allows the following accessors to be called.

=head3 server() - return IO::Socket::IP object for server

  $snmptrapd->server();

Return B<IO::Socket::IP> object for the created server.
All B<IO::Socket::IP> accessors can then be called.

=head2 get_trap() - listen for SNMP traps

  my $trap = $snmptrapd->get_trap([OPTIONS]);

Listen for SNMP traps.  Timeout after default or user specified
timeout set in C<new> method and return '0'.  If trap is received
before timeout, return is defined.  Return is not defined if error
encountered.

Valid options are:

  Option     Description                            Default
  ------     -----------                            -------
  -maxsize   Max size in bytes of acceptable PDU.     65467
             Value can be integer 1 <= # <= 65467.
             Keywords: 'RFC'         =  484
                       'recommended' = 1472
  -timeout   Timeout in seconds to wait for              10
             request.  Overrides value set with
             new().

Allows the following accessors to be called.

=head3 peeraddr() - return remote address from SNMP trap

  $trap->peeraddr();

Return peer address value from a received (C<get_trap()>)
SNMP trap.  This is the address from the IP header on the UDP
datagram.

=head3 peerport() - return remote port from SNMP trap

  $trap->peerport();

Return peer port value from a received (C<get_trap()>)
SNMP trap.  This is the port from the IP header on the UDP
datagram.

=head3 datagram() - return datagram from SNMP trap

  $trap->datagram([1]);

Return the raw datagram from a received (C<get_trap()>)
SNMP trap.  This is ASN.1 encoded datagram.  For a hex
dump, use the optional boolean argument.

=head2 process_trap() - process received SNMP trap

  $trap->process_trap([OPTIONS]);

Process a received SNMP trap.  Decodes the received (C<get_trap()>)
PDU.  Varbinds are extracted and decoded.  If PDU is SNMPv2
InformRequest, the Response PDU is generated and sent to IP 
address and UDP port found in the original datagram header 
(C<get_trap()> methods C<peeraddr()> and C<peerport()>).

Called with one argument, interpreted as the datagram to process.  
Valid options are:

  Option      Description                           Default
  ------      -----------                           -------
  -datagram   Datagram to process                   -Provided by
                                                     get_trap()-
  -noresponse Binary switch (0|1) meaning 'Do not    0
              send Response-PDU for InformRequest'  -Send Response-

This can also be called as a procedure if one is inclined to write 
their own UDP listener instead of using C<get_trap()>.  For example: 

  $sock = IO::Socket::IP->new( blah blah blah );
  $sock->recv($datagram, 1500);
  # process the ASN.1 encoded datagram in $datagram variable
  $trap = Net::SNMPTrapd->process_trap($datagram);

or

  # process the ASN.1 encoded datagram in $datagram variable
  # Do *NOT* send Response PDU if trap comes as InformRequest PDU
  $trap = Net::SNMPTrapd->process_trap(
                                       -datagram   => $datagram,
                                       -noresponse => 1
                                      );

In any instantiation, allows the following accessors to be called.

=head3 version() - return version from SNMP trap

  $trap->version();

Return SNMP Trap version from a received and processed 
(C<process_trap()>) SNMP trap.

B<NOTE:>  This module only supports SNMP v1 and v2c.

=head3 community() - return community from SNMP trap

  $trap->community();

Return community string from a received and processed 
(C<process_trap()>) SNMP trap.

=head3 pdu_type() - return PDU type from SNMP trap

  $trap->pdu_type([1]);

Return PDU type from a received and processed (C<process_trap()>) 
SNMP trap.  This is the text representation of the PDU type.  
For the raw number, use the optional boolean argument.

=head3 varbinds() - return varbinds from SNMP trap

  $trap->varbinds();

Return varbinds from a received and processed 
(C<process_trap()>) SNMP trap.  This returns a pointer to an array 
containing a hash as each array element.  The key/value pairs of 
each hash are the OID/value pairs for each varbind in the received 
trap.

  [{OID => value}]
  [{OID => value}]
  ...
  [{OID => value}]

An example extraction of the varbind data is provided:

  for my $vals (@{$trap->varbinds}) {
      for (keys(%{$vals})) {
          $p .= sprintf "%s: %s; ", $_, $vals->{$_}
      }
  }
  print "$p\n";

The above code will print the varbinds as:

  OID: value; OID: value; OID: value; [...]

=head3 SNMP v1 SPECIFIC

The following methods are SNMP v1 trap specific.

=head3 ent_OID() - return enterprise OID from SNMP v1 trap

  $trap->ent_OID();

Return enterprise OID from a received and processed 
(C<process_trap()>) SNMP v1 trap.

=head3 agentaddr() - return agent address from SNMP v1 trap

  $trap->agentaddr();

Return agent address from a received and processed 
(C<process_trap()>) SNMP v1 trap.

=head3 generic_trap() - return generic trap from SNMP v1 trap

  $trap->generic_trap([1]);

Return generic trap type from a received and processed 
(C<process_trap()>) SNMP v1 trap.  This is the text representation 
of the generic trap type.  For the raw number, use the optional 
boolean argument.

=head3 specific_trap() - return specific trap from SNMP v1 trap

  $trap->specific_trap();

Return specific trap type from a received and processed 
(C<process_trap()>) SNMP v1 trap.

=head3 timeticks() - return timeticks from SNMP v1 trap

  $trap->timeticks();

Return timeticks from a received and processed 
(C<process_trap()>) SNMP v1 trap.

=head3 SNMP v2c SPECIFIC

The following methods are SNMP v2c trap specific.

=head3 request_ID() - return request ID from SNMP v2c trap

  $trap->request_ID();

Return request ID from a received and processed 
(C<process_trap()>) SNMP v2c trap.

=head3 error_status() - return error status from SNMP v2c trap

  $trap->error_status();

Return error_status from a received and processed 
(C<process_trap()>) SNMP v2c trap.

=head3 error_index() - return error index from SNMP v2c trap

  $trap->error_index();

Return error index from a received and processed 
(C<process_trap()>) SNMP v2c trap.

=head2 error() - return last error

  printf "Error: %s\n", Net::SNMPTrapd->error;

Return last error.

=head2 dump() - Convert::ASN1 direct decode and hex dump

  $trap->dump();

or

  Net::SNMPTrapd->dump($datagram);

This does B<not> use any of the Net::SNMPTrapd ASN.1 structures; 
rather, it uses the Convert::ASN1 module debug routines (C<asn_dump> 
and C<asn_hexdump>) to attempt a decode and hex dump of the supplied 
datagram.  This is helpful to eliminate the entire Net::SNMPTrapd 
module code when troubleshooting issues with decoding and focus solely 
on the ASN.1 decode of the given datagram.

Called as a method, operates on the value returned from the 
C<datagram()> method.  Called as a subroutine, operates on the 
value passed.

Output is printed directly to STDERR.  Return is defined unless there 
is an error encountered in getting the datagram to operate on.

=head1 EXPORT

None by default.

=head1 EXAMPLES

This distribution comes with several scripts (installed to the default
"bin" install directory) that not only demonstrate example uses but also
provide functional execution.

=head1 SEE ALSO

Convert::ASN1

=head1 LICENSE

This software is released under the same terms as Perl itself.
If you don't know what that means visit L<http://perl.com/>.

=head1 AUTHOR

Copyright (C) Michael Vincent 2010

L<http://www.VinsWorld.com>

All rights reserved

=cut
