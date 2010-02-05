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

use IO::Socket;
use Convert::ASN1;

our $VERSION     = '0.03';
our @ISA         = qw(Exporter);
our @EXPORT      = qw();
our %EXPORT_TAGS = (
                    'all' => [qw(@TRAPTYPES)]
                   );
our @EXPORT_OK   = (@{$EXPORT_TAGS{'all'}});

########################################################
# Start Variables
########################################################
use constant SNMPTRAPD_DEFAULT_PORT => 162;
use constant SNMPTRAPD_MAX_SIZE     => 1024;

our @TRAPTYPES = qw(COLDSTART WARMSTART LINKDOWN LINKUP AUTHFAIL EGPNEIGHBORLOSS ENTERPRISESPECIFIC);
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

    my %params = (
        'Proto'     => 'udp',
        'LocalPort' => SNMPTRAPD_DEFAULT_PORT,
        'Timeout'   => 10
    );

    my %cfg;
    if (@_ == 1) {
        $LASTERROR = "Insufficient number of args - @_";
        return(undef)
    } else {
        %cfg = @_;
        for (keys(%cfg)) {
            if (/^-?localport$/i) {
                $params{'LocalPort'} = $cfg{$_}
            } elsif (/^-?localaddr$/i) {
                $params{'LocalAddr'} = $cfg{$_}
            } elsif (/^-?timeout$/i) {
                $params{'Timeout'} = $cfg{$_}
            }
        }
    }

    if (my $udpserver = IO::Socket::INET->new(%params)) {
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

    my $Timeout = $trap->{'Timeout'};
    my $udpserver = $self->{'_UDPSERVER_'};

    my $datagram;

    # vars for IO select
    my ($rin, $rout, $ein, $eout) = ('', '', '', '');
    vec($rin, fileno($udpserver), 1) = 1;

    # check if a message is waiting
    if (select($rout=$rin, undef, $eout=$ein, $Timeout)) {
        # read the message
        if ($udpserver->recv($datagram, SNMPTRAPD_MAX_SIZE)) {

            my ($peerport, $peeraddr) = sockaddr_in($udpserver->peername);
            $trap->{'_TRAP_'}{'PeerPort'} = $peerport;
            $trap->{'_TRAP_'}{'PeerAddr'} = inet_ntoa($peeraddr);
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

    ### Process first part of datagram
    my $asn = new Convert::ASN1;
    $asn->prepare("
        SEQUENCE {
            version INTEGER,
            community STRING,
            rest_of_pdu ANY
        }
    ");
    my $trap1 = $asn->decode($self->{'_TRAP_'}{'datagram'});
    #DEBUG: print "REST = $trap1->{'rest_of_pdu'}\n";

    ### Process second part of datagram
    # SNMP version 1
    if ($trap1->{'version'} == 0) {

        # Instead of getting the varbindlist here and in v2c, we'll just put the rest 
        # of the packet into the $trap{'ber_varbindlist'} variable and deal with it later.
        $asn->prepare("
            Trap_PDU ::= [CONTEXT 4] SEQUENCE {
                ent_OID         OBJECT IDENTIFIER,
                agentaddr       [APPLICATION 0] STRING,
                generic_trap    INTEGER,
                specific_trap   INTEGER,
                timeticks       [APPLICATION 3] INTEGER,
                ber_varbindlist ANY
            }
        ")

    # SNMP version 2c
    } elsif ($trap1->{'version'} == 1) {
        $asn->prepare("
            Trap2_PDU ::= [CONTEXT 7] SEQUENCE {
                request_ID      INTEGER,
                error_status    INTEGER,
                error_index     INTEGER,
                ber_varbindlist ANY
            }
        ")
    # SNMP version unknown
    } else {
        $LASTERROR = sprintf "Unknown Trap version - %s", $trap1->{'version'};
        return(undef)
    }
    my $trap2 = $asn->decode($trap1->{'rest_of_pdu'});
    #DEBUG: print "REST = $trap2->{'ber_varbindlist'}\n";

    ### Process third part of datagram
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
    my $trap3 = $asn->decode($trap2->{'ber_varbindlist'});
    #DEBUG: use Data::Dumper; print Dumper \$trap3;

    ### Assemble decoded trap object
    # Common
    $self->{'_TRAP_'}{'version'} = $trap1->{'version'};
    $self->{'_TRAP_'}{'community'} = $trap1->{'community'};

    if ($trap1->{'version'} == 0) {
        # v1
        $self->{'_TRAP_'}{'ent_OID'} = $trap2->{'ent_OID'};
        $self->{'_TRAP_'}{'agentaddr'} = inet_ntoa($trap2->{'agentaddr'});
        $self->{'_TRAP_'}{'generic_trap'} = $trap2->{'generic_trap'};
        $self->{'_TRAP_'}{'specific_trap'} = $trap2->{'specific_trap'};
        $self->{'_TRAP_'}{'timeticks'} = $trap2->{'timeticks'};
    } elsif ($trap1->{'version'} == 1) {
        # v2c
        $self->{'_TRAP_'}{'request_ID'} = $trap2->{'request_ID'};
        $self->{'_TRAP_'}{'error_status'} = $trap2->{'error_status'};
        $self->{'_TRAP_'}{'error_index'} = $trap2->{'error_index'};
    } else {}

    # varbinds
    my @varbinds;
    for my $i (0..$#{$trap3->{'varbind'}}) {
        my %oidval;
        for (keys(%{$trap3->{'varbind'}[$i]->{'choice'}})) {
            $oidval{$trap3->{'varbind'}[$i]->{'oid'}} = (defined($trap3->{'varbind'}[$i]->{'choice'}{$_}) ? (($_ eq 'val_IpAddr') ? inet_ntoa($trap3->{'varbind'}[$i]->{'choice'}{$_}) : $trap3->{'varbind'}[$i]->{'choice'}{$_}) : "")
        }
        push @varbinds, \%oidval
    }
    $self->{'_TRAP_'}{'varbinds'} = \@varbinds;

    return bless $self, $class
}

sub datagram {
    my $self = shift;
    return $self->{'_TRAP_'}{'datagram'}
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

########################################################
# End Public Module
########################################################

########################################################
# Start Private subs
########################################################

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
    or die "Error creating SNMPTrapd listener: %s", Net::SNMPTrapd->error;

  while (1) {
      my $trap;
      if (!($trap = $snmptrapd->get_trap())) { next }

      if (!(defined($trap->process_trap()))) {
          printf "$0: %s\n", Net::SNMPTrapd->error
      } else {
          printf "%s\t%i\t%i\t%s\n", 
                 $message->peeraddr, 
                 $message->peerport, 
                 $message->version, 
                 $message->community
      }
  }

=head1 DESCRIPTION

Net::SNMPTrapd is a class implementing a simple SNMP Trap listener in 
Perl.  Net::SNMPTrapd will accept traps on the default SNMP Trap port 
(UDP 162) and attempts to decode them.  Net::SNMPTrapd supports SNMP v1 
and v2c traps.

Net::SNMPTrapd uses Convert::ASN1 by Graham Barr to do the decoding.

=head1 METHODS

=head2 new() - create a new Net::SNMPTrapd object

  my $snmptrapd = new Net::SNMPTrapd([OPTIONS]);

or

  my $snmptrapd = Net::SNMPTrapd->new([OPTIONS]);

Create a new Net::SNMPTrapd object with OPTIONS as optional parameters.
Valid options are:

  Option     Description                            Default
  ------     -----------                            -------
  -LocalAddr Interface to bind to                       any
  -LocalPort Port to bind server to                     162
  -Timeout   Timeout in seconds to wait for request      10

=head2 get_trap() - listen for SNMP traps

  my $trap = $snmptrapd->get_trap();

Listen for a SNMP trap.  Timeout after default or user specified 
timeout set in C<new> method and return '0'; else, return is defined.

=head2 process_trap() - process received SNMP trap

  $trap->process_trap();

Process a received SNMP trap.  Varbinds are extracted and processed 
as SNMP ASN.1 types.

This can also be called as a procedure if one is inclined to write 
their own UDP listener instead of using C<get_trap()>.  For example: 

  $sock = IO::Socket::INET->new( blah blah blah );
  $sock->recv($buffer, 1500);
  $trap = Net::SNMPTrapd->process_trap($buffer);

In either instantiation, allows the following methods to be called.

=head3 datagram() - return datagram from SNMP trap

  $trap->datagram();

Return the raw datagram received from a processed (C<process_trap()>) 
SNMP trap.

=head3 peeraddr() - return remote address from SNMP trap

  $trap->peeraddr();

Return peer address value from a received and processed 
(C<process_trap()>) SNMP trap.  This is the address from the IP 
header on the UDP datagram.

=head3 peerport() - return remote port from SNMP trap

  $trap->peerport();

Return peer port value from a received and processed 
(C<process_trap()>) SNMP trap.  This is the port from the IP 
header on the UDP datagram.

=head3 version() - return version from SNMP trap

  $trap->version();

Return SNMP Trap version from a received and processed 
(C<process_trap()>) SNMP trap.

B<NOTE:>  This module only decodes SNMP v1 and v2c traps.

=head3 community() - return community from SNMP trap

  $trap->community();

Return community string from a received and processed 
(C<process_trap()>) SNMP trap.

=head3 varbinds() - return varbinds from SNMP trap

  $trap->varbinds();

Return varbinds from a received and processed 
(C<process_trap()>) SNMP trap.  This returns a pointer to an array 
containing a hash as each array element.  The key/value pairs of 
each hash are the OID/value pairs for each varbind in the received 
trap.

An example extraction of the varbind data is provided:

  for my $vals (@{$trap->varbinds}) {
      for (keys(%{$vals})) {
          $p .= sprintf "%s: %s; ", $_, $vals->{$_}
      }
  }
  print "$p\n";

The above code will print the varbinds as:

  OID: val; OID: val; OID: val; [...]

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

=head1 EXPORT

None by default.

=head1 EXAMPLES

=head2 Simple SNMP Trap Server

This example implements a simple SNMP Trap server that listens on the 
default port and prints received messages to the console.

  use Net::SNMPTrapd;

  my $snmptrapd = Net::SNMPTrapd->new()
    or die "Error creating SNMPTrapd listener: %s", Net::SNMPTrapd->error;

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
            # Here, one could use a MIB translation table or 
            # Perl module to map OID's ($_) to text and values 
            # ($varbind->{$_}) to applicable meanings or metrics.
            # This example just prints -> OID: val; OID: val; ...
                  $p .= sprintf "%s: %s; ", $_, $varbind->{$_}
              }
          }
          print "$p\n"
      }
  }

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
