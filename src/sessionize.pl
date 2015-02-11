#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# sessionize.pl - Group page requests into sessions
# $Revision: 1.8 $
#
# Divides a web log into single sessions according to a user specified
# maximal page view time. If session identifying cookies are present, these
# are used instead of the page view time heuristic.  Later, this script
# should be extended to use cookies or something like that for identifying
# single sessions more exactly
# ========================================================================
#
# Copyright (C) 2000-2005  Carsten Pohle (cp AT cpohle de)
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package WUMprep;
use FindBin;
use lib "$FindBin::Bin";
use WUMprep;
use WUMprep::Config;
use POSIX qw(difftime mktime);
use HTTP::Date;
use URI;
use strict;

my $host;         # an alias to host_dns or host_id
my %fieldMap;     # take the field mapping, either for file or warehouse
my $currentId;    # stores the current session id
my $operationMode;
my $inData;       # Required when parsing ARFF files
my $inputFile;
my $outputFile;

# Possible values for the host status field. The host status is binary coded,
# i.e., if bit 1 is set, we have IP addresses, and if bit 2 is set,
# we have resolved host names.
my $HOST_IP   = 1;
my $HOST_NAME = 2;

#$config = new WUMprep::Config;
my $config;          # set in &parseCommandLine

#my $parser = new WUMprep::LogfileParser;
my $parser;       # set in &parseCommandLine


&parseCommandLine;

# The session ID starts with a randomly chosen number - this should
# guarantee that we don't cause any conflicts when combining different logs
srand;
my $idStem = sprintf( "%06d", rand 999999 );

my $cookieName                = $config->sessionizeIdCookie;
my $sessionizeMaxPageViewTime = $config->sessionizeMaxPageViewTime;

$| = 1;

if ( $operationMode eq 'filter' ) {

  # use stdin/stdout
  open( INFILE,  "-" );
  open( OUTFILE, ">-" );
  $inputFile = 'from standard input';
  &main;
}
else {

  # run in batch mode
  if ( $operationMode eq 'file' ) {
    %fieldMap = %{ $parser->fieldMap };
  }
  else {
    die "$0\nERROR: Unknown operation mode: " . $operationMode . "\n";
  }

  # Our nextLine routine places a hash with the cookies at
  # the end of each array, here we map the index.
  $fieldMap{cookieHash} = scalar( keys(%fieldMap) );

  foreach $inputFile ( $config->inputLogs ) {
    if ( $operationMode eq 'file' ) {
      $inputFile  = longestFilename($inputFile);
      $outputFile = $inputFile . $config->sessionizeOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      $host = defined( $fieldMap{host_ip} ) ? 'host_ip' : 'host_dns';
      &main;
      close INFILE;
      close OUTFILE;
    }
  }
}

sub main {
  my $logLine;
  my $referrerLine;
  my $uri;
  my $query;
  my $cookieId;
  my $progressCount;
  my $newSession;
  my %serverFamily = $config->serverFamily;
  my $currentTimestamp;
  my %lastTimestamp;
  my $fullCookieName;
  my %query;
  my %sessionId;
  my %sessionIndex;
  my $hostId;
  my $lastHost;

  printf( STDERR "$0:\nDefining sessions in log $inputFile ...\n" );

  while ( $logLine = &nextLine ) {
    # Actually, we rely on the log being in "extended cookie" format.
    # THIS SCRIPT MIGHT NOT WORK WITH OTHER LOG FILE FORMATS! (At least
    # it is untested as of Nov. 4th, 2003)

    if ( exists( $$logLine{ts_seconds} ) ) {
      $currentTimestamp = mktime(
        $$logLine{ts_seconds}, $$logLine{ts_minutes},
        $$logLine{ts_hour},    $$logLine{ts_day},
        $$logLine{ts_month},   $$logLine{ts_year} - 1900
      );
    }
    else {

      # we assume to have an RFC 1123 timestamp
      $currentTimestamp = str2time( $$logLine{ts} );
    }

    #Remove everything after the word  via - to remove proxy lines
    $$logLine{agent} =~ s/[\+ ]via[\+ ].*//;

    # Check if we have an session cookie. First, get the exact name of the
    # cookie (some web servers change the cookie name from time to time,
    # e.g., from ASPSESSIONIDABCDE to ASPSESSIONIDFGHIJ).

    if ( exists( $$logLine{cookie} ) && $cookieName && %{ $$logLine{cookie} } )
    {
      ($fullCookieName) = grep /$cookieName/, keys( %{ $$logLine{cookie} } );

      $cookieId = ${ $$logLine{cookie} }{$fullCookieName}
        if ( $fullCookieName ne '' );
    }

    # Maybe the session ID is encoded as URI query parameter
    if ( $cookieId eq '' && $cookieName ) {
      $uri      = URI->new( $$logLine{path} );
      %query    = $uri->query_form();
      $cookieId = $query{$cookieName};
    }

    if ( $cookieId && defined( $sessionId{$cookieId} ) ) {

      # fine - we have a session identifying cookie
      $hostId = $cookieId;
    }
    else {
      $hostId = $$logLine{$host};
      if ( $host eq '' ) {
        print "\nWARNING: Empty host!\n";
      }
      
      $hostId .= $$logLine{agent} if ( exists( $$logLine{agent} ) );

      # no ID cookie - so we have to trust the heuristic
      if ( $cookieId ne '' ) {

        # from now on, we can use the session ID cookie...
        $sessionId{$cookieId}     = $sessionId{$hostId};
        $lastTimestamp{$cookieId} = $lastTimestamp{$hostId};
        undef $sessionId{$hostId};        # MAYBE IT WOULD BE BETTER TO
        undef $lastTimestamp{$hostId};    # KEEP THE NO-COOKIE ID??????
        $hostId = $cookieId;
      }
    }

    $newSession = 0;
    if ( !defined( $sessionId{$hostId} ) ) {
      $sessionId{$hostId}     = &newSessionId;
      $newSession             = 1;
      $lastTimestamp{$hostId} = $currentTimestamp;
    }

    if ( difftime( $currentTimestamp, $lastTimestamp{$hostId} ) >
      $sessionizeMaxPageViewTime )
    {
      $sessionId{$hostId} = &newSessionId;
      $newSession = 1;
      $sessionId{$hostId};
    }

    if ( $config->sessionizeForeignReferrerStartsSession
      && exists $$logLine{referrer} )
    {
      $uri = URI->new( $$logLine{referrer} );
      if ( $uri->scheme =~ /^http/ && !$newSession ) {
        if ( !$serverFamily{ $uri->host } ) {
          $sessionId{$hostId} = &newSessionId;
          $newSession = 1;
          $sessionId{$hostId};
        }
      }
    }
    $$logLine{session_id}    = $sessionId{$hostId};
    $$logLine{session_index} = $sessionIndex{ $sessionId{$hostId} }++;

    if ( $config->sessionizeInsertReferrerHits
      && $newSession
      && exists $$logLine{referrer} )
    {
      %$referrerLine         = %$logLine;
      $$referrerLine{method} = 'GET';
      $$referrerLine{status} = 200;
      $uri                   = URI->new( $$logLine{path}, 'http' );
      %query                 = $uri->query_form();

      if ( $query{'referrer'} ) {
        $$referrerLine{path} = $query{'referrer'};
      }
      else {
        $$referrerLine{path} = $$logLine{referrer};
      }
      $$referrerLine{referrer} = '';
      &writeLine($referrerLine);
    }

    &writeLine($logLine);
    $lastTimestamp{$hostId} = $currentTimestamp;
    $lastHost               = $hostId;
    $cookieId               = undef;

    if ( !( ++$progressCount % 1000 ) ) {

      # perform garbage collection
      for ( keys(%lastTimestamp) ) {
        if ( difftime( $currentTimestamp, $lastTimestamp{$_} ) >
          $sessionizeMaxPageViewTime )
        {
          $sessionId{$_}     = undef;
          $sessionIndex{$_}  = undef;
          $lastTimestamp{$_} = undef;

        #                    warn sprintf "Removing garbage of hostId %s\n", $_;
        }
      }
      printf STDERR "\r%d lines processed...", $progressCount;
    }

  }    # while
  printf STDERR "\r%d lines processed - finished\n", $progressCount;
}

# ========================================================================
# SUB: parseCommandLine
# ------------------------------------------------------------------------
# Parses the command line and sets $config and $parser.
# ========================================================================
sub parseCommandLine {
  my $currentArg = 0;
  my $arg;
  my $param;
  my $configFile = "$FindBin::Bin/wumprep.conf";
  my $loadArff   = 0;
  my $filterMode = 0;

  # set default values

  my $usage = "Version " . $VERSION . "\n";
  $usage .= "This script takes the following command line arguments:\n";
  $usage .= "-c <filename>: Full path of the WUMprep configuration\n";
  $usage .= "               file to use. Defaults to the wumprep.conf file\n";
  $usage .= "               in the source directory\n";
  $usage .= "-filter      : run in filter mode, i.e., take input from STDIN";
  $usage .= "               and write output to STDOUT.\n";
  $usage .=
    "-arff        : Read Weka ARFF input instead of using the WUMprep\n";
  $usage .= "               log template mechanism.\n";

  if (0) {

    #    if(@ARGV == 0 || lc($ARGV[0]) eq "-h" || lc($ARGV[0]) eq "--help") {
    print $0, " - Part of the WUMprep suite for log file preparation.\n";
    print $usage;
    exit;
  }
  else {
    while ( $currentArg < @ARGV ) {
      $arg   = lc( $ARGV[$currentArg] );
      $param = "";
      if ( $arg eq "-c" ) {
        $param      = $ARGV[ ++$currentArg ];
        $configFile = $param;
      }
      elsif ( $arg eq "-filter" ) {    # filter mode
        $filterMode = 1;
      }
      elsif ( $arg eq "-arff" ) {
        $loadArff = 1;
      }
      elsif ( $arg eq "--help" ) {
        print $usage;
        exit(0);
      }
      else {
        die "\nError: Illegal command line argument #"
          . $currentArg . ": "
          . $ARGV[$currentArg] . ".\n\n"
          . $usage;
      }

      $currentArg++;

      print STDERR " Using " . $arg
        . ( ( $param ne "" ) ? " " . $param : "" ) . "\n";
    }

    # Load the configuration file
    $config = new WUMprep::Config($configFile);

    if ($loadArff) {
      use WUMprep::ArffParser;
      $parser = new WUMprep::ArffParser;
    }
    else {
      use WUMprep::LogfileParser;
      $parser = new WUMprep::LogfileParser;
    }

    if ($filterMode) {
      $operationMode = 'filter';
    }
    else {
      $operationMode = $config->operationMode;
    }
  }
}

sub newSessionId {
  ++$currentId;
}

sub nextLine {
  my $logLineHashRef;
  if ( $operationMode eq 'file' ) {
  READ_LINE:
    my $logLine = <INFILE>;
    if ( $logLine =~ /^\s*\#.*/ ) {    # skip comments
      &writeLine($logLine);
      goto READ_LINE;
    }
    if ($logLine) {
      $logLineHashRef = $parser->parseLogLine($logLine);
      return $logLineHashRef;
    }
    else {
      return undef;
    }
  }
  elsif ( $operationMode =~ /filter/ ) {
  READ_LINE_FILTER:
    my $logLine = <INFILE>;

    if ($logLine) {
      if ( $logLine =~ /(?:^\s*\#.*$|^$)/ ) {

        # skip comments and blank lines
        print STDERR "Skipped line: $logLine";
        goto READ_LINE_FILTER;
      }
      $logLineHashRef = $parser->parseLogLine($logLine);

      # The ARFF parser returns -1 as long
      # as it is parsing the ARFF header
      if ( $logLineHashRef != -1 ) {
        if ( !$inData ) {

          # This happens when the first instance is processed
          %fieldMap = %{ $parser->fieldMap };

          my $inputTemplate = $parser->getInputTemplate();
          printf STDERR "input template:  %s\n", $inputTemplate;
          if ($config->sessionizeSeparator eq '') {
            $parser->appendAttribute('session_id', 'String');
            $parser->setOutputTemplate('@session_id@,' . $inputTemplate);
          } else {
            $parser->setOutputTemplate($inputTemplate);
          }
          printf STDERR "output template: %s\n", $parser->getOutputTemplate;
          $host = defined( $fieldMap{host_ip} ) ? 'host_ip' : 'host_dns';
          print OUTFILE $parser->outputArffHeader();
          $inData = 1;    # Execute the above code only once
        }
        return $logLineHashRef;
      }
      else {
        goto READ_LINE_FILTER;
      }
    }
  }
}

# ========================================================================
# SUB: dumpLine
# ------------------------------------------------------------------------
# DEPRECATED!!!
# ========================================================================
#sub dumpLine(\$) {
#  my $logLineRef = shift();
#  my $sessionId  = $$logLineRef{session_id};
#  my $returnString;
#
#  $hostLabel = exists( $$logLineRef{host_ip} ) ? 'host_ip' : 'host_dns';
#
#  my $tmp = $$logLineRef{$hostLabel};
#
#  $$logLineRef{$hostLabel} =
#      $idStem . ":"
#    . $$logLineRef{session_id}
#    . $config->sessionizeSeparator
#    . $$logLineRef{$hostLabel};
#  delete $$logLineRef{session_id};
#  $returnString = $parser->sampleLogLine($logLineRef);
#
#  $$logLineRef{$hostLabel} = $tmp;
#  $$logLineRef{session_id} = $sessionId;
#
#  return $returnString;
#}

sub writeLine(\$) {
  my $logLineRef = shift();
  if ( $operationMode eq 'file' || $operationMode eq 'filter' ) {

    # file mode - that's simple - thanks to the parser ;-)

#    $hostLabel = exists( $$logLineRef{host_ip} ) ? 'host_ip' : 'host_dns';

    $$logLineRef{session_id} = $idStem . ":" . $$logLineRef{session_id};

    if (! ($parser->getOutputTemplate =~ /session_id/)) {
      $$logLineRef{$host} =
          $$logLineRef{session_id}
        . $config->sessionizeSeparator
        . $$logLineRef{$host};
      delete $$logLineRef{session_id};
    }
    
    my $outLine = $parser->sampleLogLine($logLineRef);
    print OUTFILE $outLine . "\n";
  }
}

__END__


=head1 NAME

sessionize.pl - define single sessions in a web server log

=head1 DESCRIPTION

B<sessionize.pl> is part of the B<WUMprep> suite of perl scripts for
logfile preparation. It defines sessions by adding a session ID to the host
field of each entry in a web server log.

The script is designed as a filter, expecting a logfile on stdin an writing
it's output to stdout.

The script implements to methods for session identification: Cookies
and a hostname/page-view-time based heuristic. Sessionizing by the use
of cookies is the preferred method. If a session identifying cookie is
found in a log line, this is used instead of the heuristic's
criteria. The name of the cookie to use can be specified in the
F<wumprep.conf> file.

If a cookie is found for a session that previously has been identified
based on the heuristic, all future identification of this session is
done only by the cookie. Even the previous requests of the session are
mapped to the cookie id.

If no cookies are present, it is assumed that a new session begins (a)
for every host appearing the first time in the log and (b) for an
already appeared host, if the max. page view time has been
exceeded. The page view time is calculated as the difference of the
log entrie's timestamps in seconds. The threshold value used for
sessionizing is read from the F<wumprep.conf> file in the log
directory. See L<WUMprep::Config> for details.

The hostname used internaly by this script is a combination of the
original hostname from the log and the user-agent field. This is
because some web browsers (like the MS Internet Explorer 5.01, for
example) support offline browsing and check a website autonomously for
changes, using a different agent identification. In addition, there
exist some tools like "wget" that offer a similar functionality. As a
consequence, a single hostname (or IP address) may represent both a
human user and a robot. In this case, the user agent information
indicates the different sources of the requests.

Another benefit of using the user agent information in addition to the
hostname is that errors due to the use of proxy servers may be reduced. If
two different users accessing the website through the proxy server at the
same time, the can be distinguished if they use different web browsers.

The session ID has the format B<rrrrrr:n>, where B<rrrrrr> is a randomly
choosen number between 0 and 999999, used to ensure really unique IDs when
combining multiple log files. The B<n> after the colon is a consecutive
number of the session in a logfile.

The output of this script has the same format as the input logfile, except
of the host field which now has the format
<sessionID>B<S><originalHostField>. <sessionID> has the format described
above. B<S> is the separator character taken from B<wumprep.conf>, which is
'|' by default.














