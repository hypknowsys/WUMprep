#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# detectRobots.pl - Detect log entries caused by robots
# $Revision: 1.8 $
#
# This script is derived from the "removeRobots.pl" script, which in
# turn is based on the BotWatch.pl script written by Simon Wilkinson.
# See http://www.sxw.org.uk/computing/robots/botwatch.html.
#
# Simon's pages seem not to be actively maintained anymore, especially
# the indexers.lst robot database is not accessible (as of Oct 23, 2003).
# Thus, detectRobots.pl now supports primarily the robots database
# available on http://www.robotstxt.org, which follows the same syntax.
# (http://www.robotstxt.org/wc/active/all.txt)
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
use POSIX qw(mktime difftime ctime);
use strict;

my $config = new WUMprep::Config;
my $parser;
my $resolvStatus;
my $inputFile;
my $outputFile;
my %fieldMap;
my $operationMode;
my $inData;    # Required when parsing ARFF files

# Possible values for the host status field. The host status is binary coded,
# i.e., if bit 1 is set, we have IP addresses, and if bit 2 is set,
# we have resolved host names.
my $HOST_IP   = 1;
my $HOST_NAME = 2;
my $DEBUG     = 0;
my $hostField;

# standard agent classes
my $AGENT_CLASS_UNDEF         = 0;
my $AGENT_CLASS_HUMAN_GENERIC = 1;
my $AGENT_CLASS_ROBOT_GENERIC = 10000;

my $robotsDB;
my $revision = "Revision: 0.02";

my $extendedlog  = 1;
my $loggingIPs   = 0;    # In former times, we used a robots database containing
                         # robots' IP addresses. At the moment, this variable
                         # should remain 0. See &robot_ip for this variable's
                         # impact
my $debug        = 0;
my $nodnslookups = 1;
my $unknowncount = 0;
my @ignore;
my @ignore_after;
my %robot_name;
my %robot_url;
my %robot_host;
my $current_ua;
my %robot_agent;
my %robot_ip;
my $tempFileName;
my $writeTemp = 0;

&parseCommandLine;

if ( $config->robotsDB ne "" ) {
  $robotsDB = $config->robotsDB;
}
else {
  $robotsDB = "$FindBin::Bin/indexers.lst";
}

# Read in our robots list
open( ROBOTS, $robotsDB )
  || die "Cannot open the list of robots: " . $robotsDB . "\n";

printf( STDERR "Processing list of known robots\n" );

while (<ROBOTS>) {
  next if (/^\s*#/);

  if (/ignore-useragent:\s*(.*)$/) {
    push( @ignore, $1 );
  }
  if (/ignore-after:\s*(.*)$/) {
    push( @ignore_after, $1 );
  }
  if (/robot-id:\s*(\S*)$/) {
    $current_ua = $1;
  }
  if (/robot-name:\s*(.*)$/) {
    $robot_name{$current_ua} = $1;
  }
  if (/robot-cover-url:\s*(.*)$/) {
    $robot_url{$current_ua} = $1;
  }

  if (/robot-host:\s*(\S.*)$/) {
    foreach my $tmp ( split( ', ', $1 ) ) {
      if ( $tmp ne "*" ) {
        $tmp =~ s/\./\\\./g;
        $tmp =~ s/\*/\.\*/g;
        $robot_host{$current_ua} .= ", " if $robot_host{$current_ua} ne '';
        $robot_host{$current_ua} .= $tmp;
      }
      print STDERR "DEBUG: robot_host initialized: $robot_host{$current_ua}\n"
        if $DEBUG;
    }
  }

  if (/robot-hostIP:\s*(\S.*)$/) {
    $robot_ip{$current_ua} = $1;
  }

  if (/robot-useragent:\s*(\S.*)$/) {
    $robot_agent{$current_ua} = $1;
  }
}

close ROBOTS;

open ROBOTLINES, ">robotLogLines.log"
  || die "$0: Could not open robotLogLines.log for writing\n";

if ( $operationMode eq 'filter' ) {
  # use stdin/stdout
  open( INFILE,  "-" );
  open( OUTFILE, ">-" );
  $tempFileName =
      $config->outputDir
    . "/detectRobots."
    . sprintf( "%06d", rand 999999 ) . ".tmp";
  open( TEMPFILE, ">" . $tempFileName ) ||
    die "Could not create temporary file $tempFileName\n";
  $writeTemp = 1;
  $inputFile = 'from standard input';
  &main;
}
elsif ( $operationMode eq 'file' ) {
  %fieldMap = %{ $parser->fieldMap };
  if ( defined( $fieldMap{host_ip} ) ) {
    $hostField = 'host_ip';
  }
  elsif ( defined( $fieldMap{host_dns} ) ) {
    $hostField = 'host_dns';
  }
  else {
    $hostField = 'session_id';
  }

  #    $hostField = defined($fieldMap{host_ip}) ? 'host_ip' : 'host_dns';

  # check if we have a session ID
  die "$0: Missing field 'session_id'\n"
    if ( !defined( $fieldMap{session_id} ) );

  foreach $inputFile ( $config->inputLogs ) {
    if ( $operationMode eq 'file' ) {
      $inputFile  = longestFilename($inputFile);
      $outputFile = $inputFile . $config->rmRobotsOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "$0: Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "$0: Could not open output file $outputFile\n";
      &main;
    }
  }
}
else {
  die sprintf "$0: Unknown operation mode: %s\n", $operationMode;
}

sub main {

  # Do an initial pass of the file. Store as IP, count and transfer size

  my $logLine;
  my $agent;
  my $agentLog = defined( $fieldMap{agent} );
  my $sessionId;
  my $ip;
  my $ip_map;
  my %ip_fail;
  my $path;
  my %lastTimestamp;
  my %agent_map;
  my %ip_map;
  my %detectedBy;
  my %sessionId_map;
  my %requestCount;
  my $lastdate;
  my $unknown_count;
  my %unknown_agent;
  my $referrerFound;
  my %maxPageViewTime;
  my %seenfromlog;
  my %referrerFound;
  my %agent_fail;
  my $ipfound;
  my $found;
  my %isRobot;

  my $notifyevery  = 100;
  my $lineCount = 0;

  printf( STDERR "Detecting robots in log $inputFile ...\n" );

  while ( $logLine = &nextLine ) {
    printf STDERR "1st pass: %s lines processed\n", $lineCount
      if ( !( ++$lineCount % $notifyevery ) );

    if ($agentLog) {
      $agent = $$logLine{agent};

      #Remove everything after the word  via - to remove proxy lines
      $agent =~ s/ via .*//;
    }

    # this is only to make code more readable
    $sessionId = $$logLine{session_id};
    $ip        = $$logLine{$hostField};
    $path      = $$logLine{path};

    # save the host ip of this session
    $sessionId_map{$sessionId} = $ip;

    # count the number of 'content' requests, i.e., documents which are
    # no graphics, stilesheets, javascript etc.
    $requestCount{$sessionId}++
      if ( lc($path) !~ /(\.gif|\.jpe?g|\.css|\.js|\.bmp|\.ico)/ );

    # Robots generally don't send POSTs (they can't handle forms)
    next if ( $$logLine{method} ne "GET"
      && $$logLine{method} ne "HEAD" );

    # Measure the page view time and save the top value per session
    $lastdate = mktime(
      $$logLine{ts_seconds},   $$logLine{ts_minutes},
      $$logLine{ts_hour},      $$logLine{ts_day},
      $$logLine{ts_month} - 1, $$logLine{ts_year} - 1900
    );

    if ( exists( $lastTimestamp{$sessionId} ) ) {
      if ( difftime( $lastdate, $lastTimestamp{$sessionId} ) >=
        $maxPageViewTime{$sessionId} )
      {
        $maxPageViewTime{$sessionId} =
          difftime( $lastdate, $lastTimestamp{$sessionId} );
      }
    }

    $lastTimestamp{$sessionId} = $lastdate;

    # If we've got a valid User Agent field that we've seen as a robot before
    if ( !$isRobot{$sessionId}
      && defined($agent)
      && ( $found = $agent_map{$agent} ) )
    {

      # %agent_map holds all agents that occured in the log
      if ( !defined( $seenfromlog{ $found, $ip } ) ) {
        $seenfromlog{ $found, $ip } = 1;

        #		$robot_seenfrom{$found}.=" ".$ip;
      }
      $isRobot{$sessionId}    = 1;
      $detectedBy{$sessionId} = 'user agent';
      next;
    }

    # Now - do we have an IP address that we've seen as a robot before
    # Oh well, we didn't manage to work anything out given the UA.
    # Next, we can try comparing their IP address with those that have
    # already fetched robots.txt files, or been flagged in the cache as
    # being a robot.
    #if ($found = $ip_map{$ip}) {
    if ( $found = $isRobot{$sessionId} ) {
      next;
    }

    # Nope, we haven't seen an access from this site / UA that we've decided
    # is a robot yet.
    #
    # Now, providing we have a UA that we haven't seen before, we check it
    # with our list of robot UAs

    if ( defined($agent) && !defined( $agent_fail{$agent} ) ) {
      if ( $found = &robot_ua($agent) ) {
        $agent_map{$agent} = $found;

        # make a dummy entry in $ip_map, so we don't have to check
        # the $agent_map when tagging sessions later in this script
        $ip_map{$ip}            = 1;
        $isRobot{$sessionId}    = 1;
        $detectedBy{$sessionId} = 'user agent';
        next if $agent eq 'ignore';
        if ( !defined( $seenfromlog{ $found, $ip } ) ) {
          $seenfromlog{ $found, $ip } = 1;
        }
        next;
      }
      $agent_fail{$agent} = 1;
    }

    # Nope - not a known robot UA.
    # Now check to see if the request is coming from a robot sites IP

    #        if (!defined($agent) && !defined($ip_fail{$ip})) {
    if ( $agent_fail{$agent} && !defined( $ip_fail{$ip} ) ) {
      if ( $ipfound = &robot_ip($ip) ) {

        # $ip_map stores the robot UA behind an IP address
        $ip_map{$ip}            = $ipfound;
        $isRobot{$sessionId}    = 1;
        $detectedBy{$sessionId} = 'ip address';
        if ( !defined( $seenfromlog{ $ipfound, $ip } ) ) {
          $seenfromlog{ $ipfound, $ip } = 1;
        }
        next;
      }
      $ip_fail{$ip} = 1;
    }

    # Still nothing! Now lets see if this access is for a robots.txt
    # file
    if ( $path =~ /\/robots\.txt/ ) {

      # They requested a robots.txt file - flag them as a robot
      #
      # As we didn't spot this request previously, it must be from a
      # robot that isn't in any of our reference files or that can't
      # be detected from them, if we're using logs without referer
      # details - so we flag the request as coming from an unknown
      # robot.
      #
      # We also assume that all connections comming from this IP
      # have also been robots
      $ip_map{$ip} = $found = "UNKNOWN" . $unknown_count;
      $isRobot{$sessionId}    = 1;
      $detectedBy{$sessionId} = 'robots.txt';
      $unknown_count++;

      $unknown_agent{$found} = $agent;

      if ( !defined( $seenfromlog{ $ip_map{$ip}, $ip } ) ) {
        $seenfromlog{ $found, $ip } = 1;
      }
      next;
    }
  }
  continue {

    # Though it's not good programming style to do further
    # robot tests in this part of the loop, it is neccessary since
    # the "always without referrer" heuristic allows mis-qualification of
    # hosts as robots. This error has to be corrected indepedent of the
    # other heuristics.

    # Check for referrer information
    # We apply this heuristic only to sessions with at least two requests.
    # Otherwise, we would wrongly qualify users who typed in our site's
    # URL manually and left after the first page as robots.
    if ( !$isRobot{$sessionId}
      && defined($agent) ? $agent_fail{$agent} : 1
      && $ip_fail{$ip} )
    {
      if ( !$referrerFound{$sessionId} ) {
        if ( $$logLine{referrer} =~ /^-?$/
          && $requestCount{$sessionId} > 1 )
        {

          #if(!exists($ip_map{$ip})) {
          if ( !$isRobot{$sessionId} ) {
            $ip_map{$ip} = $found = "UNKNOWN" . $unknown_count;
            $isRobot{$sessionId}    = 1;
            $detectedBy{$sessionId} = 'missing referrer';
            $unknown_count++;

            $unknown_agent{$found} = $agent;

            if ( !defined( $seenfromlog{ $ip_map{$ip}, $ip } ) ) {
              $seenfromlog{ $found, $ip } = 1;
            }
          }
        }
        elsif ( $$logLine{referrer} !~ /^-?$/ ) {
          $referrerFound{$sessionId} = 1;
        }
      }
    }

    if ( $referrerFound{$sessionId} && $isRobot{$sessionId} ) {

      #print "Referrer found: " . $ip . "\n";
      # We wrongly qualified this host as robot - now we have
      # to correct this mistake
      # THIS WAS NECCESSARY IN A FORMER VERSION OF THIS SCRIPT AND SHOULD
      # BE SAFELY BE REMOVED NOW.
      printf STDERR "DEBUG: removing robot tag for session %d\n", $sessionId;
      delete $unknown_agent{ $ip_map{$ip} };
      delete $detectedBy{$sessionId};
      delete $isRobot{$sessionId};
      delete $ip_map{$ip};
    }
  }

  # Here comes the final check:
  # Hosts with a too high request frequency probably aren't human.
  # We can find them by checking the maxPageViewTime.
  # To provide incorrect qualification of short time visitors as
  # robots, we require the session to have at least 3 requests to
  # non-image documents before we allow to decide he's a robot.
  # Since we don't know anything but the sessionId (which _may_ be
  # the host ip or address), we cannot add the robot hits from this
  # heuristic to the statistics. We just add a dummy ip_map, so this
  # host will be

  foreach $sessionId ( keys(%maxPageViewTime) ) {
    if ( $requestCount{$sessionId} > 2
      && $maxPageViewTime{$sessionId} <= $config->rmRobotsMaxViewTime )
    {
      $ip_map{ $sessionId_map{$sessionId} } = 1;
      $isRobot{$sessionId}                  = 1;
      $detectedBy{$sessionId}               = 'page view time';
    }
  }

  # Now, we have traversed the whole log file. What follows is
  # different depending on the operation mode.

  if ( $operationMode eq 'file' ) {
    seek INFILE, 0, 0;
  }
  elsif ( $operationMode eq 'filter' ) {
    close TEMPFILE;
    close INFILE;
    open INFILE, '<' . $tempFileName || 
      die "Could not open temporary file $tempFileName\n";
    $writeTemp = 0;
  }

  printf STDERR "1st pass: %s lines processed, starting 2nd pass\n", $lineCount;

  $lineCount = 0;
  
  while ( $logLine = &nextLine ) {
    printf STDERR "2nd pass: %d lines processed\n", $lineCount
      if ( !( ++$lineCount % $notifyevery ) );
    if ( defined( $isRobot{ $$logLine{session_id} } ) ) {
      if (UNIVERSAL::isa($parser, 'WUMprep::ArffParser')) {
        $$logLine{robot} = 1;
      } else {
        &writeRobotLine( $logLine, $detectedBy{ $$logLine{session_id} } );
        next;
      }
    } elsif (UNIVERSAL::isa($parser, 'WUMprep::ArffParser')) {
      $$logLine{robot} = 0;
    }
    &writeLine($logLine);
  }
  printf STDERR "2nd pass: %d lines processed - finished\n", $lineCount;

  close INFILE;
  close OUTFILE;

  if ($operationMode eq 'filter') {
    # delete the temporary file
    unlink $tempFileName;
  }
}

sub robot_ua {
  my $agent = shift;
  my $id;

  foreach $id (@ignore) {
    return ("ignore") if ( $agent =~ /$id/ );
  }

  foreach $id ( keys(%robot_agent) ) {
    return ($id) if ( $agent =~ /\Q$robot_agent{$id}/ );
  }
  return undef;
}

sub robot_ip {
  my $id;
  my $item;

  # get the agent id of a given IP address
  my $ip = $_[0];
  if ($loggingIPs) {
    foreach $id ( keys(%robot_ip) ) {
      foreach $item ( split( ' ', $robot_ip{$id} ) ) {
        return ($id) if ( $ip =~ /$item/ );
      }
    }
  }
  else {
    foreach $id ( keys(%robot_host) ) {
      foreach $item ( split( ', ', $robot_host{$id} ) ) {
        print STDERR "robot_host match: $item - $ip\n"
          if ( $ip =~ /$item/i ) && $DEBUG;
        return ($id) if ( $ip =~ /$item/i );
      }
    }
  }
  undef;
}

sub gethost {
  my $addr;
  if ( $config->DNSlookups ) {
    $addr = $_[0];
    ( my $name, my $aliases, my $type, my $len, my $ad ) =
      gethostbyaddr( pack( 'C4', split( '\.', $addr ) ), 2 );
    if ($name) {
      $name;
    }
    else {
      $addr;
    }
  }
  else {
    $addr;
  }
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
        $filterMode = 'filter';
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
        #print STDERR "Skipped line: $logLine";
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
          if ( $config->sessionizeSeparator eq '' ) {
            $parser->appendAttribute( 'robot', 'String' );
            $parser->setOutputTemplate( '@robot@,' . $inputTemplate );
          }
          else {
            $parser->setOutputTemplate($inputTemplate);
          }
          printf STDERR "output template: %s\n", $parser->getOutputTemplate;
          $hostField = defined( $fieldMap{host_ip} ) ? 'host_ip' : 'host_dns';
          print OUTFILE $parser->outputArffHeader();
          $inData = 1;    # Execute the above code only once
        }
        if ($writeTemp) {
          print TEMPFILE $logLine;
        }
        return $logLineHashRef;
      }
      else {
        goto READ_LINE_FILTER;
      }
    }
  }
}

sub writeLine(\$) {
  my $logLineRef = shift();
  if ( $config->operationMode =~ /file|filter/ ) {

    # file mode - that's simple - thanks to the parser ;-)
    print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
  }
  else {
    die sprintf "$0: writeLine not suppported for operation mode %s\n",
      $config->operationMode;
  }
}

sub writeRobotLine(\$\$) {
  my $logLineRef = shift();
  my $detectedBy = shift();
  printf ROBOTLINES "%s (%s)\n", $parser->sampleLogLine($logLineRef),
    $detectedBy;
}

__END__

=head1 NAME

detectRobots.pl - remove requests issued by robots from a log file

=head1 CONFIGURATION

This script is configured by settings in the file "wumprep.conf". See
L<WUMprep::Config> for details.

=head1 DESCRIPTION

This script tries several methods to identify hosts which are robots
removes them from the input log files:

=head2 BotWatch robot database

The first attempt at identifying robots is performed using the BotWatch
robot database. BotWatch is a perl script generating statistics about the
robot population in log files
(http://www.tardis.ed.ac.uk/~sxw/robots/botwatch.html).  The database
consists of detailed information about already known robots, including data
on IP addresses, hostname, referrer, and user agent identification. These
data are tested against the correpsonding fields in the log file.

=head2 Heuristics

If the robot is not already known by the database, detectRobots.pl uses
several heuristics in order remove a maximum number of robot accesses from
the log:

=over 4

=item B<robots.txt>

It is good robot behaviour to request a file "/robots.txt". This file can
be used by a web site administrator to control if and how robots should
visit or index the site. Since usually no link to this file exists, one can
rely on the assumption that a request of this file has been issued by a
robot.

=item B<Missing referrer information>

If all requests originating at the same IP address show an empty referrer
field, this hosts is assumed to be a robot. This assumtion is reasonable,
because any of the common web browsers provides referrer information.

=item B<High request frequency>

A human user is assumed to need a minimum amount of time in order to
perceive the content of a webpage. If all page requests comprising a single
session occur with an extremely high frequence (less than 2 seconds between
successive requests, for example - this is user configurable), this
indicates automated requests, issued either by robots or tools for offline
browsing like wget.

The test for request frequency is only useful if the log has been
sessionized. See the L<sessionize.pl> manpage for details.

=back

Once a robot has been identified, all requests coming from the same IP
address are qualified as robot requests. We assume that by far the most
robots will run on dedicated machines that are not used for browsing by
humans, so the statistical error should be neglegible.
