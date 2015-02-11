#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# sessionFilter.pl - Remove "dust" from a log file on a per-session basis
# $Revision: 1.5 $
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
use strict;
use vars
  qw($inputFile $outputFile $host $dummy $path $status $tmp @ts $timestamp %lastRequest %lastTimestamp %month_map);

my %fieldMap;
my $operationMode;
my $inData;    # Required when parsing ARFF files
my $tempFileName;
my $writeTemp = 0;

my $HOST_IP   = 1;
my $HOST_NAME = 2;

my $config;   # set in &parseCommandLine
my $parser;   # set in &parseCommandLine

&parseCommandLine;

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
else {
  if ( $operationMode eq 'file' ) {
    %fieldMap = %{ $parser->fieldMap };
  }
  else {
    die "$0\nERROR: Unknown operation mode: " . $operationMode . "\n";
  }

  # check if we have a session ID
  die "$0: Missing field 'session_id'\n"
    if ( !defined( $fieldMap{session_id} ) );

  foreach $inputFile ( $config->inputLogs ) {
    if ( $operationMode eq 'file' ) {
      $inputFile  = longestFilename($inputFile);
      $outputFile = $inputFile . $config->sessionFilterOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      printf STDERR "$0: processing file %s\n", $inputFile;
      &main;
      close INFILE;
      close OUTFILE;
    }
  }
}

sub main {
  my $finished;
  my $logLine;
  my $currentSessionId;
  my @currentSession;
  my %dropSession;
  my %lastPath;
  my $skipLine;
  my $count;
  my $sessionFilterHostIp   = $config->sessionFilterHostIp;
  my $sessionFilterHostName = $config->sessionFilterHostName;
  my $sessionFilterPath     = $config->sessionFilterPath;
  my $sessionFilterAgent    = $config->sessionFilterAgent;

  while ( $logLine = &nextLine ) {

    # check filter conditions and skip to next session as soon as one
    # criterion matches.
    if ( $config->sessionFilterPath ) {
      $dropSession{ $$logLine{session_id} } = 1
        if ( $$logLine{path} =~ /$sessionFilterPath/ );
    }
    if ( $sessionFilterHostIp && $$logLine{host_ip} ne '' ) {
      $dropSession{ $$logLine{session_id} } = 1
        if ( $$logLine{host_ip} =~ /$sessionFilterHostIp/ );
    }
    if ( $sessionFilterHostName && $$logLine{host_dns} ne '' ) {
      $dropSession{ $$logLine{session_id} } = 1
        if ( $$logLine{host_dns} =~ /$sessionFilterHostName/ );
    }
    if ( $sessionFilterAgent && $$logLine{agent} ne '' ) {
      $dropSession{ $$logLine{session_id} } = 1
        if ( $$logLine{agent} =~ /$sessionFilterAgent/ );
    }
    printf STDERR "   1st pass: %d lines processed...     \r", $count
      if ( !( ++$count % 1000 ) );
  }
  printf STDERR "   1st pass finished (%d lines processed)               \n",
    $count;

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
  $count = 0;

  while ( $logLine = &nextLine ) {
    next if ( $dropSession{ $$logLine{session_id} } );

    # shall we filter for successive requests of the same URL?
    if ( $config->sessionFilterRepeatedRequests ) {
      if ( $$logLine{path} eq $lastPath{ $$logLine{session_id} } ) {
        $skipLine = 1;
      }
      else {
        $skipLine = 0;
      }
      $lastPath{ $$logLine{session_id} } = $$logLine{path};
    }

    # write output
    if ( !$skipLine ) {
      &writeLine($logLine);
    }
  }
  continue {
    printf STDERR "   2nd pass: %d lines processed...      \r", $count
      if ( !( ++$count % 1000 ) );
  }
  printf STDERR "   2nd pass: %d lines processed - finished                \n",
    $count;

  close INFILE;
  close OUTFILE;

  if ($operationMode eq 'filter') {
    # delete the temporary file
    unlink $tempFileName;
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
          $parser->setOutputTemplate($inputTemplate);
          printf STDERR "output template: %s\n", $parser->getOutputTemplate;
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
  if ( $config->operationMode eq 'file' ) {

    # file mode - that's simple - thanks to the parser ;-)
    print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
  }
  else {
    die sprintf "$0: writeLine not suppported for operation mode %s\n",
      $config->operationMode;
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

