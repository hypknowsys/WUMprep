#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# logFilter.pl - Remove "dust" from a log file.
# $Revision: 1.1 $
#
# This script drops all requests to images and alike embedded in HTML
# files. It also removes successive requests to the same file from the same
# host during short time intervals (probably caused by impatient users).
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
use POSIX qw(mktime difftime);
use HTTP::Date;
use strict;
use vars
  qw($inputFile $outputFile $host $dummy $path $status $tmp @ts $timestamp %lastRequest %lastTimestamp %month_map $count $i);

my %fieldMap;
my $operationMode;
my $inData;    # Required when parsing ARFF files

my $HOST_IP   = 1;
my $HOST_NAME = 2;

my $config;    # set in parseCommandLine
my $parser;    # set in parseCommandLine
my $hostField;    # alias for either host_dns or host_ip
my $writeTemp = 0;

&parseCommandLine;

if ( $operationMode eq 'filter' ) {

  # use stdin/stdout
  open( INFILE,  "-" );
  open( OUTFILE, ">-" );
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

  $hostField = exists( $fieldMap{host_ip} ) ? 'host_ip' : 'host_dns';

  $count = $config->inputLogs;
  foreach $inputFile ( $config->inputLogs ) {
    if ( $operationMode eq 'file' ) {
      $outputFile = $inputFile . $config->filterOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      &main;
      close INFILE;
      close OUTFILE;
    }
  }
}

sub main() {
  my $logLine;
  my $filterDuplicatesExtensions = $config->filterDuplicatesExtensions;
  my $count;
  my $removeCount;

  printf( STDERR "Filtering input log file $inputFile ...\n" );
  while ( $logLine = &nextLine ) {
    next if /^\#/;    # skip comments

    $path   = $$logLine{path};
    $host   = $$logLine{$hostField};
    $status = $$logLine{status};
    $tmp    = $config->filterDuplicatesExtensions;

    # do we filter duplicates for this filetype?
    if ( $path =~ /$filterDuplicatesExtensions/ ) {
      if ( defined( $$logLine{ts_seconds} ) ) {
        $timestamp = mktime(
          $$logLine{ts_seconds}, $$logLine{ts_minutes},
          $$logLine{ts_hour},    $$logLine{ts_day},
          $$logLine{ts_month},   $$logLine{ts_year} - 1900
        );
      }
      else {

        # we assume to have an RFC 1123 timestamp
        $timestamp = str2time( $$logLine{ts} );
      }

      if ( exists( $lastTimestamp{$host} ) && $lastRequest{$host} eq $path ) {
        if ( difftime( $timestamp, $lastTimestamp{$host} ) <=
          $config->filterDuplicateTimeout )
        {
          $lastTimestamp{$host} = $timestamp;
          $count++;
          $removeCount++;
          next;
        }
      }
      else {
        $lastTimestamp{$host} = $timestamp;
        $lastRequest{$host}   = $path;
      }
    }

    $tmp = $config->filterPath;
    if ( $path !~ /($tmp)/i ) {
      $tmp = $config->filterHosts;
      if ( $host !~ m/$tmp/i ) {
        if ( $config->filterStatusCodes eq "" ) {
          &writeLine($logLine);
        }
        elsif ( ( $tmp = $config->filterStatusCodes ) && $status =~ m/$tmp/ ) {
          &writeLine($logLine);
        }
        else {
          $removeCount++;
        }
      }
      else {
        $removeCount++;
      }
    }
    else {
      $removeCount++;
    }
    printf STDERR "\r%d lines processed...", $count if ( !( ++$count % 1000 ) );
  }
  printf STDERR "\r%d lines processed, %d lines removed (%.2f\%) - finished\n",
    $count, $removeCount, $removeCount / $count * 100;
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
  if ( $config->operationMode eq 'file' ) {

    # file mode - that's simple - thanks to the parser ;-)
    print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
  }
  else {
    die "Operation mode not supported\n";
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

