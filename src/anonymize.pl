#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# anonymizeLog.pl - Replace host addresses by anonymous IDs
# $Revision: 1.1 $
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

$VERSION = "1.0 - 04/06/2000";

package WUMprep;
use Socket;
use FindBin;
use lib "$FindBin::Bin";
use WUMprep;
use WUMprep::LogfileParser;
use WUMprep::Config;
use strict;
use vars qw($config $inputFile $host $dummy $path $status $tmp %anonKeys
  @ts $timestamp %lastRequest %lastTimestamp %month_map);

my %fieldMap;
my $outputFile;
my $count;
my @processedLogs;
my $operationMode;
my $inData;
my $config;       # set in parseCommandLine
my $parser;       # set in parseCommandLine
my $hostField;    # alias for either host_dns or host_ip

&parseCommandLine;

if ( $config->anonKeyFile ) {
  &keyFileInit;
}

if ( $operationMode eq 'filter' ) {
  open( INFILE,  "-" );
  open( OUTFILE, ">-" );
  $inputFile = 'from standard input';
  &ProcessInputLog;
}
else {
  if ( $operationMode eq 'file' ) {
    $fieldMap{host_dns} = $fieldMap{host_ip};    # replace address in file mode
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
      $outputFile = $inputFile . $config->anonOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      &ProcessInputLog;
      close INFILE;
      close OUTFILE;
    }
    push @processedLogs, $inputFile;
  }

  if ( $config->anonKeyFile ) {
    &keyFileSave;
  }
}

exit;

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

  my $usage = <<EOT;
This script takes the following command line arguments:
-c <filename>: Full path of the WUMprep configuration
               file to use. Defaults to the wumprep.conf file
               in the source directory
-i <filename>: Name of the input INFILE
               If no input filename is given, the program tries
               to read from stdin.
-o <filename>: Name of the output INFILE
               If no output file is specified, stdout is used.
-filter      : run in filter mode, i.e., take input from STDIN
               and write output to STDOUT.
-arff        : Read Weka ARFF input instead of using the WUMprep
               log template mechanism.
EOT

  if ( @ARGV == 0 || lc( $ARGV[0] ) eq "-h" || lc( $ARGV[0] ) eq "--help" ) {
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
      elsif ( $arg eq "-i" ) {    # input filename
        if ( -e ( $ARGV[ ++$currentArg ] ) ) {
          $inputFile = $ARGV[$currentArg];
        }
        else {
          die "\nError: Input INFILE " . $ARGV[$currentArg] . " not found.\n";
        }
      }
      elsif ( $arg eq "-o" ) {    # output filename
        $outputFile = $ARGV[ ++$currentArg ];
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

# ========================================================================
# SUB: ProcessInputLog
# ========================================================================
sub ProcessInputLog {
  my $url;
  my $logLine;
  my $count;
  my $i;
  my $hostId;

  print STDERR "Anonymizing hosts in logfile $inputFile ...\n";

  while ( $logLine = &nextLine ) {
    if ( $$logLine{host_ip} ) {
      $hostId = "host_ip";
    }
    else {
      $hostId = "host_dns";
    }
    if ( exists $anonKeys{ $$logLine{$hostId} } ) {
      $url = $anonKeys{ $$logLine{$hostId} };
    }
    else {
      $url = "";
      for ( $i = 1 ; $i <= 4 ; $i++ ) {
        $url .= "." if ( $url != "" );
        $url .= ( 256 + int( rand 743 ) );
        $anonKeys{ $$logLine{$hostId} } = $url;
      }
    }

    $$logLine{$hostId} = $url;

    &writeLine($logLine);
    printf STDERR "\r%d lines processed...        ", $count
      if ( !( ++$count % 1000 ) );
  }
  printf STDERR "\r%d lines processed - finished           \n\n", $count;
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
}

sub keyFileInit {
  open KEY_FILE, $config->anonKeyFile
    || die "Could not open key file $config->anonKeyFile.\n";

  while (<KEY_FILE>) {
    /(\S+)\s+(\S+)/;
    $anonKeys{$1} = $2;
  }
  close KEY_FILE;
}

sub keyFileSave {
  open KEY_FILE, ">" . $config->anonKeyFile
    || die "Could not open key file $config->anonKeyFile.\n";

  ( my @now ) = localtime(time);
  printf KEY_FILE
    "# anonymizeLog.pl key file created %04d-%02d-%02d %02d:%02d:%02d\n",
    $now[5] + 1900, $now[4] + 1, $now[3], $now[2], $now[1], $now[0];
  printf KEY_FILE "#\n# Processed files:\n#\n";

  for (@processedLogs) {
    printf KEY_FILE "# $_\n";
  }

  printf KEY_FILE "#\n\n";

  for ( keys %anonKeys ) {
    printf KEY_FILE "%s\t%s\n", $_, $anonKeys{$_};
  }
  close KEY_FILE;
}

