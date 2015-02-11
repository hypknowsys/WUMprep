#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# dnsLookup.pl - Resolve hosts' IP addresses in log files
# $Revision: 1.9 $
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

$VERSION = "$Revision";

package WUMprep;
use Socket;
use FindBin;
use lib "$FindBin::Bin";
use WUMprep;
use WUMprep::Config;
use strict;
use vars qw($config $inputFile $host $dummy $path $status $tmp
  @ts $timestamp %lastRequest %lastTimestamp %month_map);

#$config = new WUMprep::Config;
$config;    # set in &ParseCommandLine

#my $parser = new WUMprep::LogfileParser;
my $parser;    # set in &ParseCommandLine
my $filterMode;
my %fieldMap;
my $outputFile;
my $count;
my $lookupMode;
my $operationMode;
my $LOOK_FOR_NAME = 0;
my $LOOK_FOR_IP   = 1;
my $fieldIn, my $fieldOut;
my $inData;

# Possible values for the host status field. The host status is binary coded,
# i.e., if bit 1 is set, we have IP addresses, and if bit 2 is set,
# we have resolved host names.
my $HOST_IP   = 1;
my $HOST_DNS = 2;

&ParseCommandLine;

if ( $operationMode eq 'filter' ) {
  open( INFILE,  "-" );
  open( OUTFILE, ">-" );
  $inputFile = 'from standard input';
  if ( $lookupMode == $LOOK_FOR_NAME ) {
    $fieldIn  = 'host_ip';
    $fieldOut = 'host_dns';
  }
  else {
    $fieldIn  = 'host_dns';
    $fieldOut = 'host_ip';
  }

  &ProcessInputLog;
}
elsif ( $operationMode eq 'file' ) {
  %fieldMap = %{ $parser->fieldMap };
  if ( $lookupMode == $LOOK_FOR_NAME ) {
    $fieldIn = 'host_ip';
  }
  else {
    $fieldIn = 'host_dns';
  }
  $fieldOut = $fieldIn;    # replace address in file mode

  #    # Our nextLine routine places a hash with the cookies at
  #    # the end of each array, here we map the index.
  #    $fieldMap{cookieHash} = scalar(keys(%fieldMap));

  foreach $inputFile ( $config->inputLogs ) {

    if ( $operationMode eq 'file' ) {
      $inputFile  = longestFilename($inputFile);
      $outputFile = $inputFile . $config->rLookupOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      &ProcessInputLog;
      close INFILE;
      close OUTFILE;
    }
  }
}
else {
  die "$0\nERROR: Unknown operation mode: " . $operationMode . "\n";
}

exit;

# ========================================================================
# SUB: ParseCommandLine
# ------------------------------------------------------------------------
# Parses the command line and sets $config and $parser.
# ========================================================================
sub ParseCommandLine {
  my $currentArg = 0;
  my $arg;
  my $param;
  my $configFile = "$FindBin::Bin/wumprep.conf";
  my $loadArff   = 0;

  # set default values

  my $usage = "Version " . $VERSION . "\n";
  $usage .= "This script takes the following command line arguments:\n";
  $usage .= "-c <filename>: Full path of the WUMprep configuration\n";
  $usage .= "               file to use. Defaults to the wumprep.conf file\n";
  $usage .= "               in the source directory\n";
  $usage .= "-i <filename>: Name of the input INFILE\n";
  $usage .= "               If no input filename is given, the program tries\n";
  $usage .= "               to read from stdin.\n";
  $usage .= "-o <filename>: Name of the output INFILE\n";
  $usage .= "               If no output file is specified, stdout is used.\n";
  $usage .=
    "-ip | -name  : look for IP addresses by hostname or for hostnames\n";
  $usage .=
    "               by IP addresses. (Default: resolve name by address)\n";
  $usage .= "-filter      : run in filter mode, i.e., take input from STDIN";
  $usage .= "               and write\n";
  $usage .= "               output to STDOUT.\n";
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
      if ( $arg eq "-i" ) {    # input INFILE name
        if ( -e ( $ARGV[ ++$currentArg ] ) ) {
          $inputFile = $ARGV[$currentArg];
        }
        else {
          die "\nError: Input INFILE " . $ARGV[$currentArg] . " not found.\n";
        }
      }
      elsif ( $arg eq "-c" ) {
        $param      = $ARGV[ ++$currentArg ];
        $configFile = $param;
      }
      elsif ( $arg eq "-o" ) {    # output INFILE name
        $param      = $ARGV[ ++$currentArg ];
        $outputFile = $param;
      }
      elsif ( $arg eq "-filter" ) {    # filter mode
        $filterMode = 1;
      }
      elsif ( $arg eq "-ip" ) {    # lookup mode
        $lookupMode = $LOOK_FOR_IP;
      }
      elsif ( $arg eq "-name" ) {    # lookup mode
        $lookupMode = $LOOK_FOR_NAME;
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
    } else {
      $operationMode = $config->operationMode;
    }
  }
}

# ========================================================================
# SUB: ProcessInputLog
# ========================================================================
sub ProcessInputLog {
  my %lookupBuffer;
  my $url;
  my $logLine;
  my $lines = 0;

  print STDERR "Performing "
    . (
    $lookupMode == $LOOK_FOR_NAME
    ? 'reverse '
    : ''
    )
    . "DNS lookups for log file $inputFile ...\n";

  while ( $logLine = &nextLine ) {
    if ( $_ =~ /^\#.*/ ) {    # skip comments
      print OUTFILE $_;
      next;
    }

    if ( exists $lookupBuffer{ $$logLine{$fieldIn} } ) {
      $url = $lookupBuffer{ $$logLine{$fieldIn} };
    }
    else {
      if ( $lookupMode == $LOOK_FOR_NAME ) {
        $url = &ReverseLookup( $$logLine{$fieldIn} );
      }
      else {
        $url = &Lookup( $$logLine{$fieldIn} );
      }
      if ( $url eq '' ) {

        # don't put a hostname in the ip field (vice versa is allowed)
        if ( $lookupMode == $LOOK_FOR_NAME ) {
          $url = $$logLine{$fieldIn};
        }
        else {
          $url = $$logLine{$fieldOut};
        }
      }
      $lookupBuffer{ $$logLine{$fieldIn} } = $url;
    }
    $$logLine{$fieldOut} = $url;

    &writeLine($logLine);
    $lines++;
  }

  print STDERR "$lines lines of input processed - bye.\n";
}

# ========================================================================
# SUB: ReverseLookup
# ========================================================================
sub ReverseLookup {
  my $ip = $_[0];

  for ($ip) {
    s/^\s+|\s+$//g;    # remove leading and trailing spaces
  }
  unless ( $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ) {
    return undef;
  }

  my $name = gethostbyaddr( inet_aton($ip), AF_INET );
  return $name;
}

# ========================================================================
# SUB: Lookup
# ========================================================================
sub Lookup {
  my $name = $_[0];
  for ($name) {
    s/^\s+|\s+$//g;    # remove leading and trailing spaces
  }

  print STDERR "Lookup for $name\n";
  my $ip = join ".", unpack( 'C4', gethostbyname($name) );
  return $ip;
}

sub nextLine {
  my $logLineHashRef;
  
  if ( $operationMode =~ /file|filter/ ) {
  READ_LINE:
    my $logLine = <INFILE>;
    
    if ($logLine) {
      if ( $logLine =~ /(?:^\s*\#.*$|^$)/ ) {
        # skip comments and blank lines
        print STDERR "Skipped line: $logLine";
        goto READ_LINE;
      }

      $logLineHashRef = $parser->parseLogLine($logLine);

      # The ARFF parser returns -1 as long
      # as it is parsing the ARFF header
      if ( $logLineHashRef != -1 ) {
        if ( !$inData ) {
          # This happens when the first instance is processed
          %fieldMap = %{$parser->fieldMap};

          my $inputTemplate = $parser->getInputTemplate();
          printf STDERR "input template:  %s\n", $inputTemplate;
          $inputTemplate =~ s/$fieldIn/$fieldOut/;
          printf STDERR "output template: %s\n", $inputTemplate;
          $parser->setOutputTemplate($inputTemplate);
          $fieldMap{$fieldOut} = $fieldMap{$fieldIn};
          $parser->setDatatype($fieldOut, 'string');
          print OUTFILE $parser->outputArffHeader();
          print STDERR $parser->outputArffHeader();
          $inData = 1;  # Execute the above code only once
        }
        return $logLineHashRef;
      } else {
        goto READ_LINE;
      }
    }
    else {
      return undef;
    }
  }
}

sub writeLine(\$) {
  my $logLineRef = shift();
  if ( $operationMode eq 'file' || $operationMode eq 'filter' ) {

    my $logLine = $parser->sampleLogLine($logLineRef) . "\n";

    print OUTFILE $logLine;
  }
}

