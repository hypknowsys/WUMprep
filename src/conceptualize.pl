#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# mapReTaxonomies.pl - Map URLs from a log file onto a user-defined
#                      taxonomy using regular expressions
# $Revision: 1.1 $
#
# A taxonomy file contains contains one line for each document of a
# web site. Columns are separated by whitespace (blank, tabs).
# Comments are marked by "#" - just like this comment is.
# The last columnt which is not a comment is expected to be a valid
# URL of the web site (better: a valid path/filename combination,
# e.g., "/intro/index.html"). The columns before the last non-comment
# column are taken as concepts to map to the URL.
# Lines which start with comments are ignored. All lines not starting
# with comments must have the same number of columns.
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
use WUMprep::LogfileParser;
use strict;

my @taxonomies;    # takes an array of references to taxonomy hashes
use vars qw($inputFile);

my $config;
my $parser;
my $outputFile;

my $taxonomyCount;    # number of taxonomies
my @taxonomyLabel;
my @lineCount;
my @unmapped;
my %mappingHistory;
my $path;
my $newPath;
my $operationMode;
my $inData;
my %fieldMap;
my $hostField;
my $config;           # set in parseCommandLine
my $parser;           # set in parseCommandLine

&parseCommandLine;

for ( @{ $config->taxonomyDefs } ) {
  printf STDERR "Reading taxonomy definition file $_\n";
  &initTaxonomies($_);
}

open ERRLOG, ">unmappedUrls.html";
printf ERRLOG "<html>\n<head><title>unmapped URLs</title></head>\n<body>\n";

if ( $config->taxonomyMapLog ) {
  open MAPPING_LOG, ">" . $config->taxonomyMapLog
    or die "ERROR: Could not open $config->taxonomyMapLog for output\n";
}

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
  }
  else {
    die "$0\nERROR: Unknown operation mode: " . $operationMode . "\n";
  }

  foreach $inputFile ( $config->inputLogs ) {
    if ( $config->operationMode eq 'file' ) {
      $inputFile  = longestFilename($inputFile);
      $outputFile = $inputFile . $config->taxonoMapOutputExtension;
      open( INFILE, "<$inputFile" )
        || die "Could not open input file $inputFile\n";
      open( OUTFILE, ">$outputFile" )
        || die "Could not open output file $outputFile\n";
      &main;
      close INFILE;
      close OUTFILE;
    }
  }

  for ( my $i = 1 ; $i <= $taxonomyCount ; $i++ ) {
    printf ERRLOG "<h1>Unmatched URLs for taxonomy %s</h1>\n",
      $taxonomyLabel[$i];
    for ( sort keys( %{ $unmapped[$i] } ) ) {
      printf ERRLOG "<a href='%s' target='_blank'>%s</a><br>\n",
        "http://" . $config->domain . $_, $_;
    }
  }

  printf ERRLOG "</body>\n</html>\n";
  close ERRLOG;
  close MAPPING_LOG if ( $config->taxonomyMapLog );
}

sub main {
  my $logLine;
  my $count;
  my $i;
  my $j;
  my @found;
  my $completeMatch;
  my $noMatch;

  print STDERR "$0:\nMapping URLs to concepts for $inputFile ...\n";
  $noMatch = 0;
  while ( $logLine = &nextLine ) {
    undef @found;
    $path    = lc( $$logLine{path} );
    $i       = 0;
    $newPath = undef;

    # We can map an URL to an arbitrary number of taxonomies at a time
    # (to cover multiple conceptual dimensions). The concepts become
    # separated by underscores.
    for ( $i = 1 ; $i <= $taxonomyCount ; $i++ ) {
      for ( $j = 1 ; $j <= $lineCount[$i] ; $j++ ) {
        if ( $path =~ m{$taxonomies[$i][$j][1]}i ) {
          $newPath .= '_' if $newPath ne '';
          $newPath .= $taxonomies[$i][$j][0];
          $found[$i] = 1;
          last;
        }
      }
    }

    # URLs will be replaced by the conceptual terms comprising $newPath
    # only if there was a mach in any of the $taxonomyCount
    # dimensions. Otherwise, we keep the original path.
    $completeMatch = 1;
    for ( $i = 1 ; $i <= $taxonomyCount ; $i++ ) {
      $completeMatch = 0 if ( !$found[$i] );
    }

    if ( $completeMatch == 1 ) {
      $mappingHistory{$path} = $newPath;
      $$logLine{path} = $newPath;
    }
    else {
      for ( $i = 1 ; $i <= $taxonomyCount ; $i++ ) {
        $unmapped[$i]{$path} = 1 if ( !$found[$i] );
      }
      $noMatch = 1;
    }
    &writeLine($logLine);
    printf STDERR "\r%d lines processed...", $count if ( !( ++$count % 1000 ) );
  }
  printf STDERR "\r%d lines processed - finished\n", $count;

  &createProtocol;

  printf STDERR "\nATTENTION: Not all URLs could be mapped.\n\n" if ($noMatch);
}

sub initTaxonomies(\$) {
  my @concepts;
  my $path;
  my $lineCount;

  open TAX_DEFS, "<$_[0]"
    || die "$0: Could not open taxonomy definition file $_[0]\n";

  # Actually, we don't perform any itegrity checks on the taxonomy
  # definition files. This is left open for the next development
  # effort - so take care when defining your taxonomy defs ;-)
  # See the comments on top of this document for a description of
  # a taxonomy definition file's format.

  $taxonomyCount = 0;
  $lineCount[$taxonomyCount] = 0;

  while (<TAX_DEFS>) {
    s/\#.*$//;    # remove comments
    next if (/^\s*$/);    #skip comment-only and blank lines

    if (/^\[(.*)\]/) {
      printf STDERR "   Reading taxonomy $1\n";
      $taxonomyCount++;
      $taxonomyLabel[$taxonomyCount] = $1;
      $lineCount[$taxonomyCount]     = 0;
    }
    elsif (/^\S+\s+\S+/) {
      $lineCount[$taxonomyCount]++;
      (
        $taxonomies[$taxonomyCount][ $lineCount[$taxonomyCount] ][0],
        $taxonomies[$taxonomyCount][ $lineCount[$taxonomyCount] ][1]
        )
        = split /\s+/;
    }
  }

  close TAX_DEFS;
  die
"No taxonomies found in definition file.\nCheck the file format.\nThere must be at lease one label.\n"
    if ( $taxonomyCount == 0 );
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
    if ( $config->taxonomyMapLog ) {
      printf MAPPING_LOG "\"$newPath\",\"$path\"\n";
    }

    # file mode - that's simple - thanks to the parser
    print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
  }
  else {
    die sprintf "$0: writeLine not suppported for operation mode %s\n",
      $config->operationMode;
  }
}

sub createProtocol {

  # RESUME HERE WITH WRITING A PROTOCOL FILE CONTAINING UNAMPPED URLS AND
  # A LIST OF MAPPINGS (GENERATED USING %mappingHistory).

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

  my $usage = <<EOT;
This script takes the following command line arguments:
-c <filename>: Full path of the WUMprep configuration
               file to use. Defaults to the wumprep.conf file
               in the source directory
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
