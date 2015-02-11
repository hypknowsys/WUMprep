#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# urlList.pl - Sample a list of URLs found in log files
# $Revision: 1.4 $
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
use WUMprep::LogfileParser;
use WUMprep::Config;
use URI;
use strict;
use vars qw($i $config $inputFile $outputFile %urls @sortedUrls $htmlOutput);

$config = new WUMprep::Config;

my $parser = new WUMprep::LogfileParser;

# parse command line
while($i < @ARGV) {
    SWITCH: for ($ARGV[$i]) {
        /^-/ && do {

            /-html/ && do {
                $htmlOutput = 1;
                last SWITCH };

            die "Unknown command line argument: $_\n";
        };
    }
    $i++;
}


foreach $inputFile ($config->inputLogs) {
    
    if($config->operationMode eq 'file') {
        $inputFile = longestFilename($inputFile);
        open(INFILE, "<$inputFile") 
            || die "Could not open input file $inputFile\n";
        &ProcessInputLog;
        close INFILE;
    }
}

@sortedUrls = sort keys %urls;


if($htmlOutput) {
    printf "<html>\n<body>\n";
    for(@sortedUrls) {
        printf "<a href='$_' target='_blank'>$_</a>\n";
    }
    printf "</body>\n</html>\n";
} else {
    for(@sortedUrls) {
        printf "$_\n";
    }
}

exit 1;

# ========================================================================
# SUB: ProcessInputLog
# ========================================================================
sub ProcessInputLog {
    my $logLine;
    my $count;
    print STDERR "$0:\nExtracting URLs from log file $inputFile ...\n";

    while($logLine = &nextLine) {
        $urls{URI->new_abs($$logLine{path}, "http://" . $config->domain)} = 1 if($$logLine{status} eq '200');
	printf STDERR "\r%d lines processed...", $count if(!(++$count % 1000));
    }
    printf STDERR "\r%d lines processed                   \n", $count;
    
}


sub nextLine {
    my $logLineHashRef;
    if($config->operationMode eq 'file') {
READ_LINE:
        my $logLine = <INFILE>;
        if($logLine =~ /^\s*\#.*/) {   # skip comments
            &writeLine($logLine);
            goto READ_LINE;
        }
        if($logLine) {
            $logLineHashRef = $parser->parseLogLine($logLine);
            return $logLineHashRef;
        } else {
            return undef;
        }
    }
}


