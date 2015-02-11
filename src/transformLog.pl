#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# transformLog.pl - Transform a log file from one format into another
# $Revision: 1.4 $
#
# See the transformSettings section of wumprep.conf for some usage hints
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

use vars qw($inputFile $outputFile $count $i %fieldMap
            $transformMode %sessionVectors %sessionSeen %dimensions
            $withEntryPage);

my $config = new WUMprep::Config;
my $parserIn = new WUMprep::LogfileParser;
my $parserOut = new WUMprep::LogfileParser $config->transformTemplate;

if(lc($ARGV[0]) eq '--filter' || lc($ARGV[0]) eq '-f') {
    # use stdin/stdout
    open(INFILE, "-");
    open(OUTFILE, ">-");
    $inputFile = 'from standard input';
    &main;
} else {
    if($config->operationMode eq 'file') {
        # do nothing
    } else {
        die "$0\nERROR: Unknown operation mode: ".$config->operationMode."\n";
    }
    
    $transformMode = uc($config->transformMode);
    $withEntryPage = $config->transformSessionVectorWithEntryPage;
    die "$0\nERROR: Unknown tranformation mode '$transformMode'.\n"
        if($transformMode ne "SEQUENCE" && $transformMode ne "SESSION_VECTOR");

    printf STDERR "$0\nOperating in $transformMode mode.\n";

    $count = $config->inputLogs;

    if($transformMode eq "SESSION_VECTOR") {
        open(OUTFILE, ">" . $config->transformSessionVectorFile) || die "$0\nCould not open output file $config->transformSessionVectorFile\n";
    }

    foreach $inputFile ($config->inputLogs) {
        if($config->operationMode eq 'file') {
            open(INFILE, "<$inputFile") || die "$0\nCould not open input file $inputFile\n";
            if($transformMode eq "SEQUENCE") {
                $outputFile = $inputFile.$config->transformOutputExtension;
                open(OUTFILE, ">$outputFile") || die "$0\nCould not open output file $outputFile\n";
                &mainSequenceMode;
                close OUTFILE;
            } else {
                &mainSessionVectorMode;
            }
            close INFILE;
        } else {   # operation mode warehouse
            # Not suported -> Script already died!
        }
    }

    if($transformMode eq "SESSION_VECTOR") {
        &writeSessionVectors;
        close OUTFILE;
    }
}


sub mainSequenceMode() {
    my $logLine;
    my $count;

    printf(STDERR "$0:\nTransforming input log file %d: $inputFile ...\n", ++$i);
    while($logLine = &nextLine) {
        &writeLine($logLine);
        printf STDERR "\r%d lines processed...", $count if(!(++$count % 1000));
    }
    printf STDERR "\r%d lines processed - finished\n", $count;
}


sub mainSessionVectorMode() {
    my $logLine;
    my $count;

    printf(STDERR "$0:\nTransforming input log file %d: $inputFile ...\n", ++$i);
    while($logLine = &nextLine) {
        # do we have a sessionized log?
        die "$0\nERROR: Log must be sessionized (check logfile template).\n"
            if($$logLine{session_id} eq '');

        if($withEntryPage && !$sessionSeen{$$logLine{session_id}}) {
            $sessionVectors{$$logLine{session_id}}{START} = $$logLine{path};
            $sessionSeen{$$logLine{session_id}} = 1;
        }

        $sessionVectors{$$logLine{session_id}}{$$logLine{path}} += 1;
        $dimensions{$$logLine{path}} = 1;
        printf STDERR "\r%d lines processed...", $count if(!(++$count % 1000));
    }
    printf STDERR "\r%d lines processed - finished\n", $count;
}


sub writeSessionVectors() {
    my $count;
    my $sessId;
    my @dimensions;

    my $max = scalar keys %sessionVectors;

    printf(STDERR "$0:\nWriting %d session vectors in file %s...\n",
           $max, $config->transformSessionVectorFile);
    
    @dimensions = sort keys %dimensions;

    printf OUTFILE "SESSION_ID";
    if($withEntryPage) {
        printf OUTFILE "," . "START";
    }
    for(@dimensions) {
        printf OUTFILE "," . $_;
    }

    printf OUTFILE "\n";

    foreach $sessId (keys %sessionVectors) {
        printf OUTFILE $sessId;
        if($withEntryPage) {
            printf OUTFILE "," . $sessionVectors{$sessId}{START};
        }
        for(@dimensions) {
            printf OUTFILE ",%0d", $sessionVectors{$sessId}{$_};
        }
        printf STDERR "\r%d vectors processed (%d\%)...", $count, $count / $max * 100
            if(!(++$count % 1000));

        printf OUTFILE "\n";
    }
    
    printf STDERR "\r%d vectors processed (100\%).        \n", $count;
}

sub nextLine {
    my $logLineHashRef;
READ_LINE:
    my $logLine = <INFILE>;
    if($logLine =~ /^\s*\#.*/) {   # skip comments
        &writeLine($logLine);
        goto READ_LINE;
    }
    if($logLine) {
        $logLineHashRef = $parserIn->parseLogLine($logLine);
        return $logLineHashRef;
    } else {
        return undef;
    }
}


sub writeLine(\$) {
    my $logLineRef = shift();

    $parserOut->setMonthAlpha($parserIn->getMonthAlpha());
    print OUTFILE $parserOut->sampleLogLine($logLineRef) . "\n";
}




















