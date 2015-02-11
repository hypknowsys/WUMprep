#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# grepUrls.pl - Extract URLs from a log file and generate a HTML link list
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
use URI::Escape;
use lib "$FindBin::Bin";
use WUMprep;
use WUMprep::Config;
use WUMprep::LogfileParser;
use strict;

use vars qw($inputFile $outputFile $host $dummy %paths $status $tmp @ts
$timestamp %lastRequest %lastTimestamp %month_map $count $i);

my %fieldMap;

my $HOST_IP = 1;
my $HOST_NAME = 2;

my $config = new WUMprep::Config;
my $parser = new WUMprep::LogfileParser;
my $hostLabel;   # alias for either host_dns or host_ip

if(lc($ARGV[0]) eq '--filter' || lc($ARGV[0]) eq '-f') {
    # use stdin/stdout
    open(INFILE, "-");
    open(OUTFILE, ">-");
    $inputFile = 'from standard input';
    &main;
} else {
    if($config->operationMode eq 'file') {
        %fieldMap = %{$parser->fieldMap};
    } else {
        die "$0\nERROR: Unknown operation mode: ".$config->operationMode."\n";
    }

    $hostLabel = exists($fieldMap{host_ip}) ? 'host_ip' : 'host_dns';

    $count = $config->inputLogs;
    foreach $inputFile ($config->inputLogs) {
        if($config->operationMode eq 'file') {
#            $inputFile = longestFilename($inputFile);
            open(INFILE, "<" . $inputFile) || die "Could not open input file $inputFile\n";
            &main;
            close INFILE;
        }
    }

    my $pathCount = scalar keys %paths;
    printf STDERR "%d URLs found. Sorting the list of URLs... ", $pathCount;
    my @sortList = sort keys %paths;
    printf STDERR "finished.\n";

    # Write list of URLs into the output file
    printf STDERR "Writing the URL list... ";

    my $listDir = "urlList";
    mkdir $listDir;
    my $pageCount = 0;
    my $rowCount = 0;
    my $urlsPerPage = 500;


    open TXTOUT, ">$listDir/urlList-".$config->domain.".txt";
    my $path;
    foreach $path (@sortList) {
        if(! ($rowCount % $urlsPerPage)) {
            if($rowCount > 1) {
                printf OUTFILE "</table><br>\n";
                printf OUTFILE "<a href='urlList" . $pageCount - 1 . ".html'>[&lt;]</a>";
                printf OUTFILE "<a href='index.html#P" . $pageCount ."'>[Back to the Index]</a>";
                printf OUTFILE "<a href='urlList" , $pageCount + 1 , ".html'>[&gt;]</a>" if($rowCount < $pathCount - $urlsPerPage);
                printf OUTFILE "\n</body></html>\n";
            }

            $pageCount++;
            $outputFile = $listDir . "/urlList$pageCount.html";
            open(OUTFILE, ">" . $outputFile) || die "Could not open output file $outputFile\n";
            printf OUTFILE "<html>";
            printf OUTFILE "<head><title>URL list of " . $config->domain . " - Page $pageCount</title></head>\n";
            printf OUTFILE "<body>\n";
            printf OUTFILE "<h1>URL list of " . $config->domain . " - Page $pageCount</h1><p>\n";
            if($rowCount > 1) {
                printf OUTFILE "<a href='urlList" . $pageCount - 1 . ".html'>[&lt;]</a>";
            }
            printf OUTFILE "<a href='index.html#P" . $pageCount ."'>[Back to the Index]</a>";
            if($rowCount < $pathCount - $urlsPerPage) {
                printf OUTFILE "<a href='urlList" . $pageCount + 1 . ".html'>[&gt;]</a>";
            }
            printf OUTFILE "<p>\n<table border='0'>\n";
        }
        $rowCount++;

        $tmp = "http://" . $config->domain . uri_unescape($path);
        printf OUTFILE "<tr><td><a href='$tmp' target='_blank'>$tmp</a></td></tr>\n";
        printf TXTOUT uri_unescape($path) . "\n";
    }

    printf OUTFILE "</table><br>";
    printf OUTFILE "<a href='urlList" . $pageCount - 1 .".html'>[&lt;]&nbsp;</a>";
    printf OUTFILE "<a href='index.html#P" . $pageCount ."'>[Back to the Index]</a>";
    printf OUTFILE "</body></html>\n";

    # create index page
    open(OUTFILE, ">" . $listDir . "/index.html") || die "Could not open output file index.html\n";
    printf OUTFILE "<html>\n";
    printf OUTFILE "<head><title>URL list of " . $config->domain . " - Index Page</title></head>\n";
    printf OUTFILE "<body>\n";
    printf OUTFILE "<h1>URL list of " . $config->domain . " - Index Page</h1><p>\n";
    printf OUTFILE "<table border='1'>\n";
    printf OUTFILE "<tr><td rowspan='2' nowrap><b>Page</b></td><td><b>From URL</b></td></tr>\n";
    printf OUTFILE "<tr><td><b>To URL</b></td></tr>\n";


    $pageCount = 1;
    $rowCount = 0;
    while($rowCount <= $pathCount) {
        printf OUTFILE "<tr><td rowspan='2' nowrap><a href='urlList%d.html' name='P%d'>Page %d</a></td>", $pageCount, $pageCount, $pageCount;
        printf OUTFILE "<td>" . uri_unescape($sortList[$rowCount]) . "</td></tr>\n";
        printf OUTFILE "<td>" . uri_unescape($sortList[$rowCount + $urlsPerPage - 1]) . "</td></tr>\n";
        $pageCount++;
        $rowCount += $urlsPerPage;
    }

    printf OUTFILE "</table></body></html>\n";
    close OUTFILE;
    printf STDERR "finished.\n";
}


sub main() {
    my $logLine;
    my $count;

    printf(STDERR "$0:\nScanning input log file %d: $inputFile ...\n", ++$i);
    while($logLine = &nextLine) {
        next if /^\#/;   # skip comments

        $paths{$$logLine{path}} = 1 ;
        $status = $$logLine{status};
        printf STDERR "\r%d lines scanned...", $count if(!(++$count % 1000));
    }
    printf STDERR "\r%d lines processed - finished.\n", $count;
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


sub writeLine(\$) {
    my $logLineRef = shift();
    if($config->operationMode eq 'file') {
        # file mode - that's simple - thanks to the parser ;-)
        print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
    }
}



