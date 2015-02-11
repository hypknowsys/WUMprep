#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# urlList.pl - Sample a list of URLs found in log files
# $Revision: 1.4 $
#
# This script counts the requests for each document in a log file. It is
# actually implemented as a filter, intended to be used in a way like
#    cat logfile.log | perl countRequests.pl > statistics.file
#
# The script makes use of the WUMprep logfile parser. The log file
# format has to be defined in a template file. The name of the
# template file is taken from a wumprep.conf file in the working
# directory.
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
use WUMprep::Config;
use WUMprep::LogfileParser;
use strict;

my $parser = new WUMprep::LogfileParser;

my $logLineRef;
my %requestCount;
my $lineCount;

while(<STDIN>) {
    next if(/^\s*\#*$/); # skip comments and blank lines
    $logLineRef = $parser->parseLogLine($_);
    $requestCount{$$logLineRef{path}}++
    if($$logLineRef{status} =~ /(2\d\d|304)/);  
    if(!(++$lineCount % 10000)) {
        printf STDERR "$0: %d lines processed...\n", $lineCount;
    }
}
printf STDERR "$0: %d lines processed - printing statistics\n", $lineCount;


for(keys(%requestCount)) {
    printf "%s %s\n", $_, $requestCount{$_};
}
