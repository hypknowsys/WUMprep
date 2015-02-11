#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# mergeSessions.pl - Merge a main logfile with an other website's
#		     server log.
# $Revision: 1.5 $
#
# !!! ATTENTION !!!
# This script actually can output timestamp only in a format like
#      07/Apr/2000:10:42:54 +0100
# There still has to be some work in order to make this more
# flexible
#
# REQUIRES: Date::Format
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
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
use POSIX qw(mktime difftime);
use HTTP::Date;
use Date::Format qw(time2str);
use strict;

my %fieldMap;
my %extFieldMap;
my $host;
my $extHost;
my $inputFile;
my $outputFile;

my $HOST_IP = 1;
my $HOST_NAME = 2;

my $config = new WUMprep::Config;
my $parser = new WUMprep::LogfileParser;
my $extParser;

my $extTemplate;
my $extLogfile;
my $filterMode;
my $offset;
my $minTimeDiff;
my $maxTimeDiff;
my $setExtPathTo;
my $i;

# parse command line
while($i < @ARGV) {
    if(lc($ARGV[$i]) =~ /(--extern-template|-t)/) {
	$extTemplate = $ARGV[++$i];
    } elsif(lc($ARGV[$i]) =~ /(-f|--filter)/) {
	$filterMode = 1;
    } elsif(lc($ARGV[$i]) =~ /(-l|--logfile)/) {
	$extLogfile = $ARGV[++$i];
    } elsif(lc($ARGV[$i]) =~ /(-o|--offset)/) {
	$offset = $ARGV[++$i];
    } elsif(lc($ARGV[$i]) =~ /(-min|--min-timediff)/) {
	$minTimeDiff = $ARGV[++$i];
    } elsif(lc($ARGV[$i]) =~ /(-max|--max-timediff)/) {
	$maxTimeDiff = $ARGV[++$i];
    } elsif(lc($ARGV[$i]) =~ /(-r|--replace-path)/) {
	$setExtPathTo = $ARGV[++$i];
    } else {
	die "Illegal command line argumgent: $ARGV[$i]\n";
    }
    $i++;
}

die "You must specify the external logfile (with '-l <filename>')\n"
	if(!$extLogfile);

if($config->operationMode eq 'file') {
	%fieldMap = %{$parser->fieldMap};
} else {
	die "$0\nERROR: Unknown operation mode: ".$config->operationMode."\n";
}

if($filterMode) {
    # use stdin/stdout
    open(INFILE, "-");
    open(OUTFILE, ">-");
    $inputFile = 'from standard input';
    $host = defined($fieldMap{host_ip}) ? 'host_ip' : 'host_dns';
    &main;
} else {
    foreach $inputFile ($config->inputLogs) {
        if($config->operationMode eq 'file') {
            $inputFile = longestFilename($inputFile);
            $outputFile = $inputFile.$config->filterOutputExtension;
            open(INFILE, "<$inputFile") || die "Could not open input file $inputFile\n";
            open(OUTFILE, ">$outputFile") || die "Could not open output file $outputFile\n";
            $host = defined($fieldMap{host_ip}) ? 'host_ip' : 'host_dns';
            &main;
            close INFILE;
            close OUTFILE;
        }
    }
}

close EXT_LOGFILE;

sub main() {
    my $logLine;
    my $extLogLine;
    my $filterDuplicatesExtensions = $config->filterDuplicatesExtensions;
    my $count;
    my $timestamp;
    my $lastTimestamp;
    my $extTimestamp;
    my %linesMerged;
    my $currentSession;
    my $currentSessionIndex;
    my $currentHost;
    my $lineNo;
    my @candidates;
    my @mergeQueue;
    my $tmp;
    my $lastFound;
    my $mergeCount;
    
    &initExternLog;
    
    printf(STDERR "Merging logfile %s into logfile %s...\n", $extLogfile, $inputFile);
    while($logLine = &nextLine) {
        $lineNo++;
        next if /^\#/;   # skip comments 
        
        $currentHost = @$logLine[$fieldMap{$host}];
        $currentSession = @$logLine[$fieldMap{session_id}];
        $currentSessionIndex = @$logLine[$fieldMap{session_index}];
        $timestamp = &convertTimestamp($logLine);
        
        # We keep an array with all the log lines from the extern log
        # having timestamps within the specified timeframe.
        
        # remove outdated lines
        my $cnt = @candidates;
        for($i = 0; $i < $cnt; $i++) {
            $tmp = shift @candidates;
            if(&convertTimestamp($tmp) - $offset 
               >= $timestamp + $minTimeDiff) {
                unshift @candidates, $tmp;
                last;
            }
        }
        
        # now add extern loglines until the next one is too late
        while(&convertTimestamp($extLogLine) - $offset
              <= $timestamp + $maxTimeDiff) {
            push @candidates, $extLogLine;
            $extLogLine = &nextExternLine;
        }
        # Traverse the stack we've just updated and check if we find
        # a line matching the current one from the main log.
        $lastFound = -1;
        for($i = 0; $i < @candidates; $i++) {
            if($candidates[$i][$fieldMap{$host}] eq $currentHost) {
                # We've found a matching line in the extern log and
                # insert it into the main log.
                $candidates[$i][$fieldMap{session_id}] = $currentSession
                    if(defined($fieldMap{session_id}));
                $candidates[$i][$fieldMap{session_index}] = 
                    $currentSessionIndex + $linesMerged{$currentSession}
                if(defined($fieldMap{session_index}));
                $candidates[$i][$fieldMap{path}] = $setExtPathTo
                    if($setExtPathTo);
                &fixTimestamp(\@{$candidates[$i]}, @$logLine[$fieldMap{tz}]);
                push @mergeQueue, \@{$candidates[$i]};
                $linesMerged{$currentSession}++;
                printf STDERR "$0: merging log line into session %s\n", $currentSession;
                $mergeCount++;
                $lastFound = $i;
            }
        }
        
        # Lines that precede the merged ones in the stack should be removed
        # now. The stack is ordered by time, so it would be not correct to
        # keep older lines as candidates.
        for($i = 0; $i <= $lastFound; $i++) {
            shift @candidates;
        }
        
        # If we have a session_index (as in warehouse mode), 
        # update it in the main log if neccessary.
        if($linesMerged{$currentSession} && defined($fieldMap{session_index})) {
            @$logLine[$fieldMap{session_index}] += $linesMerged{$currentSession};
        }
        
        # check the merge queue if there are any lines to insert between the
        # previous line and this one
        $tmp = &convertTimestamp($mergeQueue[0]);
        while($tmp && $tmp >= $lastTimestamp && $tmp < $timestamp) {
            &writeLine(shift @mergeQueue);
            $tmp = &convertTimestamp($mergeQueue[0]);
        }
        
        &writeLine($logLine);
        $lastTimestamp = $timestamp;
        printf STDERR "$0: %d lines processed...\n", $count if(!(++$count % 1000));
    }
    while(@mergeQueue) {
        &writeLine(shift @mergeQueue);
    }
    
    printf STDERR "$0: %d lines processed, %d lines merged - finished\n", $count, $mergeCount;
}


sub convertTimestamp (\$){
    my $logLine = shift();
    my $timestamp;
    
    if(defined($fieldMap{ts_seconds})) {
        $timestamp = 
            str2time(
                     @$logLine[$fieldMap{ts_day}] . '/'
                     . @$logLine[$fieldMap{ts_month}] . '/'
                     . @$logLine[$fieldMap{ts_year}] . ':'
                     . @$logLine[$fieldMap{ts_hour}] . ':'
                     . @$logLine[$fieldMap{ts_minutes}] . ':'
                     . @$logLine[$fieldMap{ts_seconds}]
                     . (defined($fieldMap{tz}) ? ' '.@$logLine[$fieldMap{tz}] : ''));
        
    } else {
        # We assume to have an RFC 1123 timestamp
        $timestamp = str2time(@$logLine[$fieldMap{ts}]);
    }
    
    return $timestamp;
}


sub fixTimestamp(\$,\$) {
    # The external server's system clock might differ from the original
    # server's one. The user can specify this offset as an optional
    # argument to this script. When lines of the external log are inserted
    # into the main logfile, the external log lines timestamp has to be
    # fixed in order to guarantee that the resulting logfile is still
    # order by ascending timestamps (as required by WUM).
    
    my $logLine = shift;
    my $newTimezone = shift;
    my $oldTime = &convertTimestamp($logLine);
    my $newTime = $oldTime - $offset;
    
    (@$logLine[$fieldMap{ts_day}],
     @$logLine[$fieldMap{ts_month}],
     @$logLine[$fieldMap{ts_year}],
     @$logLine[$fieldMap{ts_hour}],
     @$logLine[$fieldMap{ts_minutes}],
     @$logLine[$fieldMap{ts_seconds}],
     @$logLine[$fieldMap{tz}]) = 
         split ':', Date::Format::time2str('%d:%b:%Y:%T:%z', 
                                           $newTime, $newTimezone);
    
}

sub nextLine {
    my $logLineArrayRef;
    if($config->operationMode eq 'file') {
      READ_LINE:
        my $logLine = <INFILE>;
        if($logLine =~ /^\s*\#.*/) {   # skip comments
            &writeLine($logLine);
            goto READ_LINE;
        }
        if($logLine) {
            $logLineArrayRef = $parser->parseLogLine($logLine);
            return $logLineArrayRef;
        } else {
            return undef;
        }
     }
}


sub nextExternLine {
    my $logLineArrayRef;
  READ_LINE:
    my $logLine = <EXT_LOGFILE>;
    my @tmp;
    if($logLine =~ /^\s*\#.*/) {   # skip comments
        goto READ_LINE;
    }
    if($logLine) {
        $logLineArrayRef = $extParser->parseLogLine($logLine);
        # convert the logline to the main log's format
        for(keys(%fieldMap)) {
            @tmp[$fieldMap{$_}] = @$logLineArrayRef[$extFieldMap{$_}]
                if(defined($extFieldMap{$_}));
        }
        $logLineArrayRef = \@tmp;
        return $logLineArrayRef;
    } else {
        return undef;
    }
}


sub writeLine(\$) {
    my $logLineRef = shift();
    if($config->operationMode eq 'file') {
        print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
    }
}


sub initExternLog {
    # open external logfile
    close EXT_LOGFILE;
    open EXT_LOGFILE, "<$extLogfile" || die "$0: could not open logfile $extLogfile\n";
    
    $extParser = new WUMprep::LogfileParser($extTemplate);
    
    %extFieldMap = %{$extParser->fieldMap};
    $extHost = defined($extFieldMap{host_ip}) ? 'host_ip' : 'host_dns';
}











