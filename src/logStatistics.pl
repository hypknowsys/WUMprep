#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# logStatistics.pl - Calculate log file statistics
# $Revision: 1.4 $
#
# REQUIRES: HTML::Template
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


# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ATTENTION: As of Nov 1 2000, this script has to be updated to use the
# WUMprep::LogfileParser interface for more flexibility and compatibility
# with the other WUMprep scripts.
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

package WUMprep;

use FindBin;
use lib "$FindBin::Bin";
use WUMprep;
use WUMprep::Config;
use POSIX qw(difftime mktime);
use HTML::Template;
use File::Copy;


$config = new WUMprep::Config;

# This part of the script controls the operation mode.
# The actual statistics processing is done in sub main().
if(lc($ARGV[0]) eq '--filter' || lc($ARGV[0]) eq '-f') {
    # use stdin/stdout
    $statisticsDirectory = "stdin" . $config->statisticsOutputExtension;
    if(-e $statisticsDirectory) {
	printf STDERR "Removing old statistics directory...\n";
	@files = glob $statisticsDirectory."/*";
	unlink @files;
	rmdir $statisticsDirectory;
    }	
    $inputFileBasename = "stdin";
    $inputFile = 'from standard input';
    open(INFILE, "-") || die "Could not open input file $inputFile\n";
    # prepare statistics directory if neccessary
    printf STDERR "Creating statistics directory $statisticsDirectory...\n";
    mkdir $statisticsDirectory, 0777 || die "Could not create statistics directory: $!\n";
    open(OUTFILE, ">".$statisticsDirectory."/index.html") || die "Could not open output file $statisticsDirectory/index.html\n";
    &main;
} else {
    # use disk files as specified in config file
    foreach $inputFile ($config->inputLogs) {
	$statisticsDirectory = $inputFile . $config->statisticsOutputExtension;
	if(-e $statisticsDirectory) {
		printf STDERR "Removing old statistics directory...\n";
		@files = glob $statisticsDirectory."/*";
		unlink @files;
		rmdir $statisticsDirectory;
	}	
   
	$inputFileBasename = $inputFile;
	$inputFile = longestFilename($inputFile);
	open(INFILE, "<$inputFile") || die "Could not open input file $inputFile\n";

	# prepare statistics directory if neccessary
	printf STDERR "Creating statistics directory $statisticsDirectory...\n";
	mkdir $statisticsDirectory, 0777 || die "Could not create statistics directory: $!\n";
	    
        open(OUTFILE, ">".$statisticsDirectory."/index.html") || die "Could not open output file $statisticsDirectory/index.html\n";
        &main;
        close(INFILE);
        close(OUTFILE);
    }
}


# Here begins the interesting part of the script.
sub main() {
    $firstRun = 1;

    
    print STDERR "Calculating statistics for log $inputFile ...\n";

    # analyze the logfile
    while(<INFILE>) {
	($ip,$timestamp,$method,$path,$code,$size,$referrer,$agent) =
	    /(\S*) \S* \S* \[([^\]]*)\] \"(\S*) (\S*) [^\"]*\" ([\d-]*) ([\d-]*) \"([^\"]*)\" \"([^\"]*)\" \"[^\"]*\"/;

	next if($ip eq '');   # skip empty lines

	# extract the session ID
	$sessionizeSeparator = $config->sessionizeSeparator;
	$ip =~ /\Q$sessionizeSeparator\E/;
	$sessionId = $`;

	# convert the timestamp into a 
	@ts = $timestamp =~ m/(\d*)\/(\S*)\/(\d*):(\d*):(\d*):(\d*)/;
	$currentTimestamp = mktime($ts[5], $ts[4], $ts[3], $ts[0], $month_map{$ts[1]}, $ts[2] - 1900);

	# count log records
	$recordCount++;

	# count number of requests for each page
	$requestCount{$path}++;

	# store the first timestamp of each session
	if(!$sessionLength{$sessionId}){
	    $firstTimestamp{$sessionId} = $currentTimestamp;
	}
	
	# length of sessions in requests
	$sessionLength{$sessionId}++;

	# make a note in which sessions a page appears at least once
	push @{$occurrenceInSessions{$path}}, $sessionId if !grep(/$sessionId/, @{$occurrenceInSessions{$path}});

	# page view time
	if(exists($lastTimestamp{$sessionId})) {
	    $viewTime = difftime($currentTimestamp, $lastTimestamp{$sessionId});
	    push @{$pageViewTimesSession{$sessionId}}, $viewTime;
	    push @{$pageViewTimesPage{$lastPath{$sessionId}}}, $viewTime;
	    
	    $pageHistogram{$lastPath{$sessionId}}{$viewTime}++; # if($config->statisticsExport);
	    $totalViewTimeSession{$sessionId} += $viewTime;
	    $totalViewTimePage{$lastPath{$sessionId}} += $viewTime;
	}

	# save timestamp for the computation of next page view time
	$lastTimestamp{$sessionId} = $currentTimestamp;
	$lastPath{$sessionId} = $path;
    }

    # calculate statistics and output

    # logfile statistics
    $sessionCount = keys %lastTimestamp;

    # session statistics
    @keys = keys %sessionLength;

    # calculate mean values
    for(@keys) {
	$sessionLengthSum += $sessionLength{$_};
	$sessionDurationSum += difftime($lastTimestamp{$_}, $firstTimestamp{$_});
    }
    $avgSessionLength = $sessionLengthSum / $sessionCount;
    $avgSessionDuration = $sessionDurationSum / $sessionCount;

    # calculate standard deviations
    for(@keys) {
	$varianceSessionLength += ($avgSessionLength - $sessionLength{$_})**2;
	$varianceSessionDuration += (difftime($lastTimestamp{$_}, $firstTimestamp{$_}) - $avgSessionDuration) ** 2;
    }
    $varianceSessionLength /= $sessionCount;
    $varianceSessionDuration /= @keys;

   
    @keys = sort keys %totalViewTimePage;
    for(@keys) {
	$avgViewTime{$_} = $totalViewTimePage{$_} / @{$pageViewTimesPage{$_}};
	$avgViewTimeSum += $avgViewTime{$_};
    }

    $avgViewTime = $avgViewTimeSum / keys(%avgViewTime);

    $variance = 0;
    for(%avgViewTime) {
	$variance += ($_ - $avgViewTime) ** 2;
    }
    $pageViewTimeStdDev = sqrt($variance / keys(avgViewTime));

    # create a template object for the report
    $report = HTML::Template->new( filename =>
         $config->htmlTemplateDir."/".$config->statisticsTemplateFile );

    $report->param( LOG_NAME => $inputFileBasename,
		    RECORD_COUNT => $recordCount,
		    SESSION_COUNT => $sessionCount,
		    AVG_VIEW_TIME => sprintf("%.5f", $avgViewTime),
		    PAGE_VIEW_TIME_STDDEV => sprintf("%.5f",$pageViewTimeStdDev),
		    AVG_SESSION_LENGTH => sprintf("%.5f", $avgSessionLength),
		    STDDEV_SESSION_LENGTH => sprintf("%.5f", sqrt($varianceSessionLength)),
		    AVG_SESSION_DURATION => sprintf("%.5f", $avgSessionDuration),
		    STDDEV_SESSION_DURATION => sprintf("%.5f", sqrt($varianceSessionDuration) ));
		    

#      printf OUTFILE "[logfile summary]\n";
#      printf OUTFILE "Number of requests: %d\n", $recordCount;
#      printf OUTFILE "Number of sessions: %d\n", $sessionCount;
#      printf OUTFILE "Average page view time: %.3f seconds\n", $avgViewTime;
#      printf OUTFILE "Page view time standard deviation: %.3f seconds\n", $pageViewTimeStdDev;
    
#      printf OUTFILE "\n[sessions summary]\n";
#      printf OUTFILE "Average session length: %.3f requests\n", $avgSessionLength;
#      printf OUTFILE "Session length standard deviation: %.3f requests\n", sqrt($varianceSessionLength);
#      printf OUTFILE "Average session duration: %.3f seconds\n", $avgSessionDuration;
#      printf OUTFILE "Session duration standard deviation: %.3f seconds\n", sqrt($varianceSessionDuration);

#      # page statistics
#      printf OUTFILE "\n[page statistics]\n";
#      printf OUTFILE "# Line format:\n";
#      printf OUTFILE "# page|# of requests|min PVT|max PVT|avg. Page View Time|stddev. of PVT|in %% of sessions\n";

    @pageStatistics = ();
    $rowCount = 0;

    foreach(sort keys %requestCount) {
	my %rowData = ();
	$minTime = 999999999;
	$maxTime = 0;
	$variance = 0;
	if(@{$pageViewTimesPage{$_}}) {
	    foreach $viewTime (@{$pageViewTimesPage{$_}}) {
		$variance += ($viewTime - $avgViewTime{$_}) ** 2;
		$minTime = $viewTime if($viewTime < $minTime);
		$maxTime = $viewTime if($viewTime > $maxTime);
	    }
	    $stdDev = sqrt($variance/@{$pageViewTimesPage{$_}});
	} else {
	    $avgTime = 0;
	    $stdDev = 0;
	}
	$minTime = 0 if($minTime = 999999999);

	$gifFile{$_} = $_ . ".gif";
	$gifFile{$_} =~ s![/\?\+]!_!g;
	$gifFile{$_} =~ s/^_//;

	$rowData{PATH} = $_;
	$rowData{GIF} = $gifFile{$_};
	$rowData{REQUEST_COUNT} = $requestCount{$_};
	$rowData{MIN_PVT} = $minTime;
	$rowData{MAX_PVT} = $maxTime;
	$rowData{AVG_PVT} = sprintf("%.3f", $avgViewTime{$_});
	$rowData{PVT_STDDEV} = sprintf("%.3f", $stdDev);
	$rowData{PERCENT_SESSIONS} = 
	    sprintf("%.5f", (@{$occurrenceInSessions{$_}} / $sessionCount) * 100);
	$rowData{ODD_LINE} = $rowCount++ % 2;
        
	push(@pageStatistics, \%rowData);
    }
    $report->param( PAGE_STATISTICS_BY_URL => \@pageStatistics );

    @pageStatistics = ();
    $rowCount = 0;

    foreach(sort {$requestCount{$b} <=> $requestCount{$a}} keys %requestCount) {
	my %rowData = ();
	$minTime = 999999999;
	$maxTime = 0;
	$variance = 0;
	if(@{$pageViewTimesPage{$_}}) {
	    foreach $viewTime (@{$pageViewTimesPage{$_}}) {
		$variance += ($viewTime - $avgViewTime{$_}) ** 2;
		$minTime = $viewTime if($viewTime < $minTime);
		$maxTime = $viewTime if($viewTime > $maxTime);
	    }
	    $stdDev = sqrt($variance/@{$pageViewTimesPage{$_}});
	} else {
	    $avgTime = 0;
	    $stdDev = 0;
	}
	$minTime = 0 if($minTime = 999999999);

	$rowData{PATH} = $_;
	$rowData{GIF} = $gifFile{$_};
	$rowData{REQUEST_COUNT} = $requestCount{$_};
	$rowData{MIN_PVT} = $minTime;
	$rowData{MAX_PVT} = $maxTime;
	$rowData{AVG_PVT} = sprintf("%.3f", $avgViewTime{$_});
	$rowData{PVT_STDDEV} = sprintf("%.3f", $stdDev);
	$rowData{PERCENT_SESSIONS} = 
	    sprintf("%.5f", (@{$occurrenceInSessions{$_}} / $sessionCount) * 100);
	$rowData{ODD_LINE} = $rowCount++ % 2;
        
	push(@pageStatistics, \%rowData);
    }
    $report->param( PAGE_STATISTICS_BY_ACCESSES => \@pageStatistics );

    print OUTFILE $report->output();
    copy $config->htmlTemplateDir."/WumReport.css", $statisticsDirectory."/WumReport.css";

    if($config->statisticsExport) {
	$graphicsLeft = scalar keys %pageHistogram;
	print STDERR "Drawing histograms...\n";
	# writing histogram files and GNU-Plot input files
	foreach $page ( sort keys %pageHistogram) {
	    print STDERR $graphicsLeft-- . " graphics left.\n";
	    open(DATFILE, ">".$statisticsDirectory . "/tmp") || die "Could not create datfile ".$statisticsDirectory . "/tmp\n";
	    print DATFILE "set term pbm; set title 'Page View Times for $page'; set xlabel 'sec'; set ylabel '#'; plot [-0.5:] [0:] '-' notitle with impulses\n";
	    foreach $key (keys %{$pageHistogram{$page}}) {
		printf DATFILE "%d %d\n", $key, $pageHistogram{$page}{$key};
	    }
	    close DATFILE;
	    system "gnuplot ". $statisticsDirectory . "/tmp | ppmtogif > " . $statisticsDirectory."/".$gifFile{$page};
	}
    }
}



__END__

=head1 NAME

logStatistics.pl - Calculate statistics about logfiles

=head1 DESCRIPTION

This script is part of the B<WUMprep> suite of Perl scripts for data
preparation. It calculates statistics for the logfile, for single HTML
pages and for sessions.

B<This script's internals are deprecated. It must be updated in order
to exploit the improved flexibility of the WUMprep log file template
mechanism.>

=head2 The statistics

Statistics for the logfile:

=over 4

=item *

Number of requests in log (= number of lines)

=item *

Number of sessions

=item *

Average page view time (not yet implemented)

=item *

Standard deviation of average page view time (not yet implemented)

=back

Statistics for sessions:

=over 4

=item *

Average page requests per session (= session length)

=item *

Standard deviation of session length

=item *

Average session duration

=item *

Standard deviation of session duration

=back

Statistics for HTML pages:

=over 4

=item *

Absolute number of requests

=item *

Average page view time

=item *

Standard deviation of page view time

=item *

Max page view time

=item *

Min page view time

=item *

Occurrence in % of sessions

=back

=head2 Output

The script relies on the log being sessionized.

The results are stored in a text file named like the logfile but with
the (default) extension ".stats".

The statistics are intended to be used for other data preparation
tasks. For example, the average page view time in conjunction with the
standard deviation might be used for heuristics defining session
borders or to guess which requests stem from robots.







