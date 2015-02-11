#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# removeRobots.pl - Remove robot hits from a Web log file
# $Revision: 1.4 $
#
# THIS SCRIPT IS DEPRECATED! USE detectRobots.pl INSTEAD.
#
# This script is based on the BotWatch.pl script written by Simon Wilkinson
# See http://www.tardis.ed.ac.uk/~sxw/robots/botwatch.html
# This script has to pass the input log two times - that is why it cannot
# be implemented as a filter (stdin->stdout).
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
use POSIX qw(mktime difftime ctime);
#use strict;

my $parser = new WUMprep::LogfileParser;

$config = new WUMprep::Config;

if($config->robotsDB ne "") {
    $robotsDB = $config->robotsDB;
} else {
    $robotsDB="$FindBin::Bin/indexers.lst";
}

$revision="Revision: 0.02";

$extendedlog=1;
$loggingIPs=1;
$debug=0;
$notifyevery=1000;
$notifycount=0;
$notifyticker=0;
$nodnslookups=1;
$sessionized=0;
$sessionizeSeparator = undef;

$unknowncount=0;

#  if(@ARGV == 0) {
#      print "Usage: [perl ]$0 infile [outfile]\n";
#      print "If outfile is omitted, output is directed to stdout.\n\n";
#      exit(0);
#  }

# parse command line
while($i < @ARGV) {
    if($ARGV[$i] eq '-i') {
		$inputFile = $ARGV[++$i];
    } elsif($ARGV[$i] eq '-o') {
		$outputFile = $ARGV[++$i];
    } else {
		die "Illegal command line argumgent: $ARGV[i]";
    }
    $i++;
}

printf(STDERR "Processing list of known robots\n");
# Read in our robots list
open(ROBOTS,$robotsDB) ||
    die "Cannot read in the list of robots: " . $robotsDB . "\n";

while(<ROBOTS>) {
#    next if (/^\s*#/);
    
    if (/ignore-useragent:\s*(.*)$/) {
        push(@ignore,$1);
    }
    if (/ignore-after:\s*(.*)$/) {
        push(@ignore_after,$1);
    }
    if (/robot-id:\s*(.*)$/) {
	$current_ua=$1;
    }
    if (/robot-name:\s*(.*)$/) {
	$robot_name{$current_ua}=$1;
    }
    if (/robot-cover-url:\s*(.*)$/) {
	$robot_url{$current_ua}=$1;
    }
   
    if (/robot-host:\s*(\S.*)$/) {
	$robot_host{$current_ua}=$1;
    }

    if (/robot-hostIP:\s*(\S.*)$/) {
	$robot_ip{$current_ua}=$1;
    }

    if (/robot-useragent:\s*(\S.*)$/) {
  	$robot_agent{$current_ua}=$1;
    }
}

if($inputFile eq '') {
    foreach $inputFile ($config->inputLogs) {
	$inputFile = longestFilename($inputFile);
	$outputFile = $inputFile.$config->rmRobotsOutputExtension;
	open(INFILE, "<$inputFile") || die "Cannot open inputfile $inputFile.\n";
	open(OUTFILE, ">$outputFile") || die "Cannot open file $outputFile for output.\n";
	&main;
	close INFILE;
	close OUTFILE;
    }
} else {
    open(INFILE, "<".$inputFile) || die "Cannot open inputfile $inputFile.\n";
    if($outputFile ne '') {
	open(OUTFILE, ">$outputFile") || die "Cannot open file $outputFile for output.\n";
    } else {
	open(OUTFILE, ">-");
    }
    &main;
}


sub main {
# Do an initial pass of the file. Store as IP, count and transfer size

    printf(STDERR "Removing robots from log $inputFile ...\n");

    while($logLine = &nextLine) {
	$notifyticker++;
	if ($notifyticker > $notifyevery) {
	    $notifycount+=$notifyevery;
	    printf(STDERR "Processed %s lines of log\r",$notifycount);
	    $notifyticker=0;
	}

	if (!defined($firstdate)) {


            if(defined($$logLine{host_ip})) {
                $ip = $$logLine{host_ip};
                $loggingIPs = 1;
            } else {
                $ip = $$logLine{host_dns};
                $loggingIPs = 0;
            }
            $method = $$logLine{method};
            $path = $$logLine{path};
            $code = $$logLine{status};
            $size = $$logLine{sc_bytes};
            $referrer = $$logLine{referrer};
            $agent = $$logLine{agent};

            $firstdate = $$logLine{ts_day} . "/" . $$logLine{ts_month} . "/" . $$logLine{ts_year} . ":" . $$logLine{ts_hour} . ":" . $$logLine{ts_minutes} . ":" . $$logLine{ts_seconds} . " " . $$logLine{ts_tz};

            if(defined($$logLine{host_ip})) {
                $loggingIPs = 1;
            }

            if(defined $$logLine{agent}) {
                $loggingAgents = 1;
                $extendedLog = 1;
            }
            
            if(defined $$logLine{cookie}) {
                $cookieLog = 1;
            }

            
#	    # remove session ID from $ip if the log has been sessionized
	    $sessionizeSeparator = $config->sessionizeSeparator;
	    
	    if($ip =~ /\Q$sessionizeSeparator\E/) {
		$ip = $';
		$sesionId = $`;
	    } else {
		$sessionId = $ip;
	    }
	   
	    $sessionId_map{$sessionId} = $ip;
		
	} else { 

            if(defined($$logLine{host_ip})) {
                $ip = $$logLine{host_ip};
                $loggingIPs = 1;
            } else {
                $ip = $$logLine{host_dns};
                $loggingIPs = 0;
            }
            $method = $$logLine{method};
            $path = $$logLine{path};
            $code = $$logLine{status};
            $size = $$logLine{sc_bytes};
            $referrer = $$logLine{referrer};
            $agent = $$logLine{agent};

	    # remove session ID if the log has been sessionized
	    if($sessionizeSeparator ne '' && $ip =~ /\Q$sessionizeSeparator\E/) {
		$ip = $';
		$sessionId = $`;
	    } else {
		$sessionId = $ip;
	    }
	}

	$sessionId_map{$sessionId} = $ip;

	$total_hits+=1;
	$total_bytes+=$size;

	# Robots generally don't send POSTs (they can't handle forms)
	next if ($method ne "GET" && $method ne "HEAD");

	# Measure the page view time and save the top value per session
	$lastdate = mktime($$logLine{ts_seconds}, $$logLine{ts_minutes}, $$logLine{ts_hour}, $$logLine{ts_day}, $$logLine{ts_month}, $$logLine{ts_year} - 1900);

        if(exists($lastTimestamp{$sessionId}) && difftime($lastdate, $lastTimestamp{$sessionId}) > $maxViewTime{$sessionId}) {
	    $maxViewTime{$sessionId} = difftime($lastdate, $lastTimestamp{$sessionId});
#            printf STDERR "%.2f\n", $maxViewTime{$sessionId} / 60;
	}

	$lastTimestamp{$sessionId} = $lastdate;

	# If we've got a valid User Agent field that we've seen as a robot before
	if (defined($agent) && ($found = $agent_map{$agent}) ) {
	    $robot_hits{$found}+=1; $robot_hits+=1;
	    $robot_bytes{$found}+=$size; $robot_bytes+=$size;
	    if (!defined($seenfromlog{$found,$ip})) {
		$seenfromlog{$found,$ip}=1;
		$robot_seenfrom{$found}.=" ".$ip;
	    }
            $robot_detectedBy{$ip} .= "agent ";
	    next;
	}
	
	# Now - do we have an IP address that we've seen as a robot before
	# Oh well, we didn't manage to work anything out given the UA.
	# Next, we can try comparing their IP address with those that have
	# already fetched robots.txt files, or been flagged in the cache as
	# being a robot.
	if ($found = $ip_map{$ip}) {
	    $robot_hits{$found}+=1; $robot_hits+=1;
	    $robot_bytes{$found}+=$size; $robot_bytes+=$size;
	    next;
	}
	
	# Nope, we haven't seen an access from this site / UA that we've decided
	# is a robot yet.
	#
	# Now, providing we have a UA that we haven't seen before, we check it 
	# with our list of robot UAs

	if (defined($agent) && !defined($agent_fail{$agent})) {
	    if ($found= &robot_ua($agent)) {
		$agent_map{$agent} = $found;
		next if $agent eq ignore;
		$robot_hits{$found}+=1; $robot_hits+=1;
		$robot_bytes{$found}+=$size; $robot_bytes+=$size;
		if (!defined($seenfromlog{$found,$ip})) {
		    $seenfromlog{$found,$ip}=1;
		    $robot_seenfrom{$found}.=" ".$ip;
		}
		next;
	    }
	    $agent_fail{$agent}=1;
	}

	# Nope - not a known robot UA.
	# Now check to see if the request is coming from a robot sites IP

	if (!defined($ip_fail{$ip})) {
	    if ($ipfound = &robot_ip($ip)) {
		$ip_map{$ip}=$ipfound;
		$robot_hits{$ipfound}+=1; $robot_hits+=1;
		$robot_bytes{$ipfound}+=$size; $robot_bytes+=$size;
		if (!defined($seenfromlog{$ipfound,$ip})) {
		    $seenfromlog{$ipfound,$ip}=1;
		    $robot_seenfrom{$ipfound}.=" ".$ip;
		}
        $robot_detectedBy{$ip} .= "address ";
		next;
	    }
	    $ip_fail{$ip}=1;
	}
	
	# Still nothing! Now lets see if this access is for a robots.txt
	# file
        $robotsTxt = false;
	if ($path =~ /robots\.txt/) {
	    # They requested a robots.txt file - flag them as a robot
	    # 
	    # As we didn't spot this request previously, it must be from a 
	    # robot that isn't in any of our reference files or that can't
	    # be detected from them, if we're using logs without referer
	    # details - so we flag the request as coming from an unknown
	    # robot.
	    #
	    # We also assume that all connections comming from this IP
	    # have also been robots

	    $ip_map{$ip}=$found="UNKNWN".$unknown_count;
	    $unknown_count++;

	    $unknown_agent{$found}=$agent;

	    $robot_hits{$found}+=$ip_past_hits{$ip}+1;
	    $robot_hits+=$ip_past_hits{$ip}+1;
	    $robot_bytes{$found}+=$ip_past_size{$ip}+$size;
	    $robot_bytes+=$ip_past_size{$ip}+$size;

	    if (!defined($seenfromlog{$ip_map{$ip},$ip})) {
		$seenfromlog{$found,$ip}=1;
		$robot_seenfrom{$found}.= " ".$ip;
	    }
        $robotsTxt = true;
        $robot_detectedBy{$ip} .= "robots.txt ";
	    next;
	}


	# Oh well, I guess this wasn't a robot request (after all that!)
	# Lets make a note of it incase they decide to get a robots.txt
	# file at a later date
	$ip_past_hits{$ip}+=1;
	$ip_past_size{$ip}+=$size;

    } continue {
	# I know that it's not good programming style to do further
	# robot tests in this part of the loop, but it is neccessary since
	# the "always without referrer" heuristic allows mis-qualification of
	# hosts as robots. This error has to be corrected indepedent of the
	# other heuristics.

	# Check for referrer information
	if(!exists($referrerFound{$ip}) && exists $$logLine{referrer}) {
	    if($referrer eq "-") {
            if(!exists($ip_map{$ip})) {
                $ip_map{$ip}=$found="UNKNWN".$unknown_count;
                $unknown_count++;
                
                $unknown_agent{$found}=$agent;
                
                $robot_hits{$found}+=$ip_past_hits{$ip}+1;
                $robot_hits+=$ip_past_hits{$ip}+1;
                $robot_bytes{$found}+=$ip_past_size{$ip}+$size;
                $robot_bytes+=$ip_past_size{$ip}+$size;
                
                if (!defined($seenfromlog{$ip_map{$ip},$ip})) {
                    $seenfromlog{$found,$ip}=1;
                    $robot_seenfrom{$found}.=" ".$ip;
                }
                $robot_detectedBy{$ip} .= "noReferrer ";
            }
        } else {
            $referrerFound{$ip} = 1;
        }
	}
    
	if($referrerFound{$ip} && exists($ip_map{$ip}) && !$robotsTxt && !$agent_fail{$agent}) {

	    # We wrongly qualified this host as robot - now we have
	    # to correct this mistake
	    delete $unknown_agent{$ip_map{$ip}};
	    $robot_hits{$ip_map{$ip}} -= $ip_past_hits{$ip} - 1;
	    $robot_hits -= $ip_past_hits{$ip} - 1;
	    $robot_bytes{$ip_map{$ip}} -= $ip_past_hits{$ip} - $size;
	    $robot_bytes -= $ip_past_hits{$ip} - $size;
	    delete $ip_past_hits{$ip};
	    delete $seenfromlog{$found,$ip};
	    delete $robot_seenfrom{$ip_map{$ip}};
	    delete $ip_map{$ip};
        delete $robot_detectedBy{$ip};

	}
    }

    # Now it comes - the final check!
    # Hotst with a too high request frequency probably aren't human.
    # We can find them by checking the maxViewTime.
    # Since we don't know anything but the sessionId (which _may_ be
    # the host ip or address), we cannot add the robot hits from this
    # heuristic to the statistics. We just add a dummy ip_map, so this
    # host will be

    foreach $sessionId (keys(%maxViewTime)) {
        if($maxViewTime{$sessionId} <= $config->rmRobotsMaxViewTime) {
            $ip_map{$sessionId_map{$sessionId}} = 1;
            $robot_detectedBy{$sessionId_map{$sessionId}} .= "maxViewTime ";
        }
    }
    
    printf(STDERR "\nTotal number of hits: %d\n",$total_hits);
    printf(STDERR "Number of robot hits: %d\n",$robot_hits);
    printf(STDERR "%% of total by robots: %.2f\n", $robot_hits*100/$total_hits);
    printf(STDERR "\nWriting output and performing DNS lookups (if neccessary)\n");
    
# If a robot has been found, either $agent_map{$agent} or $ip_map{$ip} will exist.
    
    seek INFILE, 0, 0;
    while($logLine = &nextLine) {

        if(defined($$logLine{host_ip})) {
            $ip = $$logLine{host_ip};
            $loggingIPs = 1;
        } else {
            $ip = $$logLine{host_dns};
            $loggingIPs = 0;
        }
        $method = $$logLine{method};
        $path = $$logLine{path};
        $code = $$logLine{status};
        $size = $$logLine{sc_bytes};
        $referrer = $$logLine{referrer};
        $agent = $$logLine{agent};
        
	if($sessionizeSeparator ne '' && $ip =~ /\Q$sessionizeSeparator\E/) {
#	    $ip =~ /\Q$sessionizeSeparator\E/;
            $ip = $';
	}
	
	next if $agent && exists($agent_map{$agent});
	next if exists($ip_map{$ip});
	&writeLine($logLine);
    }

    open ROBOTHOSTS, ">robot_hosts.txt";
    printf STDERR "\nStoring robot hosts\n";
    for(sort keys %ip_map) {
        printf ROBOTHOSTS "$_ ($robot_detectedBy{$_})\n";
    }
    close ROBOTHOSTS;
}

sub robot_ua {
    local($agent)=$_[0];

    foreach $id (@ignore) {
	return("ignore") if ($agent=~ /$id/);
    }

    foreach $id (keys(%robot_agent)) {
        return($id) if ($agent=~ /\Q$robot_agent{$id}\E/);
#        foreach $item (split('|',$robot_agent{$id})) {
#            return($id) if ($agent=~ /$item/);
#        }
    }
    undef;
}

sub robot_ip {
    local($ip)=$_[0];
    if ($loggingIPs) {
	foreach $id (keys(%robot_ip)) {
	    foreach $item (split(' ',$robot_ip{$id})) {
		return($id) if ($ip=~ /$item/);
	    }
	}
    } else {
        
	foreach $id (keys(%robot_host)) {
	    foreach $item (split(' [,]?',$robot_host{$id})) {
                $item =~ s/\./\\\./g;
                $item =~ s/\//\\\//g;
                $item =~ s/\*/\.\*\?/g;
#                printf STDERR "%s matched by %s\n", $ip, $item if ($ip =~ /$item/);
		return($id) if ($ip=~ /$item/);
	    }
	}
    }
    undef;
}

sub gethost {
    if($config->DNSlookups) {
        $addr = $_[0];
        local ($name, $aliases, $type, $len, $ad)
	    = gethostbyaddr(pack('C4', split('\.', $addr)),2);
        if ($name) {
	    $name;
        } else {
	    $addr;
        }
    } else {
        $addr;
    }
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
    } else {   # operation mode 'warehouse'
	die sprintf "$0: nextLine not suppported for operation mode %s\n",
	    $config->operationMode;
    }
}

sub writeLine(\$) {
    my $logLineRef = shift();
    if($config->operationMode eq 'file') {
        # file mode - that's simple - thanks to the parser ;-)
        print OUTFILE $parser->sampleLogLine($logLineRef) . "\n";
    } else {   
	die sprintf "$0: writeLine not suppported for operation mode %s\n",
	    $config->operationMode;
    }
}


__END__

=head1 NAME

removeRobots.pl - remove requests issued by robots from a log file

=head1 CONFIGURATION

This script is configured by settings in the file "wumprep.conf". See
L<WUMprep::Config> for details.

=head1 DESCRIPTION

This script tries several methods to identify hosts which are robots and
remove their request from the web server log:

=head2 BotWatch robot database

The first attempt at identifying robots is performed using the BotWatch
robot database. BotWatch is a perl script generating statistics about the
robot population in log files
(http://www.tardis.ed.ac.uk/~sxw/robots/botwatch.html).  The database
consists of detailed information about already known robots, including data
on IP addresses, hostname, referrer, and user agent identification. These
data are tested against the correpsonding fields in the logfile.

=head2 Heuristics

If the robot is not already known by the database, removeRobots.pl uses
several heuristics in order remove a maximum number of robot accesses from
the log:

=over 4

=item B<robots.txt>

It is good robot behaviour to request a file "/robots.txt". This file can
be used by a web site administrator to control if and how robots should
visit or index the site. Since usually no link to this file exists, one can
rely on the assumption that a request of this file has been issued by a
robot.

=item B<Missing referrer information>

If all requests originating at the same IP address show an empty referrer
field, this hosts is assumed to be a robot. This assumtion is reasonable,
because any of the common web browsers provides referrer information.

=item B<High request frequency>

A human user is assumed to need a minimum amount of time in order to
perceive the content of a webpage. If all page requests comprising a single
session occur with an extremely high frequence (less than 2 seconds between
successive requests, for example - this is user configurable), this
indicates automated requests, issued either by robots or tools for offline
browsing like wget.

The test for request frequency is only useful if the log has been
sessionized. See the L<sessionize.pl> manpage for details.

=back

Once a robot has been identified, all requests coming from the same IP
address are qualified as robot requests. We assume that by far the most
robots will run on dedicated machines that are not used for browsing by
humans, so the statistical error should be neglegible.
