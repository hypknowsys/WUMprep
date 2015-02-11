# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# WUMprep/LogfileParser.pm - Parse Web server log files
# $Revision: 1.6 $
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

package WUMprep::LogfileParser;

use strict;
use Cwd;
use FindBin;
use lib "$FindBin::Bin";
use WUMprep::Config;

use constant CONFIG_FILENAME => "wumprep.conf";

my $config = new WUMprep::Config;

my @validFields = qw(vhost
                     host_ip
                     host_dns
                     ident
                     auth_user
                     ts_day ts_month ts_year ts_hour ts_minutes ts_seconds tz
                     method
                     path
                     protocol
                     status
                     sc_bytes
                     cs_bytes
                     referrer
                     agent
                     time_taken
                     cookie
                     args
                     ignore
                     ignore1
                     ignore2
                     ignore3
                     ignore4
                     ignore5
                     ignore6
                     ignore7
                     ignore8
                     ignore9
                     ignore10
                     session_id
);


my %monthMap = 
    (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
     Jul => 6,Aug => 7, Sep => 8, Oct =>  9, Nov => 10, Dec => 11 );

my %monthMapInverse;

for (keys %monthMap) {
    $monthMapInverse{$monthMap{$_}} = $_;
}


# ========================================================================
# SUB: new
# ------------------------------------------------------------------------
# Constructor method
# ------------------------------------------------------------------------
# Parameter:
# The constructor takes an optional argument specifying the template file
# which defines the logfile format. If the argument is omitted, the 
# logline template file is taken from the wumprep.conf file.
# ========================================================================
sub new ($) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = {};
    bless ($self, $class);
	$self->{TEMPLATE_FILENAME} = shift;
	$self->{TEMPLATE_FILENAME} = $config->inputLogTemplate
		if(!$self->{TEMPLATE_FILENAME});
    $self->readLogFormatDef($self->{TEMPLATE_FILENAME});
		
    return $self;
}   


# ========================================================================
# SUB: setMonthAlpha, getMonthAlpha
# ------------------------------------------------------------------------
# These function provide the user manual control about the MONTH_ALPHA
# variable, which is neccessary if multiple parsers are used in parallel,
# as is the case for the transformLog.pl script.
# ========================================================================
sub getMonthAlpha() {
    my $self = shift;

    return $self->{MONTH_ALPHA};
}

sub setMonthAlpha(\$) {
    my $self = shift;

    $self->{MONTH_ALPHA} = 1 if shift;
}


# ========================================================================
# SUB: readLogFormatDef
# ------------------------------------------------------------------------
# Read the logfile definition and build a nice regexp from it.
# ------------------------------------------------------------------------
# Parameter:
# path/name of the logfile format definition file
# ========================================================================
sub readLogFormatDef (\$) {
    my $self = shift;
    my $regexp = '';
    my $count = 0;
    my $pre;
    my $field;
    my $end;
    my $templateFile = shift();


    open(LOG_DEF_FILE, "<".$templateFile) || 
	die "$0\nERROR: Could not open format definition file $templateFile.\n";
    
    print STDERR "Reading log format definition...\n";
    # this loop reads the config file line by line and initializes
    # the Config fields.
    while(<LOG_DEF_FILE>) {
        $_ = $` if /\s*#/;   # drop comments
        chomp;
        
        if(/^\s*$/) {  # skip blank lines
            next;
        } else {
	    $self->{LOG_LINE_TEMPLATE} = $_;
	    $self->{LOG_LINE_TEMPLATE_EXPORT} = $_;
	    # later, we might add an option to use a different
	    # output format - et voila, a converter was born :-)

            # We trust the user and perform no further file integrity
            # tests.  Any line containing non-blanks and not being a
            # comment is treated as log format definition
            
            while(m/(.*?)@(\w*)@/gc) {
                $pre = quotemeta($1);
                $field = $2;
                $end = quotemeta($');
                
                die "$0\nERROR: Unrecognized field in log template: $field\n\n"
                    if(! scalar(grep(/^$field$/, @validFields)));
                
                $regexp .= "$pre(.*?)";
                $self->{FIELD_MAP}{$field} = $count;
                printf STDERR "Field %2d: %s\n", $self->{FIELD_MAP}{$field}, $field;
                $count++;
            }
            # \015 catches DOS line endings on Linux
#            $regexp = "^" . $regexp . $end . "(\015)?\$";
            $regexp = "^" . $regexp . $end . "\$";
        }
    }
    close LOG_DEF_FILE;

    $self->{PARSER_REGEXP} = $regexp;
    return $regexp;
}


sub fieldMap {
    my $self = shift();
#    return \%{$self->{FIELD_MAP}};
    return $self->{FIELD_MAP};
}


# ========================================================================
# SUB: parseLogLine
# ------------------------------------------------------------------------
# Parses a log line into an array comporised of the single fields
# ------------------------------------------------------------------------
# Argument:
# - the log line to parse
# ------------------------------------------------------------------------
# Returns: A hash containing the log line fields.
# ========================================================================
sub parseLogLine(\$) {
    my $self = shift();
    my $logLine = shift();
    chomp $logLine;
    my (@parsedLogLine) = $logLine =~ /$self->{PARSER_REGEXP}/;

    # set all empty fields (marked by '-') to undef
    for(@parsedLogLine) {
        s/^-$//;
    }
    
    # join path and query (args) field
    if((defined $self->{FIELD_MAP}{args} &&
        $parsedLogLine[$self->{FIELD_MAP}{args}] !~ /(-|^$)/)) {
        $parsedLogLine[$self->{FIELD_MAP}{path}]
            .= '?' . $parsedLogLine[$self->{FIELD_MAP}{args}];
    }
       
    # To make our users' lifes easier, we take care about the month
    # format. If the log line to sample contains a textual month
    # representation, we convert it to the corresponding integer
    # value (which is out of 1..12).
    # We store the original month format to be able to write a
    # correct output log using the sampleLogLine method.
    if(defined $self->{FIELD_MAP}{ts_month}) {
        # non-numeric month format?
        if($parsedLogLine[$self->{FIELD_MAP}{ts_month}] !~ /^\d+$/) {
            $parsedLogLine[$self->{FIELD_MAP}{ts_month}] 
                = $monthMap{$parsedLogLine[$self->{FIELD_MAP}{ts_month}]};
            $self->{MONTH_ALPHA} = 1;
        }
    }

    # convert cookie part of the logline into a hash reference:
    ##### ATTENTION #####
    # The following split condition might not work on other log files
    # than those of the MS IIS!
    # It is necessary to search for documentation about different formats of 
    # loggin cookies.
    my %cookies;
    if(defined($self->{FIELD_MAP}{cookie})) {
        my @cookies = split /;(\+|\ )/, @parsedLogLine[$self->{FIELD_MAP}{cookie}];
        for(@cookies) {
            (my $key, my $value) = split /=/;
			next if($key eq '+');
            $cookies{$key} = $value;
        }
        @parsedLogLine[$self->{FIELD_MAP}{cookie}] = \%cookies;
    }

    # Convert the array to a hash (that's easier to handle with for this
    # method's users).

    my %parsedLogLine;
    my %fieldMapInverted = reverse %{$self->{FIELD_MAP}};

    for(my $i = 0; $i < scalar(@parsedLogLine); $i++) {
            $parsedLogLine{$fieldMapInverted{$i}} = $parsedLogLine[$i];
    }

    return \%parsedLogLine;
}


# ========================================================================
# SUB: sampleLogLine
# ------------------------------------------------------------------------
# The opposite of parseLogLine: Creates a log line from a hash 
# ------------------------------------------------------------------------
# Argument:
# - the log line to parse as hash
# ------------------------------------------------------------------------
# Returns: An array containing the log line fields according to the
#          field map.
# ========================================================================
sub sampleLogLine(\$) {
    my $self = shift();
    my $logLine = shift();
    my $logLineReturn =  $self->{LOG_LINE_TEMPLATE_EXPORT};
    my $cookie;

    if($self->{FIELD_MAP}{cookie}) {
       if(defined($$logLine{cookie})
		  && keys(%{$$logLine{cookie}})) {
		   # convert the cookie hash back to a string
		   for(keys(%{$$logLine{cookie}})) {
			   $cookie .= ';+' if($cookie);
			   $cookie .= $_;
			   $cookie .= '=' . ${$$logLine{cookie}}{$_}
        		   if(${$$logLine{cookie}}{$_});
	       }
	   
	       $cookie =~ s/;\+$//;  # remove trailing separator
	       $$logLine{cookie} = $cookie;
       } else {
		   $$logLine{cookie} = undef;
	   }
    }

    # replace undef values by '-'
    for(keys %$logLine) {
        $$logLine{$_} = '-' if $$logLine{$_} eq '';
    }

    # Make sure that the month value is in the same format as it was when
    # we read it.
    # ATTENTION: This mechanism assumes that the parseLogLine method is called
    #            _before_ the sampleLogLine method. (As for now, this assumption
    #            seems reasonable.) Here, we rely on the format value defined
    #            by $self->{MONT_ALPHA}.
    if(defined $self->{FIELD_MAP}{ts_month}) {
        if($$logLine{ts_month} =~ /^\d+$/ 
           && $self->{MONTH_ALPHA}) {
            $$logLine{ts_month}
                = $monthMapInverse{sprintf("%d", 
                                      $$logLine{ts_month})};
        } elsif($$logLine{ts_month} !~ /^\d+$/ 
                && !$self->{MONTH_ALPHA}) {
            $$logLine{ts_month} 
                = $monthMap{$$logLine{ts_month}};
        }
        # Make sure month has two digits if !MONTH_ALPHA
        if(!$self->{MONTH_ALPHA}) {
            $$logLine{ts_month} = sprintf("%02d", $$logLine{ts_month});
        }
    }


    # replace the placeholders in the template line by
    # the values of the hash passed as argument
    $logLineReturn =~ s/@(.*?)@/$$logLine{$1}/ge;


    # THIS IS TO FIX A BUG SOMEWHERE ABOVE:
    # If there is no cookie for this line, there is an = appended to 
    # the end fo the line. This is now removed.
    $logLineReturn =~ s/=$//;
    return $logLineReturn;
}


1;











