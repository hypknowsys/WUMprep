#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# mapTaxonomies.pl - Map URLs from a log file onto a user-defined taxonomy
# $Revision: 1.4 $
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
#
# ATTENTION: This script is deprecated. Use mapReTaxonomies.pl instead,
#            which accepts (more powerful) regular expressions in template
#            files.
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

#my %fieldMap;    # take the field mapping, either for file or warehouse
my %taxonomies;  # takes an array of references to taxonomy hashes
my $inputFile;

my $config = new WUMprep::Config;
my $parser = new WUMprep::LogfileParser;
my $outputFile;

if(lc($ARGV[0]) eq '--filter' || lc($ARGV[0]) eq '-f') {
    # use stdin/stdout
    open(INFILE, "-");
    open(OUTFILE, ">-");
    $inputFile = 'from standard input';
    &main;
} else {
    # run in batch mode
    if($config->operationMode eq 'file') {
#        %fieldMap = %{$parser->fieldMap};
    } else {
        die "$0\nERROR: Unknown operation mode: ".$config->operationMode."\n";
    }

    for(@{$config->taxonomyDefs}) {
        &initTaxonomies($_);
    }
    
    foreach $inputFile ($config->inputLogs) {
        if($config->operationMode eq 'file') {
            $inputFile = longestFilename($inputFile);
            $outputFile = $inputFile.$config->taxonoMapOutputExtension;
            open(INFILE, "<$inputFile") 
                || die "Could not open input file $inputFile\n";
            open(OUTFILE, ">$outputFile") 
                || die "Could not open output file $outputFile\n";
            &main;
            close INFILE;
            close OUTFILE;
        }
    }
}


sub main {
    my $logLine;
    my $path;
    my $newPath;
    my $count;
    my $i;

    open ERRLOG, ">>unmappedUrls.html";
    printf ERRLOG "<html>\n<head><title>$0 - unmatched URLs</title></head>\n<body>\n";

    while($logLine = &nextLine) {
        $path = lc($$logLine{path});
        $i = 0;
        $newPath = undef;
        for(@{$taxonomies{$path}}) {
            $newPath .= '_' if $newPath ne '';
            $newPath .= $_;
        }
        if($newPath ne '') {
            $$logLine{path} = $newPath;
        } else {
            printf ERRLOG "<a href='%s' target='_blank'>%s</a><br>\n", $path, $path;
        }
        &writeLine($logLine);
	printf STDERR "$0: %d lines processed\n", $count if(!(++$count % 1000));
    }
    printf STDERR "$0: %d lines processed - finished\n", $count;

    close ERRLOG;
    printf ERRLOG "</html>\n</body>\n";
}


sub initTaxonomies(\$) {
    my @concepts;
    my $path;
    
    open TAX_DEFS, "<$_[0]" 
        || die "$0: Could not open taxonomy definition file $_[0]\n";

    # Actually, we don't perform any itegrity checks on the taxonomy
    # definition files. This is left open for the next development
    # effort - so take care when defining your taxonomy defs ;-)
    # See the comments on top of this document for a description of 
    # a taxonomy definition file's format.
    
    while(<TAX_DEFS>) {
        s/\#.*$//;        # remove comments
        next if(/^\s*$/); #skip comment-only and blank lines
        (@concepts) = split /\s+/;
        $path = lc(pop @concepts);
        my $conceptCount = scalar @taxonomies{$path};
        my $i = 0;
        for(@concepts) {
            $taxonomies{$path}[$conceptCount + $i++] = $_;
        }
    }

    close TAX_DEFS;
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
    } else {
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










