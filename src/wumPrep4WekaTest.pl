#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# wumPrep4WekaTest.pl - Script for testing WUMprep4Weka connectivity
# $Revision: 1.1 $
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

use Text::CSV_XS;
#use WUMprep::ArffParser;


# This script does noting but piping STDIN input to STDOUT output and
# sending some test messages to STDERR

my $csv = new Text::CSV_XS->new({ 'quote_char' =>"'" });


while($i < @ARGV) {
	print STDERR "Argument: " . $ARGV[$i] . "\n";
		
	$i++;
}

$i = 0;
while (<STDIN>) {
  my $out;
  
  if (! /^[@\s]/ ) {
    $csv->parse($_);
    $csv->combine($csv->fields());
    $out = $csv->string() . "\n";
  } else {
    $out = $_;
  }
  
  printf STDOUT "%s", $out;
  printf STDERR "Line %3d: %s", $i + 1, $out;

	$i++;
}

close STDOUT;
print STDERR "Received $i lines of input - bye.\n";

