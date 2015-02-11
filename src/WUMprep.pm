# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# WUMprep.pm - Helper functions used by the WUMprep script suite
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
use strict;
require Exporter;

use vars qw($VERSION @ISA @EXPORT);
#    $VERSION = do { my @r = (q$Revision: 1.4 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };
#
@ISA = qw(Exporter);
@EXPORT = qw(%month_map);

use vars @EXPORT;

use vars qw($maxLenFilename $tmp);

%WUMprep::month_map = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
	      Jul => 6,Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11 );

# In the configuration file wumprep.conf, the user can specify the files to
# process in batch mode. Each script of the WUMprep suite can write its
# output to a new file. The filename is then composed of the input filename
# plus a new filename extension, specified in the configuration file.

# Since the scripts may be executed in a different order or single scripts
# may be omitted during logfile preparation, we cannot tell the actual
# filename extension of the input files. So we simply use the longest
# filename that starts with the input filename given in the config
# file. Since the filename gets longer with the exectuion of each script,
# the longest filename is probably the most recent one and should be used
# for the next data preparation step.

sub longestFilename ($) { 
    my $maxLenFilename = ""; @_ = glob shift() . "*";

    foreach $tmp (@_){
	$maxLenFilename = $tmp if(length($maxLenFilename) < length($tmp));
    }
    return $maxLenFilename;
}

1;









