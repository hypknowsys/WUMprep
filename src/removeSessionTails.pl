#!/usr/bin/perl

# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------

# removeSessionTails.pl - This little utility reads a sessionized log
#                         from the standard input and leaves only the
#                         first request of each session in the output.
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


use FindBin;
use lib "$FindBin::Bin";
use WUMprep::Config;
use WUMprep::LogfileParser;

$config = new WUMprep::Config;
$parser = new WUMprep::LogfileParser;

while(<STDIN>) {
    chomp;
    $logLine = $parser->parseLogLine($_);
    next if($sessionSeen{session_id});
    $sessionSeen{session_id} = 1;
    print $_, "\n";
}
