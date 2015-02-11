# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# WUMprep/Config.pm - Interface to the wumprep.conf configuration file
# $Revision: 1.5 $
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

package WUMprep::Config;

use strict;
use FindBin;
FindBin->again;
use lib "$FindBin::Bin/../lib";
use Cwd;

#use WUMprep;

use constant CONFIG_FILENAME => "wumprep.conf";

# Used to check log file templates for validity
sub validFields {
  return qw(vhost
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
}

sub new {
  my $proto          = shift;
  my $class          = ref($proto) || $proto;
  my $arg1           = shift;
  my $self           = {};
  my $currentSection = undef;
  my $tmp;
  my %tmp;
  my $val;
  my $configFile;

  if ( !$arg1 ) {

    # No parameter given -> search the working directory for wumprep.conf
    $configFile = $FindBin::Bin . "/" . CONFIG_FILENAME;
  }
  else {

    # Invoked with an argument -> take it as the absolute path to a
    # user-specified wumprep.conf
    $configFile = $arg1;
  }

  open( CONFIGFILE, "<" . $configFile )
    || die "Could not open configuration file " . $configFile . "\n";

  print STDERR "Reading configuration file " . $configFile . "...\n";

  # this loop reads the config file line by line and initializes
  # the Config fields.
  while (<CONFIGFILE>) {
    $_ = $` if /\s*#/;    # drop comments
    chomp;

    if (/^\[/) {          # we've found a section label - let's note it
      /^\[(.*)\]/;
      $currentSection = $1;
    }
    elsif (/=\.\.\.\s*$/) {

      # we've found a value list label - treat it like a section
      # (ugly, but better than rewriting everything below)
      /^(\S*)\s*=\.\.\.\s*$/;
      $currentSection = $1;
    }
    elsif ( $currentSection eq "" || /^\s*$/ ) {

      # skip lines containing no information
      next;
    }
    elsif ( $currentSection eq 'global' ) {

      # read options according to section...
      /(\S*)\s*=\s*(.*)$/;
      $val = $2;
      if ( uc($val) eq "YES" ) { $val = 1 }
      if ( uc($val) eq "NO" )  { $val = 0 }
      if ( $1 eq 'DNSlookups' ) {
        $self->{DNSLOOKUPS} = $val;
      }
      elsif ( $1 eq 'outputDirectory' ) {
        $self->{OUTPUTDIR} = $val;
      }
      elsif ( $1 eq 'htmlTemplateDir' ) {
        $self->{HTML_TEMPLATE_DIR} = $val;
      }
      elsif ( $1 eq 'operationMode' ) {
        if ( lc($val) eq 'file' ) {
          $self->{OPERATION_MODE} = lc($val);
        }
        else {
          die "Unknown operation mode: \"$2\" in section "
            . "[$currentSection] of "
            . CONFIG_FILENAME . "\n";
        }
      }
      elsif ( $1 eq 'inputLogTemplate' ) {
        $self->{INPUT_LOG_TEMPLATE} = $val;
      }
      elsif ( $1 eq 'domain' ) {
        $self->{DOMAIN} = $val;
        ${ $self->{SERVER_FAMILY} }{$val} = 1;

      }
      else {
        die "Unrecognized option \"$1\" in section "
          . "[$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'serverFamily' ) {
      $self->{SERVER_FAMILY}->{$_} = 1;
    }
    elsif ( $currentSection eq 'inputLogs' ) {
      while ( $tmp = glob ) {
        for ( @{ $self->{INPUTLOGS} } ) { $tmp{$_} = 1 }
        push @{ $self->{INPUTLOGS} }, WUMprep::longestFilename($tmp)
          if !$tmp{ WUMprep::longestFilename($tmp) };
      }
    }
    elsif ( $currentSection eq 'conversionSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'conversionOutputExtension' ) {
        $self->{CONVERSION_OUTPUT_EXT} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'filterSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'filterDuplicateTimeout' ) {
        $self->{DUPLICATE_TIMEOUT} = $val;
      }
      elsif ( $1 eq 'filterOutputExtension' ) {
        $self->{FILTER_OUTPUT_EXT} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'filterPath' ) {

      #       s/\./\\\./g;
      if (/^@(.*)$/) {

        # read path filters from file
        open FILTER_PATH_FILE, "<$1"
          || die "Cannot open filterPath file $1\n";
        while (<FILTER_PATH_FILE>) {
          $self->{FILTER_PATH} .= "|" if $self->{FILTER_PATH} ne '';
          chomp;
          $self->{FILTER_PATH} .= $_ if ( !/^\s*$/ );
        }
        close FILTER_PATH_FILE;
      }
      else {
        $self->{FILTER_PATH} .= "|" if $self->{FILTER_PATH} ne '';
        $self->{FILTER_PATH} .= $_;
      }
    }
    elsif ( $currentSection eq 'filterHosts' ) {
      $self->{FILTER_HOSTS} .= "|" if $self->{FILTER_HOSTS} ne '';
      if (/^RE:(\S*)/) {
        $self->{FILTER_HOSTS} .= $1;
      }
      else {
        $self->{FILTER_HOSTS} .= quotemeta;
      }
    }
    elsif ( $currentSection eq 'filterStatusCodes' ) {
      $self->{FILTER_STATUS_CODES} .= "|"
        if $self->{FILTER_STATUS_CODES} ne '';
      $self->{FILTER_STATUS_CODES} .= $_;
    }
    elsif ( $currentSection eq 'sessionFilterSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'sessionFilterOutputExtension' ) {
        $self->{SESSION_FILTER_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'sessionFilterRepeatedRequests' ) {
        $self->{SESSION_FILTER_REPEATED_REQUESTS} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'sessionFilterHostIp' ) {
      $self->{SESSION_FILTER_HOST_IP} .= "|"
        if $self->{SESSION_FILTER_HOST_IP} ne '';
      if (/^RE:(\S*)/) {
        $self->{SESSION_FILTER_HOST_IP} .= $1;
      }
      else {
        $self->{SESSION_FILTER_HOST_IP} .= quotemeta;
      }
    }
    elsif ( $currentSection eq 'sessionFilterHostName' ) {
      $self->{SESSION_FILTER_HOST_NAME} .= "|"
        if $self->{SESSION_FILTER_HOST_NAME} ne '';
      if (/^RE:(\S*)/) {
        $self->{SESSION_FILTER_HOST_NAME} .= $1;
      }
      else {
        $self->{SESSION_FILTER_HOST_NAME} .= quotemeta;
      }
    }
    elsif ( $currentSection eq 'sessionFilterPath' ) {
      $self->{SESSION_FILTER_PATH} .= "|"
        if $self->{SESSION_FILTER_PATH} ne '';
      if (/^RE:(\S*)/) {
        $self->{SESSION_FILTER_PATH} .= $1;
      }
      else {
        $self->{SESSION_FILTER_PATH} .= quotemeta;
      }
    }
    elsif ( $currentSection eq 'sessionFilterAgent' ) {
      $self->{SESSION_FILTER_AGENT} .= "|"
        if $self->{SESSION_FILTER_AGENT} ne '';
      if (/^RE:(\S*)/) {
        $self->{SESSION_FILTER_AGENT} .= $1;
      }
      else {
        $self->{SESSION_FILTER_AGENT} .= quotemeta;
      }
    }
    elsif ( $currentSection eq 'reverseLookupSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'rLookupOutputExtension' ) {
        $self->{RLOOKUP_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'rLookupCacheFile' ) {
        $self->{RLOOKUP_CACHE_FILE} = $val;
      }
      elsif ( $1 eq 'rLookupNumThreads' ) {
        $self->{RLOOKUP_NUM_THREADS} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'filterDuplicatesExtensions' ) {
      s/\./\\\./g;
      $self->{FILTER_DUPLICATES_EXT} .= "|"
        if $self->{FILTER_DUPLICATES_EXT} ne '';
      $self->{FILTER_DUPLICATES_EXT} .= $_;
    }
    elsif ( $currentSection eq 'sessionizeSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'sessionizeMaxPageViewTime' ) {
        $self->{SESS_MAX_PAGE_VIEW_TIME} = $val;
      }
      elsif ( $1 eq 'sessionizeOutputExtension' ) {
        $self->{SESS_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'sessionizeSeparator' ) {
        $val =~ s/\"//g;
        $self->{SESS_SEPARATOR} = $val;
      }
      elsif ( $1 eq 'sessionizeIdCookie' ) {
        $self->{SESS_ID_COOKIE} = $val;
      }
      elsif ( $1 eq 'sessionizeInsertReferrerHits' ) {
        $self->{SESS_REF_HITS} = $val;
      }
      elsif ( $1 eq 'sessionizeQueryReferrerName' ) {
        $self->{SESS_QUERY_REF_NAME} = $val;
      }
      elsif ( $1 eq 'sessionizeForeignReferrerStartsSession' ) {
        $self->{SESS_FOREIGN_REF_STARTS_SESSION} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'statisticsSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'statisticsOutputExtension' ) {
        $self->{STAT_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'statisticsExport' ) {
        $self->{STAT_EXPORT} = $val;
      }
      elsif ( $1 eq 'statisticsTemplateFile' ) {
        $self->{STAT_TEMPLATE_FILE} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'rmRobotsSettings' ) {
#      /(\S*)\s*=\s*"?([^"]*)"?$/;
      /(\S*)\s*=\s*(.*)$/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'rmRobotsDB' ) {
        $self->{ROBOTS_DB} = $val;
      }
      elsif ( $1 eq 'rmRobotsOutputExtension' ) {
        $self->{ROBOTS_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'rmRobotsMaxViewTime' ) {
        $self->{ROBOTS_MAX_VIEW_TIME} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'mapTaxonomiesSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'taxonoMapOutputExtension' ) {
        $self->{TAXOMOMY_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'taxonoMapLog' ) {
        $self->{TAXONOMY_MAP_LOG} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'taxonomyDefs' ) {
      while ( $tmp = glob ) {
        push @{ $self->{TAXONOMY_DEFS} }, $tmp;
      }
    }
    elsif ( $currentSection eq 'anonymizerSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'anonKeyFile' ) {
        $self->{ANON_KEY_FILE} = $val;
      }
      elsif ( $1 eq 'anonOutputExtension' ) {
        $self->{ANON_OUTPUT_EXT} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    elsif ( $currentSection eq 'transformSettings' ) {
      /(\S*)\s*=\s*(\S*)/;
      $val = $2;
      if ( uc($2) eq "YES" ) { $val = 1 }
      if ( uc($2) eq "NO" )  { $val = 0 }
      if ( $1 eq 'transformOutputExtension' ) {
        $self->{TRANSFORM_OUTPUT_EXT} = $val;
      }
      elsif ( $1 eq 'transformTemplate' ) {
        $self->{TRANSFORM_TEMPLATE} = $val;
      }
      elsif ( $1 eq 'transformMode' ) {
        $self->{TRANSFORM_MODE} = $val;
      }
      elsif ( $1 eq 'transformSessionVectorFile' ) {
        $self->{TRANSFORM_SESSION_VECTOR_FILE} = $val;
      }
      elsif ( $1 eq 'transformSessionVectorWithEntryPage' ) {
        $self->{TRANSFORM_SESSION_VECTOR_WITH_ENTRY_PAGE} = $val;
      }
      else {
        die "Unrecognized option \"$1\" in section [$currentSection] of "
          . CONFIG_FILENAME . "\n";
      }
    }
    else {    # oops - before we guess, we better die
      die "Unrecognized section label in "
        . CONFIG_FILENAME
        . ": $currentSection\n";
    }
  }

  close CONFIGFILE;

  die "You selected the 'warehouse' operation mode, but did"
    . " not specify a domain name in "
    . CONFIG_FILENAME . "\n"
    if ( $self->{OPERATION_MODE} eq 'warehouse'
    && !defined( $self->{DOMAIN} ) );

  if ( !@{ $self->{INPUTLOGS} } ) {
    die "Cannot find an input log file \"$_\"\n";
  }

  bless $self;
  return $self;
}

sub domain {
  my $self = shift;
  return $self->{DOMAIN};
}

sub operationMode {
  my $self = shift;
  return $self->{OPERATION_MODE};
}

sub warehouseName {
  my $self = shift;
  return $self->{WAREHOUSE_NAME};
}

sub warehouseUser {
  my $self = shift;
  return $self->{WAREHOUSE_USER};
}

sub warehousePassword {
  my $self = shift;
  return $self->{WAREHOUSE_PASSWORD};
}

sub inputLogTemplate {
  my $self = shift;
  return $self->{INPUT_LOG_TEMPLATE};
}

sub path {
  my $self = shift;
  return $self->{PATH};
}

sub dnsLookups {
  my $self = shift;
  return $self->{DNSLOOKUPS};
}

sub outputDir {
  my $self = shift;
  return $self->{OUTPUTDIR};
}

sub htmlTemplateDir {
  my $self = shift;
  return $self->{HTML_TEMPLATE_DIR};
}

sub inputLogs {
  my $self = shift;
  return @{ $self->{INPUTLOGS} };
}

sub filterDuplicateTimeout {
  my $self = shift;
  return $self->{DUPLICATE_TIMEOUT};
}

sub conversionOutputExtension {
  my $self = shift;
  return $self->{CONVERSION_OUTPUT_EXT};
}

sub filterOutputExtension {
  my $self = shift;
  return $self->{FILTER_OUTPUT_EXT};
}

sub filterPath {
  my $self = shift;
  return $self->{FILTER_PATH};
}

sub filterHosts {
  my $self = shift;
  return $self->{FILTER_HOSTS};
}

sub filterStatusCodes {
  my $self = shift;
  return $self->{FILTER_STATUS_CODES};
}

sub filterDuplicatesExtensions {
  my $self = shift;
  return $self->{FILTER_DUPLICATES_EXT};
}

sub sessionFilterOutputExtension {
  my $self = shift;
  return $self->{SESSION_FILTER_OUTPUT_EXT};
}

sub sessionFilterRepeatedRequests {
  my $self = shift;
  return $self->{SESSION_FILTER_REPEATED_REQUESTS};
}

sub sessionFilterHostIp {
  my $self = shift;
  return $self->{SESSION_FILTER_HOST_IP};
}

sub sessionFilterHostName {
  my $self = shift;
  return $self->{SESSION_FILTER_HOST_NAME};
}

sub sessionFilterPath {
  my $self = shift;
  return $self->{SESSION_FILTER_PATH};
}

sub sessionFilterAgent {
  my $self = shift;
  return $self->{SESSION_FILTER_AGENT};
}

sub rLookupOutputExtension {
  my $self = shift;
  return $self->{RLOOKUP_OUTPUT_EXT};
}

sub rLookupCacheFile {
  my $self = shift;
  return $self->{RLOOKUP_CACHE_FILE};
}

sub rLookupNumThreads {
  my $self = shift;
  return $self->{RLOOKUP_NUM_THREADS};
}

sub serverFamily {
  my $self = shift;
  return %{ $self->{SERVER_FAMILY} };
}

sub sessionizeForeignReferrerStartsSession {
  my $self = shift;
  return $self->{SESS_FOREIGN_REF_STARTS_SESSION};
}

sub sessionizeIdCookie {
  my $self = shift;
  return $self->{SESS_ID_COOKIE};
}

sub sessionizeInsertReferrerHits {
  my $self = shift;
  return $self->{SESS_REF_HITS};
}

sub sessionizeMaxPageViewTime {
  my $self = shift;
  return $self->{SESS_MAX_PAGE_VIEW_TIME};
}

sub sessionizeOutputExtension {
  my $self = shift;
  return $self->{SESS_OUTPUT_EXT};
}

sub sessionizeQueryReferrerName {
  my $self = shift;
  return $self->{SESS_QUERY_REF_NAME};
}

sub sessionizeSeparator {
  my $self = shift;
  return $self->{SESS_SEPARATOR};
}

sub statisticsOutputExtension {
  my $self = shift;
  return $self->{STAT_OUTPUT_EXT};
}

sub statisticsExport {
  my $self = shift;
  return $self->{STAT_EXPORT};
}

sub statisticsTemplateFile {
  my $self = shift;
  return $self->{STAT_TEMPLATE_FILE};
}

sub robotsDB {
  my $self = shift;
  return $self->{ROBOTS_DB};
}

sub rmRobotsOutputExtension {
  my $self = shift;
  return $self->{ROBOTS_OUTPUT_EXT};
}

sub rmRobotsMaxViewTime {
  my $self = shift;
  return $self->{ROBOTS_MAX_VIEW_TIME};
}

sub anonKeyFile {
  my $self = shift;
  return $self->{ANON_KEY_FILE};
}

sub anonOutputExtension {
  my $self = shift;
  return $self->{ANON_OUTPUT_EXT};
}

sub taxonoMapOutputExtension {
  my $self = shift;
  return $self->{TAXOMOMY_OUTPUT_EXT};
}

sub taxonomyMapLog {
  my $self = shift;
  return $self->{TAXONOMY_MAP_LOG};
}

sub taxonomyDefs {
  my $self = shift;
  return $self->{TAXONOMY_DEFS};
}

sub transformOutputExtension {
  my $self = shift;
  return $self->{TRANSFORM_OUTPUT_EXT};
}

sub transformTemplate {
  my $self = shift;
  return $self->{TRANSFORM_TEMPLATE};
}

sub transformMode {
  my $self = shift;
  return $self->{TRANSFORM_MODE};
}

sub transformSessionVectorFile {
  my $self = shift;
  return $self->{TRANSFORM_SESSION_VECTOR_FILE};
}

sub transformSessionVectorWithEntryPage {
  my $self = shift;
  return $self->{TRANSFORM_SESSION_VECTOR_WITH_ENTRY_PAGE};
}

1;    # modules always have to return 1

__END__

=head1 NAME

WUMprep::Config - Interface to the wumprep.conf configuration file

=head1 SYNOPSIS

    # The following code snipped shows how to use the Config class
    # in your own perl scripts

    use WUMprep::Config;

    $config = new WUMprep::Config;
    print join ':', $config->inputLogs;
    #...


=head1 DESCRIPTION

This class is part of the WUMprep library of Perl scripts for logfile
preparation.  It provides access to the options stored in the
F<wumprep.conf> configuration file. Please see the template config file in
the directory containing the WUMprep scripts for further details about the
possible options.

=head1 INTERFACE

=head2 CONSTRUCTOR

=over 4

=item B<new>

The constructor searches in the current working directory for the
configuration file F<wumprep.conf>. A template of this file is contained in
the script directory and should be copied from there to the working
directory which is used for logfile preprocessing. If the configuration
file is not found, the constructor will die with an error message.

=back

=head2 METHODS

=over 4

=item B<domain>

Returns the domain name of the server wich's logfiles shall be processed.

=item B<operationMode>

Returns the desired operation mode ('file' or 'warehouse').

=item B<warehouseName>

The name of the warehouse database to use

=item B<warehouseUser>

The user name for accessing the warehouse database

=item B<warehousePassword>

The password to access the warehouse database

=item B<inputLogTemplate>

Returns the name/path of the file specifying the format of a line from
the input log file.

=item B<path>

Returns the current working dir where the config file resides.

=item B<dnsLookups>

Returns the value set for the DNS lookup option. If the user wanted the
WUMprep scripts to perform DNS lookups where applicable, this value should
be 1, otherwise 0.

=item B<outputDir>

Returns the directory where the processed logs should be written into. If
no directory is given, this method returns an empty string.

=item B<htmlTemplateDir>

Returns the directory where HTML template files are stored. Those
templates are used for generating reports, for example by
logStatistics.pl.

=item B<inputLogs>

Returns an array of input log file names. Please keep in mind that these
are the names of the original log files. If you want to access a processed
logfile, you should use the B<...OutputExtension> information to construct
the filename you want.

=item B<conversionOutputExtension>

Returns the extension the user wants to be added to the original log
files's name after converting the log to the WUMprep standard format.

=item B<filterOutputExtension>

Returns  the extension  the user wants to  be added  to the  original log
file's name after filtering.

=item B<filterFilenameExtensions>

Returns a reqular expression consisting of the filename extensions of
requested documents the user wants to be dropped from the log. This string
might be used as follows:

    use WUMprep::Config;

    $config = new WUMprep::Config;
    $tmp = $config->filterFilenameExtensions;
    if($request ~= m/$tmp/i) {
       # drop this log line...
    }

=item B<filterHosts>

Returns a regular expression pattern consisting of the hosts which requests
the users wants to be dropped from the log. Usage is similar to the example
for B<filterFilenameExtension>.

=item B<filterStatusCodes>

Returns a regular expresson pattern consisting of the HTTP status codes of
the requests the user wants to be included in the filtered logfile. The
status code filter is an "include filter", this means that only log lines
with a status code listed in this section will be included in the output
logfile.  If no filter on the status code field is wanted, this method
returns an empty string.

=item B<filterDuplicateTimeout>

Returns the timeout in seconds. If the users requests the same page two or
more times consecutively, the duplicate requests should be removed since
they only indicate that the users was impatient, but disturb the process of
pattern finding.

=item B<filterDuplicatesExtensions>

Returns a regular expression pattern consisting of the filename extensions
defining the reuqests that should be considered when checking for duplicate
requests.

=item B<sessionFilterOutputExtension>

Returns the user specified filename extension that should be used for the
sessionFilter.pl output file.

=item B<sessionFilterRepeatedRequests>

Returns true if sessionFilter.pl shall leave only the first from a
series of successive requests to the same URL in the log.

=item B<sessionFilterPath>

Returns a list of regular expressions, concatenated by '|'s. A request's path
matching one of these expressions should cause the session this request
belongs to to be removed from the filter output.

=item B<rLookupOutputExtension>

Returns the user specified filename extension that should be used for the
reverseLookup.pl output files.

=item B<rLookupCacheFile>

Returns the name of the file which should be used to stored the DNS
lookup cache.

=item B<rLookupNumThreads>

Returns the maximum number of threads for reverse DNS lookups.

=item B<serverFamily>

Returns a hash which keys are server names that are to be treated as
aliases for the main server name given as 'domain' in the [global]
section. This is needed e.g. by the sessionizer in order to detect the
beginning of a new session based on a foreign referrer.

=item B<sessionizeForeignReferrerStartsSession>

Returns true if the sessionizer should start a new session when a
foreign referrer occurs.

=item B<sessionizeIdCookie>

Returns the name of the cookie identifying a user session, or an empty
string, if cookies shall not be used. May be a regular expression.

=item B<sessionizeInsertReferrerHits>

Returns true if the sessionizer should insert dummy hits to the
referring document at the beginning of each session.

=item B<sessionizeMaxPageViewTime>

Returns the maximum page view time for sessionizing in seconds.

=item B<sessionizeQueryReferrerName>

Returns the name of the GET query parameter denoting the referrer
(blank if not applicable)

=item B<sessionizeSeparator>

Returns the character (or string) that shall be used for separationg the
session ID prefix from the hostname.

=item B<statisticsOutputExtension>

Returns the filename that should be used for the output of F<logStatistics.pl>.

=item B<statisticsExport>

Returns a boolean value, indicating if the statistics (histogram data
etc.) shall be exported to ASCII files which can be further processed
by tools like GNU-Plot.

=item B<robotsDB>

Returns the user specified robot database or Null, if no database was
specified.

=item B<rmRobotsOutputExtension>

Returns the user specified filename extension that should be used for the
removeRobots output files.

=item B<anonKeyFile>

The file where the keys for de-anonymization of a log file shall be
stored. If left blank, no key file shall be created.

=item B<anonOutputExtension>

Returns the filename that should be used for the output of F<anonymizeLog.pl>.

=item B<taxonomyMapLog>

File where each conceptual mapping should be logged to. Left blank if
no logging is desired.

=item B<taxonomyDefs>

Returns an array of taxonomy definition file names.

=item B<transformOutputExtension>

Returns the filename that should be used for the output of F<transformLog.pl>.

=item B<transformMode>

Returns the desired transformation Mode (i.e., "SEQUENCE" or "SESSION_VECTOR").

=item B<transformTemplate>

Returns the name containing the record template for the transformed log.

=item B<transformSessionVectorFile>

Returns the output file for the session vectors in SESSION_VECTOR
transform mode.

=item B<transformSessionVectorWithEntryPage>

Returns true if each session's first hit should be included in the session vector (see F<transformLog.pl>).

=back



