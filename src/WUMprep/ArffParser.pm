# ========================================================================
# WUMprep - Log file Preparation for Web Usage Mining
# ------------------------------------------------------------------------
# WUMprep/ArffParser.pm - Parse Web server log data in Weka ARFF-Format
# $Revision: 1.2 $
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

package WUMprep::ArffParser;

use strict;
use Cwd;
use FindBin;
use lib "$FindBin::Bin";
use WUMprep::Config;
use Text::CSV_XS;

use constant CONFIG_FILENAME => "wumprep.conf";

my $config = new WUMprep::Config;

my $csv = new Text::CSV_XS->new( { 'quote_char' => '\'' } );

my %monthMap = (
  Jan => 0,
  Feb => 1,
  Mar => 2,
  Apr => 3,
  May => 4,
  Jun => 5,
  Jul => 6,
  Aug => 7,
  Sep => 8,
  Oct => 9,
  Nov => 10,
  Dec => 11
);

my %monthMapInverse;

# Indicates whether we're parsing the ARFF header or the data part
my $inData = 0;

for ( keys %monthMap ) {
  $monthMapInverse{ $monthMap{$_} } = $_;
}

# ========================================================================
# SUB: new
# ------------------------------------------------------------------------
# Constructor method
# ========================================================================
sub new ($) {
  my $proto = shift;
  my $self  = {};
  my $class = ref($proto) || $proto;
  bless( $self, $class );

  $self->initialize;

  return $self;
}

# ========================================================================
# SUB: initialize
# ------------------------------------------------------------------------
# Initializes an instance
# ========================================================================
sub initialize {
  my $self = shift;

  $self->{IN_DATA}    = 0;
  $self->{ATTRIBUTES} = [];
  $self->{DATATYPES}  = {};
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
  my ($self) = @_;

  $self->{MONTH_ALPHA} = 1 if shift;
}

# ========================================================================
# SUB: readLogFormatDef
# ------------------------------------------------------------------------
# Read the logfile definition and build a nice regexp from it.
# ------------------------------------------------------------------------
# Parameters:
# @attributes The attribute names
# ========================================================================
sub readLogFormatDef {
  my $self   = shift;
  my $regexp = '';
  my $count  = 0;
  my $field;
  my $template;
  my $attrib;
  my $pre;
  my $end;

  print STDERR "Parsing ARFF log format definition...\n";

  # Build a template log line for later sampling of WUMprep output
  foreach $attrib ( @{ $self->{ATTRIBUTES} } ) {
    $template .= ',' if $template ne '';
    $template .= '@' . $attrib . '@';
  }

  $self->{LOG_LINE_TEMPLATE}        = $template;
  $self->{LOG_LINE_TEMPLATE_EXPORT} = $template;

  # Build the regular expression for the parser
  while ( $template =~ m/(.*?)@(\w*)@/gc ) {
    $pre   = quotemeta($1);
    $field = $2;
    $end   = quotemeta($');

    die "$0\nERROR: Unrecognized field in log template: $field\n\n"
      if ( !scalar( grep( /^$field$/, $config->validFields ) ) );

    $regexp .= "$pre'?(.*?)'?";
    $self->{FIELD_MAP}{$field} = $count;
    $count++;
  }

  $regexp = "^" . $regexp . $end . "\$";

  $self->{PARSER_REGEXP} = $regexp;
  return $regexp;
}

sub getInputTemplate {
  my $self = shift;
  return $self->{LOG_LINE_TEMPLATE};
}

sub getOutputTemplate {
  my $self = shift;
  return $self->{LOG_LINE_TEMPLATE_EXPORT}; 
}

sub setOutputTemplate( \$ ) {
  my $self          = shift;
  my $logLineExport = shift;

  $self->{LOG_LINE_TEMPLATE_EXPORT} = $logLineExport;
}

sub fieldMap {
  my $self = shift;

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
# Returns: A hash containing the log line fields when passed a log line,
#          or -1 if the passed line belongs to the ARFF header.
# ========================================================================
sub parseLogLine(\$) {
  my $self    = shift;
  my $logLine = shift;
  chomp $logLine;

  if ( $self->{IN_DATA} ) {
    # Parse an instance
    $csv->parse($logLine);
    my (@parsedLogLine) = $csv->fields();

    # set all empty fields (marked by '-') to undef
    for (@parsedLogLine) {
      s/^-$//;
    }

    # join path and query (args) field
    if (
        defined $self->{FIELD_MAP}{args}
        && $parsedLogLine[ $self->{FIELD_MAP}{args} ] !~ /(-|^$)/
      )
    {
      $parsedLogLine[ $self->{FIELD_MAP}{path} ] .=
        '?' . $parsedLogLine[ $self->{FIELD_MAP}{args} ];
    }

    # To make our users' lifes easier, we take care about the month
    # format. If the log line to sample contains a textual month
    # representation, we convert it to the corresponding integer
    # value (which is out of 1..12).
    # We store the original month format to be able to write a
    # correct output log using the sampleLogLine method.
    if ( defined $self->{FIELD_MAP}{ts_month} ) {

      # non-numeric month format?
      if ( $parsedLogLine[ $self->{FIELD_MAP}{ts_month} ] !~ /^\d+$/ ) {
        $parsedLogLine[ $self->{FIELD_MAP}{ts_month} ] =
          $monthMap{ $parsedLogLine[ $self->{FIELD_MAP}{ts_month} ] };
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
    if ( defined( $self->{FIELD_MAP}{cookie} ) ) {
      my @cookies = split /;(\+|\ )/,
        @parsedLogLine[ $self->{FIELD_MAP}{cookie} ];
      for (@cookies) {
        ( my $key, my $value ) = split /=/;
        next if ( $key eq '+' );
        $cookies{$key} = $value;
      }
      @parsedLogLine[ $self->{FIELD_MAP}{cookie} ] = \%cookies;
    }

    # Convert the array to a hash (that's easier to handle with for this
    # method's users).

    my %parsedLogLine;
    my %fieldMapInverted = reverse %{ $self->{FIELD_MAP} };

    for ( my $i = 0 ; $i < scalar(@parsedLogLine) ; $i++ ) {
      $parsedLogLine{ $fieldMapInverted{$i} } = $parsedLogLine[$i];
    }

    return \%parsedLogLine;
  }
  else {

    # Not $inData -> we're still parsing the ARFF header

    if ( $logLine =~ /^(\@relation)\s(.+)$/ ) {

      # The relation name (first line of the ARFF file)
      $self->{RELATION} = $2;

    }
    elsif ( $logLine =~ /^(\@attribute)\s(\S+)\s(\S+)/ ) {

      # It's an attribute definition in the ARFF header
      push @{ $self->{ATTRIBUTES} }, $2;
      ${$self->{DATATYPES}}{$2} = $3;
    }
    elsif ( $logLine =~ /\@data/ ) {

      # Finished reading the ARFF header, construct the instance line
      # parser now.
      $self->readLogFormatDef;

      # The remaining lines are data
      $self->{IN_DATA} = 1;
    }

    return -1;
  }
}

sub inHeader {
  my $self = shift;
  
  return ! $self->{IN_DATA};
}

sub inData {
  my $self = shift;
  
  return $self->{IN_DATA};
}

sub inputArffHeader {
  my $self = shift;
  
  my $arffHeader;
  $arffHeader = "\@relation " . $self->{RELATION} . "\n\n";

  for (my $i = 0; $i < scalar @{$self->{ATTRIBUTES}}; $i++) {
    $arffHeader .= "\@attribute " . $self->{ATTRIBUTES}[$i] . " " 
      . ${$self->{DATATYPES}}{$self->{ATTRIBUTES}[$i]} . "\n";
  }
  
  $arffHeader .= "\n\@data\n";
  
  return $arffHeader;
}

sub outputArffHeader {
  my $self = shift;
  
  my $arffHeader;
  $arffHeader = "\@relation " . $self->{RELATION}  . "\n\n";
  
  # Parse an instance
  $csv->parse($self->{LOG_LINE_TEMPLATE_EXPORT});
  my (@parsedTemplate) = $csv->fields();

    # set all empty fields (marked by '-') to undef
  for (@parsedTemplate) {
    s/\@(.+)\@$/$1/;  # remove the field markers
    $arffHeader .= "\@attribute " . $_ . " " . $self->{DATATYPES}{$_} . "\n";
  }  
  $arffHeader .= "\n\@data\n";
  
  return $arffHeader;
}

sub setDatatype(\$, \$) {
  my $self = shift;
  
  my $field = shift;
  my $type = shift;
  
  ${$self->{DATATYPES}}{$field} = $type;
}

sub appendAttribute(\$, \$) {
  my $self = shift;
  my $attributeName = shift;
  my $attributeType = shift;
  
  push @{ $self->{ATTRIBUTES} }, $attributeName;
  $self->setDatatype($attributeName, $attributeType);
}

# ========================================================================
# SUB: sampleLogLine
# ------------------------------------------------------------------------
# The opposite of parseLogLine: Creates a log line from a hash
# ------------------------------------------------------------------------
# Argument:
# - the log line to parse as hash
# ------------------------------------------------------------------------
# Returns: A string containing the log line fields according to the
#          field map.
# ========================================================================
sub sampleLogLine(\$) {
  my $self          = shift;
  my $logLine       = shift();
  my $logLineReturn = $self->{LOG_LINE_TEMPLATE_EXPORT};
  my $cookie;

  if ( $self->{FIELD_MAP}{cookie} ) {
    if ( defined( $$logLine{cookie} )
      && keys( %{ $$logLine{cookie} } ) )
    {

      # convert the cookie hash back to a string
      for ( keys( %{ $$logLine{cookie} } ) ) {
        $cookie .= ';+' if ($cookie);
        $cookie .= $_;
        $cookie .= '=' . ${ $$logLine{cookie} }{$_}
          if ( ${ $$logLine{cookie} }{$_} );
      }

      $cookie =~ s/;\+$//;    # remove trailing separator
      $$logLine{cookie} = $cookie;
    }
    else {
      $$logLine{cookie} = undef;
    }
  }

  # replace undef values by '-' and
  # enclose values containing blanks with single quotes
  for ( keys %$logLine ) {
    $$logLine{$_} = '-' if $$logLine{$_} eq '';
    $$logLine{$_} =~ s/(.*)/\'\1\'/ if $$logLine{$_} =~ /[\s,]/;
  }

  # Make sure that the month value is in the same format as it was when
  # we read it.
  # ATTENTION: This mechanism assumes that the parseLogLine method is called
  #            _before_ the sampleLogLine method. (As for now, this assumption
  #            seems reasonable.) Here, we rely on the format value defined
  #            by $self->{MONT_ALPHA}.
  if ( defined $self->{FIELD_MAP}{ts_month} ) {
    if ( $$logLine{ts_month} =~ /^\d+$/
      && $self->{MONTH_ALPHA} )
    {
      $$logLine{ts_month} =
        $monthMapInverse{ sprintf( "%d", $$logLine{ts_month} ) };
    }
    elsif ( $$logLine{ts_month} !~ /^\d+$/
      && !$self->{MONTH_ALPHA} )
    {
      $$logLine{ts_month} = $monthMap{ $$logLine{ts_month} };
    }

    # Make sure month has two digits if !MONTH_ALPHA
    if ( !$self->{MONTH_ALPHA} ) {
      $$logLine{ts_month} = sprintf( "%02d", $$logLine{ts_month} );
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

