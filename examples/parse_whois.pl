#!/usr/bin/perl

# Debian
# required packages (gcc make libdatetime-format-dateparse-perl libdata-dumper-concise-perl libexpat1-dev)

# Perl
# required modules (XML::IODEF::Simple DateTime::Format::DateManip) 

use strict;
use warnings; 

use Getopt::Std;
use DateTime::Format::DateParse;
use Data::Dumper;
use XML::IODEF::Simple;

my %opts;
getopts('df:D:i:s:t:',\%opts);

my $debug               = $opts{'d'};
my $filename            = $opts{'f'};
my $description         = $opts{'D'} || 'suspicious';
my $impact              = $opts{'i'} || 'suspicious';
my $source              = $opts{'s'} || 'localhost';
my $specified_timestamp = $opts{'t'};

my $timestamp;
my $cymru_timestamp;

# debugging
if (defined $debug) {
    print "Debug mode: On\n";
}

my @lines;

if($filename){
    open my $FILE, '<', $filename || die('unable to open '.$filename.': '.$!);
    while(<$FILE>){
        push(@lines,$_);
    }
    close ($FILE);
} else {
    while(<ARGV>){
        push(@lines,$_);
    }
}

# First line in file must start with 
# "Bulk mode; whois.cymru.com [dddd-dd-dd dd:dd:dd +dddd]"
#
die('invalid format') unless($lines[0] =~ /^Bulk mode;\swhois\.cymru\.com\s\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\+\d{4}\]/);

# regex: first char of the line must be one or more digits
# one or more spaces, and a pipe character
# ^ 123  |
#
die('invalid format') unless($lines[1] =~ /^\d+\s+\|/);


# Obtain, validate and format buik whois timestamp
#
if ($lines[0] =~ m/^Bulk mode;\swhois\.cymru\.com\s\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\+\d{4})\]/){
    $cymru_timestamp = DateTime::Format::DateParse->parse_datetime($1);
}

foreach (1 ... $#lines) {
    # split on one or more spaces on either side of "|"
    my @array = split(/\s+\|\s+/,$lines[$_]);

    $timestamp = get_timestamp($specified_timestamp,\@array,$cymru_timestamp);

    # remove a new line chracpter from the last item in the array
    
    $array[-1] =~ s/\n$//;

    ## should try to localize variables wherever possible
    my $x = XML::IODEF::Simple->new({
        purpose     => 'reporting',
        address     => $array[1],
        detecttime  => $timestamp,
        source      => $source,
        impact      => $impact,
        description => $description,
    });
    if (defined $debug) {
        #warn Dumper($x);
        print "$array[1]|$timestamp\n";
    } else {
        # print out the XML using XML::IODEF's ->out() function
        print $x->out();
    }
}

sub get_timestamp {
    my $specified_timestamp = shift;
    my $array = shift;
    my $cymru_timestamp = shift;

    ## this could be replaced with:
    ## for($#array){
    ##      if(/^3$/){
    ##          ...
    ##          last;
    ##      }
    ##      if(/^4$/){
    ##          ...
    ##          last;
    ##      }
    ##      perldoc -f for, easier to add more statements to later on

    # Find the size of the array
    #
    my $array_size = @$array;
 
    # If there is not a info column, (array size == 3)
    #
    ## could use: if($#array == 2), cleaner code ($#array will give you 0,1,3 which == 3)
    if ($array_size == 3) {
        if ($specified_timestamp) {
            return $specified_timestamp;
        }
        else {
            return $cymru_timestamp.'Z';
        }
    }

    # Look for timestamp if the info column exists
    # (e.g. a total of four columns)
    #
    ## if($#array == 3)
    if ($array_size == 4) {

        my @t = split(/ /, @$array[2]);
        if ($specified_timestamp) {
            return $specified_timestamp;
        }
        elsif ($t[0] =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/) {
            return $t[0];
        }
        else {
            return $cymru_timestamp.'Z';
        }
    }
}
