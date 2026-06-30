package Log::Munger::LogProcessor;

use 5.006;
use strict;
use warnings;
use Log::Munger::WhichRuleFile;

=head1 NAME

Log::Munger::LogProcessor - 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS



=head1 METHODS

=head2 new

Initiates the object.

    - rules :: Rules to load. The taken value is a array.
        default :: []

=cut

sub new {
	my ( $blank, %opts ) = @_;

	if (!defined($opts{'rules'})){
		die('$opts{rules} is undef');
	}elsif( ref($opts{'rules'}) ne 'ARRAY' ){
		die('$opts{rules} has a ref of "'.ref($opts{'rules'}).'" and not "ARRAY"');
	}elsif	(!defined($opts{'rules'}[0])){
		die('$opts{rules}[0] is undef... no rules have been specified to use');
	}
	
	my $self={
		'rules' => [],
			'loaded_rules' => [],
	};
	bless $self;

	my $parser = Log::Munger::RuleFileParser->new;
	
	my $rules_int=0;
	while(defined($opts{'rules'}[$rules_int])){
		my $file_location;
		eval{
			$file_location = Log::Munger::WhichRuleFile->rule_file_location('file' => $opts{'rules'}[$rules_int]);
		};
		if ($@){
			die('Errored getting file location for $opts{rules}['.$rules_int.'.], "'.$opts{'rules'}[$rules_int].'"... '.$@);
		}elsif(!defined($file_location)){
			die('File location for $opts{rules}['.$rules_int.'.], "'.$opts{'rules'}[$rules_int].'", could not be found');
		}

		my $rules;
		eval{
			$rules = $parser->load('file' => $file_location);
		};
		if ($@){
			die('Failed to load $opts{rules}['.$rules_int.'],"'.$file_location.'".... '.$@);
		}

		if (!defined($rules->{'rules'})){
			die('.rules does not exist in "'.$file_location.'" meaning rules file has no rules');
		}elsif(  ){
			
		}
		
		$rules_int++;
	}

	return $self;
} ## end sub string
