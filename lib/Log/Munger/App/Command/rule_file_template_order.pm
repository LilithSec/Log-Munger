package Log::Munger::App::Command::rule_file_template_order;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::RulesTemplateOrder;
use YAML::XS qw(Dump);

sub opt_spec {
	return ( [ 'f=s', 'Rule file to read.', { 'default' => 'base' } ],
			 [ 'd', 'Print depend info.' ],
		);
}

sub abstract { "Reads in the specified rule file and dumps it to stdout" }

sub description { "Reads in the specified rule file and dumps it to stdout" }

sub validate { return 1 }

sub execute {
	my ( $self, $opts, $args ) = @_;

	my $results;
	if (! $opts->{'d'} ){
		$results=Log::Munger::RulesTemplateOrder->order_for_rules_file('file'=>$opts->{'f'});
	}else{
		$results=Log::Munger::RulesTemplateOrder->depends_for_rules_file('file'=>$opts->{'f'});
	}

	print Dump($results);
}

1;
