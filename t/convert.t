#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use Scalar::Util qw(looks_like_number);

BEGIN {
	use_ok('Log::Munger')            || print "Bail out!\n";
	use_ok('Log::Munger::RulesTest') || print "Bail out!\n";
}

my $yaml = <<'YAML';
---
includes:
- base
vars_templated:
  LINE: '(?<who>[% WORD %]) port=(?<port>[% INT %]) load=(?<load>[% NUMBER %]) blob=(?<blob>[% NOTSPACE %])'
convert:
  port: int
  load: float
  who: int
  b_x: int
decompose:
  - field: blob
    type: kv
    prefix: 'b_'
    remove: true
    tests:
      - input: 'x=5'
        result: { b_x: '5' }
rules:
  - name: c
    field: MESSAGE
    anchored: true
    patterns: [LINE]
    tests:
      positive:
        - string: 'host port=022 load=0.50 blob=x=5'
          result: { who: 'host', port: '022', load: '0.50', blob: 'x=5' }
      negative: ['nope']
YAML

my ( $fh, $file ) = tempfile( 'lm_convert_XXXXXX', SUFFIX => '.yaml', TMPDIR => 1, UNLINK => 1 );
print {$fh} $yaml;
close($fh);

# the file must test clean
my $res = Log::Munger::RulesTest->test( 'file' => $file );
is( scalar( @{ $res->{'errors'} } ), 0, 'convert file tests clean' )
	or diag( join( "\n", @{ $res->{'errors'} } ) );

my $m = Log::Munger->new( 'rules' => [$file] );
my $r = $m->process_item( 'item' => { MESSAGE => 'host port=022 load=0.50 blob=x=5' } );

# numeric coercion
ok( looks_like_number( $r->{'port'} ), 'port is numeric' );
is( $r->{'port'}, 22, 'int drops leading zero (022 -> 22)' );
ok( looks_like_number( $r->{'load'} ), 'load is numeric' );
cmp_ok( $r->{'load'}, '==', 0.5, 'float 0.50 -> 0.5' );

# a value that is not a number is left as a string
is( $r->{'who'}, 'host', 'non-numeric field declared int is left untouched' );

# convert applies to a decomposed field (rule-level convert of b_x from the kv)
ok( !exists( $r->{'blob'} ), 'kv source removed' );
is( $r->{'b_x'}, 5, 'decomposed field coerced to int' );
ok( looks_like_number( $r->{'b_x'} ), 'decomposed field is numeric' );

# an unknown convert type is a load-time error
eval {
	my $bad = { 'convert' => { 'x' => 'stringy' }, 'rules' => [] };
	Log::Munger::LogProcessor->_compile_convert( $bad->{'convert'} );
};
like( $@, qr/unknown \(expected int or float\)/, 'unknown convert type dies at compile' );

# RulesTest reports a bad file-level convert map
my $badres = Log::Munger::RulesTest->test(
	'hash' => { 'convert' => { 'x' => 'weird' }, 'vars' => {}, 'rules' => [] } );
like( join( "\n", @{ $badres->{'errors'} } ), qr/\.convert is invalid/, 'RulesTest flags bad convert' );

done_testing();
