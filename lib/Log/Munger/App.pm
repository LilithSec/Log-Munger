package Log::Munger::App;

use 5.006;
use strict;
use warnings;
use App::Cmd::Setup -app;

our $VERSION = '0.0.1';

sub global_opt_spec {
        return (
                [ 'help|h'    => "This usage screen." ],
                [ 'version|v' => "This usage screen." ],
        );
} ## end sub global_opt_spec


1;
