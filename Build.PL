my @requires = qw();
my @recommends = qw();

use Module::Build;

my $build_pkg = 'Module::Build';

my $build = $build_pkg->new(
    module_name => 'Crypt::ECDH',
    license => 'artistic',
    build_requires => {},
    requires => {},
    recommends => {},
    create_makefile_pl => 'passthrough',
    dist_author => 'Scott Hardin <scott@hnsc.de>',
    dist_version_from => 'lib/Crypt/ECDH.pm',
);

$build->create_build_script;

