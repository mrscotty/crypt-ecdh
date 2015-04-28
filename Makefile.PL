use inc::Module::Install;

name     'Crypt-ECDH';
all_from 'lib/Crypt/ECDH.pm';
#license  'perl';

#requires   'Moose';

#recommends 'Config::Versioned' => '0.5';
#recommends 'Config::Std';
#recommends 'YAML';
#
#recommends 'Text::CSV_XS';
#
#recommends 'Template';
#recommends 'Proc::SafeExec';
#
#build_requires 'Test::More';

auto_install;

WriteAll;

