use inc::Module::Install;

WriteMakefile(
    NAME              => 'Crypt::ECDH',
    VERSION_FROM      => 'lib/Crypt/ECDH.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/ECDH.pm', # retrieve abstract from module
       AUTHOR         => 'Gideon Knocke') : ()),
    LIBS              => ['-L/opt/local/lib -L/usr/local/lib -lcrypto'], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I/opt/local/include -I/usr/local/include', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => '$(O_FILES)', # link all the C files too
);

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

