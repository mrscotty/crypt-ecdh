Name:         perl-Crypt-ECDH
Version:      0.01 
Release:      1
# define the name from CPAN
%define cpan_name Crypt-ECDH
# do this package was known as "perl_cur" in old times. So we do need to Provide and Obsolete
# this package. YaST will install this package during update instead of the old one in this way.
Provides:     %cpan_name
# we better require the exact perl version, which was used to create this package
Requires:     perl = %{perl_version}
Group:        Development/Libraries/Perl
License:      Arkadius Litwinczuk 
#URL:          http://cpan.org/modules/by-module/Curses/
Summary:      Inline C elliptic curve Diffi-Hellman implemntation using the openSSL lib
Source:       %cpan_name-%{version}.tar.gz
BuildRoot:    %{_tmppath}/%{name}-%{version}-build

%description
Generate elliptic Curve PEM encoded Keypairs and a elliptic curve Diffi-Hellman key

%prep
%setup -q -n %cpan_name

%build
perl Makefile.PL OPTIMIZE="$RPM_OPT_FLAGS -Wall"
make
make test

%install
make DESTDIR=$RPM_BUILD_ROOT install_vendor
%perl_process_packlist

%clean
# clean up the hard disc after build
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README
%{perl_vendorarch}/
/usr/share/man/
#%{perl_vendorarch}/Crypt/ECDH.pm
#%{perl_vendorarch}/auto/Crypt/ECDH/ECDH.bs
#%{perl_vendorarch}/auto/Crypt/ECDH/ECDH.so
#%{perl_vendorarch}/auto/Crypt/ECDH/.packlist
/var/adm/perl-modules/%{name}


