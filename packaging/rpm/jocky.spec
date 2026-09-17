Name:           jocky
Version:        1.0.0
Release:        1%{?dist}
Summary:        Enterprise Digital Forensics Platform
License:        MIT
URL:            https://github.com/vmmuthu31/jocky
# Source binary is injected by CI — see packaging/rpm/build-rpm.sh

%description
JOCKY is a forensic DSL compiler and command-and-control platform for
authorized computer and network forensic analysis under IT Act 2000 §69.
Compiles .jocky scripts to polymorphic LLVM IR with a 7-pass obfuscation
pipeline and supports Windows/Linux field agents.

%prep
# Binary is already placed by build-rpm.sh

%install
mkdir -p %{buildroot}%{_bindir}
install -m 755 %{_sourcedir}/jocky-compile %{buildroot}%{_bindir}/jocky-compile

%files
%{_bindir}/jocky-compile

%post
echo "JOCKY installed. Run: jocky-compile --help"

%changelog
* Wed Sep 17 2026 NTRO JOCKY Team <vmmuthu20000@gmail.com> - 1.0.0-1
- Initial release
