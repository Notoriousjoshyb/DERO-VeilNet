Name:           veilnet
Version:        %{dist_version}
Release:        1%{?dist}
Summary:        Decentralized privacy VPN (WireGuard data plane, DERO control plane)
License:        TBD
URL:            https://github.com/dero-veilnet/veilnet
Source0:        veilnet-%{version}.tar.gz

Requires:       wireguard-tools
Requires:       nftables | iptables
BuildArch:      noarch

%description
VeilNet client, node, and privileged service binaries plus systemd units.
DERO coordinates payments and sessions; it never carries user traffic.

%prep
%setup -q -n veilnet-%{version}-linux-%{_arch}

%install
install -D -m 0755 bin/veilnet %{buildroot}%{_bindir}/veilnet
install -D -m 0755 bin/veilnet-node %{buildroot}%{_bindir}/veilnet-node
install -D -m 0755 bin/veilnet-service %{buildroot}%{_bindir}/veilnet-service
install -D -m 0644 packaging/veilnet.service %{buildroot}%{_unitdir}/veilnet.service
install -D -m 0644 packaging/veilnet-node.service %{buildroot}%{_unitdir}/veilnet-node.service

%post
%systemd_post veilnet.service

%preun
%systemd_preun veilnet.service

%postun
%systemd_postun_with_restart veilnet.service

%files
%{_bindir}/veilnet
%{_bindir}/veilnet-node
%{_bindir}/veilnet-service
%{_unitdir}/veilnet.service
%{_unitdir}/veilnet-node.service

%changelog
