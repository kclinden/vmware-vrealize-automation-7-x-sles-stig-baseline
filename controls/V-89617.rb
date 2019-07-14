control "V-89617" do
  title "The Datagram Congestion Control Protocol (DCCP) must be disabled
unless required."
  desc  "The DCCP is a proposed transport layer protocol. This protocol is not
yet widely used. Binding this protocol to the network stack increases the
attack surface of the host. Unprivileged local processes may be able to cause
the kernel to dynamically load a protocol handler by opening a socket using the
protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89617"
  tag "rid": "SV-100267r1_rule"
  tag "stig_id": "VRAU-SL-000495"
  tag "fix_id": "F-96359r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Check that the DCCP protocol handler is prevented from dynamic
loading:

# grep \"install dccp /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/*

If no result is returned, this is a finding.

# grep \"install dccp_ipv4 /bin/true\" /etc/modprobe.conf
/etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding.

# grep \"install dccp_ipv6\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/* | grep ‘bin/true’

If no result is returned, this is a finding."
  tag "fix": "Prevent the DCCP protocol handler for dynamic loading:

# echo \"install dccp /bin/true\" >> /etc/modprobe.conf.local
# echo \"install dccp_ipv4 /bin/true\" >> /etc/modprobe.conf.local
# echo \"install dccp_ipv6 /bin/true\" >> /etc/modprobe.conf.local"
end

