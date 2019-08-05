control "V-89675" do
  title "The Internetwork Packet Exchange (IPX) protocol must be disabled or
not installed."
  desc  "The Internetwork Packet Exchange (IPX) protocol is a network-layer
protocol that is no longer in common use. Binding this protocol to the network
stack increases the attack surface of the host. Unprivileged local processes
may be able to cause the system to dynamically load a protocol handler by
opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89675"
  tag "rid": "SV-100325r1_rule"
  tag "stig_id": "VRAU-SL-000640"
  tag "fix_id": "F-96417r1_fix"
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
  tag "check": "Check that the IPX protocol handler is prevented from dynamic
loading:

# grep \"install ipx /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the IPX protocol handler for dynamic loading:

# echo \"install ipx /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install ipx /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

