control "V-89619" do
  title "The Stream Control Transmission Protocol (SCTP) must be disabled
unless required."
  desc  "The SCTP is an IETF-standardized transport layer protocol. This
protocol is not yet widely used. Binding this protocol to the network stack
increases the attack surface of the host. Unprivileged local processes may be
able to cause the kernel to dynamically load a protocol handler by opening a
socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89619"
  tag "rid": "SV-100269r1_rule"
  tag "stig_id": "VRAU-SL-000500"
  tag "fix_id": "F-96361r1_fix"
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
  tag "check": "Verify the SCTP protocol handler is prevented from dynamic
loading:

# grep \"install sctp /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the SCTP protocol handler for dynamic loading:

# echo \"install sctp /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install sctp /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

