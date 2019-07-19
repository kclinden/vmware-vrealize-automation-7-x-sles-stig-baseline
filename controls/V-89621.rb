control "V-89621" do
  title "The Reliable Datagram Sockets (RDS) protocol must be disabled or not
installed unless required."
  desc  "The RDS protocol is a relatively new protocol developed by Oracle for
communication between the nodes of a cluster. Binding this protocol to the
network stack increases the attack surface of the host. Unprivileged local
processes may be able to cause the system to dynamically load a protocol
handler by opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89621"
  tag "rid": "SV-100271r1_rule"
  tag "stig_id": "VRAU-SL-000505"
  tag "fix_id": "F-96363r1_fix"
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
  tag "check": "Ask the SA if RDS is required by application software running
on the system. If so, this is not applicable.

Check that the RDS protocol handler is prevented from dynamic loading:

# grep \"install rds /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the use of RDS protocol handler for dynamic loading:

# echo \"install rds /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install rds /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

