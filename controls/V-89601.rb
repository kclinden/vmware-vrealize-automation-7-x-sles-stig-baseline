control "V-89601" do
  title "The Bluetooth protocol handler must be disabled or not installed."
  desc  "Bluetooth is a personal area network (PAN) technology. Binding this
protocol to the network stack increases the attack surface of the host.
Unprivileged local processes may be able to cause the kernel to dynamically
load a protocol handler by opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-89601"
  tag "rid": "SV-100251r1_rule"
  tag "stig_id": "VRAU-SL-000445"
  tag "fix_id": "F-96343r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Verify the Bluetooth protocol handler is prevented from dynamic
loading:

# grep \"install bluetooth /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the Bluetooth protocol handler for dynamic loading:

# echo \"install bluetooth /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install bluetooth /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end


end

