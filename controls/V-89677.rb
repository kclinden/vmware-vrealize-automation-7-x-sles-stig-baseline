control "V-89677" do
  title "The AppleTalk protocol must be disabled or not installed."
  desc  "The AppleTalk suite of protocols is no longer in common use. Binding
this protocol to the network stack increases the attack surface of the host.
Unprivileged local processes may be able to cause the system to dynamically
load a protocol handler by opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89677"
  tag "rid": "SV-100327r1_rule"
  tag "stig_id": "VRAU-SL-000645"
  tag "fix_id": "F-96419r1_fix"
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
  tag "check": "Verify the AppleTalk protocol handler is prevented from dynamic
loading:

# grep \"install appletalk /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the AppleTalk protocol handler for dynamic loading:

# echo \"install appletalk /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install appletalk /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

