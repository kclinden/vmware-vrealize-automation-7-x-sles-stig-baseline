control "V-89623" do
  title "The Transparent Inter-Process Communication (TIPC) must be disabled or
not installed."
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is a
relatively new cluster communications protocol developed by Ericsson. Binding
this protocol to the network stack increases the attack surface of the host.
Unprivileged local processes may be able to cause the kernel to dynamically
load a protocol handler by opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89623"
  tag "rid": "SV-100273r1_rule"
  tag "stig_id": "VRAU-SL-000510"
  tag "fix_id": "F-96365r1_fix"
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
  tag "check": "Verify the TIPC protocol handler is prevented from dynamic
loading:

# grep \"install tipc /bin/true\" /etc/modprobe.conf /etc/modprobe.conf.local
/etc/modprobe.d/*

If no result is returned, this is a finding."
  tag "fix": "Prevent the TIPC protocol handler for dynamic loading:

# echo \"install tipc /bin/true\" >> /etc/modprobe.conf.local"

describe command('grep "install tipc /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/*') do
  its('stdout') {should_not eq ''}
end

end

