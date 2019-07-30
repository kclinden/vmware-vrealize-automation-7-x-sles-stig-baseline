control "V-89687" do
  title "The DHCP client must be disabled if not needed."
  desc  "DHCP allows for the unauthenticated configuration of network
parameters on the system by exchanging information with a DHCP server."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89687"
  tag "rid": "SV-100337r1_rule"
  tag "stig_id": "VRAU-SL-000670"
  tag "fix_id": "F-96429r1_fix"
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
  tag "check": "Check that no interface is configured to use DHCP:

# grep -i bootproto=dhcp4 /etc/sysconfig/network/ifcfg-*

If any configuration is found, this is a finding."
  tag "fix": "Edit the /etc/sysconfig/network/ifcfg-* file(s) and change the
\"bootproto\" setting to \"static\"."

#check all with grep
describe command('grep -i bootproto=dhcp4 /etc/sysconfig/network/ifcfg-*') do
  its('stdout') {should cmp ''}
end

#explicitly check configuration of eth0
describe parse_config_file('/etc/sysconfig/network/ifcfg-eth0') do
  its('BOOTPROTO') { should_not eq 'dhcp4' }
end


end

