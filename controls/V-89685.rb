control "V-89685" do
  title "The SLES for vRealize must not have Teredo enabled."
  desc  "Teredo is an IPv6 transition mechanism that involves tunneling IPv6
packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent
network security."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89685"
  tag "rid": "SV-100335r1_rule"
  tag "stig_id": "VRAU-SL-000665"
  tag "fix_id": "F-96427r1_fix"
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
  tag "check": "Verify the Teredo service is not running:

ps ax | grep teredo | grep -v grep

If the Teredo process is running, this is a finding."
  tag "fix": "Kill the Teredo service.

Edit startup scripts to prevent the service from running on startup.

For Appliance OS, Teredo is not included by default, this is not a finding."

describe service('teredo') do
  it {should_not be_running}
  it {should_not be_enabled}
end

end

