control "V-89683" do
  title "The SLES for vRealize must not have 6to4 enabled."
  desc  "6to4 is an IPv6 transition mechanism that involves tunneling IPv6
packets encapsulated in IPv4 packets on an ad-hoc basis. This is not a
preferred transition strategy and increases the attack surface of the system."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89683"
  tag "rid": "SV-100333r1_rule"
  tag "stig_id": "VRAU-SL-000660"
  tag "fix_id": "F-96425r1_fix"
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
  tag "check": "Check the SLES for vRealize for any active \"6to4\" tunnels
without specific remote addresses:

# ip tun list | grep \"remote any\" | grep \"ipv6/ip\"

If any results are returned the \"tunnel\" is the first field.

If any results are returned, this is a finding."
  tag "fix": "Disable the active 6to4 tunnel:

# ip link set <tunnel> down

Add this command to a startup script, or remove the configuration creating the
tunnel."

describe command('ip tun list | grep "remote any" | grep "ipv6/ip"') do
 its('stdout') {should eq ""}
end

end

