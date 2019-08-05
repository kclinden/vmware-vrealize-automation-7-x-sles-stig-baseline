control "V-89681" do
  title "Proxy Neighbor Discovery Protocol (NDP) must not be enabled on the
system."
  desc  "Proxy Neighbor Discovery Protocol (NDP) allows a system to respond to
NDP requests on one interface on behalf of hosts connected to another
interface. If this function is enabled when not required, addressing
information may be leaked between the attached network segments."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89681"
  tag "rid": "SV-100331r1_rule"
  tag "stig_id": "VRAU-SL-000655"
  tag "fix_id": "F-96423r1_fix"
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
  tag "check": "Note: For Appliance OS, proxy_ndp is disabled by default and
this is not a finding.

Determine if the system is configured for proxy NDP, and if it is enabled:

more /proc/sys/net/ipv6/conf/*/proxy_ndp

If the file is not found, the kernel is not configured for proxy NDP, and this
is not a finding.

If the file has a value of \"0\", proxy NDP is not enabled, and this is not a
finding.

If the file has a value of \"1\", proxy NDP is enabled, and this is a finding."
  tag "fix": "Disable proxy NDP on the system."

describe kernel_parameter('net.ipv6.conf.eth0.proxy_ndp') do
  its('value') { should eq 0 }
end

end

