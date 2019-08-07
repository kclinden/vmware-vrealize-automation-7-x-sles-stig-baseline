control "V-89715" do
  title "The SLES for vRealize must manage excess capacity, bandwidth, or other
redundancy to limit the effects of information flooding types of Denial of
Service (DoS) attacks."
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    Managing excess capacity ensures that sufficient capacity is available to
counter flooding attacks. Employing increased capacity and service redundancy
may reduce the susceptibility to some DoS attacks. Managing excess capacity may
include, for example, establishing selected usage priorities, quotas, or
partitioning.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000142-GPOS-00071"
  tag "gid": "V-89715"
  tag "rid": "SV-100365r1_rule"
  tag "stig_id": "VRAU-SL-000785"
  tag "fix_id": "F-96457r2_fix"
  tag "cci": ["CCI-001095"]
  tag "nist": ["SC-5 (2)", "Rev_4"]
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
  tag "check": "Check that the SLES for vRealize configured to use TCP
syncookies when experiencing a TCP SYN flood.

# cat /proc/sys/net/ipv4/tcp_syncookies

If the result is not \"1\", this is a finding."
  tag "fix": "Configure the SLES for vRealize to use TCP syncookies when
experiencing a TCP SYN flood.

# sed -i 's/^.*\\bnet.ipv4.tcp_syncookies\\b.*$/net.ipv4.tcp_syncookies=1/'
/etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"

#https://www.inspec.io/docs/reference/resources/kernel_parameter/
describe kernel_parameter('net.ipv4.tcp_syncookies') do
  its('value') { should eq 1 }
end

end

