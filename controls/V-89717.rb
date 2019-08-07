control "V-89717" do
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
  tag "gid": "V-89717"
  tag "rid": "SV-100367r1_rule"
  tag "stig_id": "VRAU-SL-000790"
  tag "fix_id": "F-96459r1_fix"
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
  tag "check": "Check that the SLES for vRealize has an appropriate TCP backlog
queue size to mitigate against TCP SYN flood DOS attacks with the following
command:

# cat /proc/sys/net/ipv4/tcp_max_syn_backlog

If the TCP backlog queue size is not set to at least the recommended default
setting of \"1280\", this is a finding."
  tag "fix": "Configure the TCP backlog queue size with the following command:

# sed -i
's/^.*\\bnet.ipv4.tcp_max_syn_backlog\\b.*$/net.ipv4.tcp_max_syn_backlog=1280/'
/etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"

#https://www.inspec.io/docs/reference/resources/kernel_parameter/
describe kernel_parameter('net.ipv4.tcp_max_syn_backlog') do
  its('value') { should eq 1280 }
end

end

