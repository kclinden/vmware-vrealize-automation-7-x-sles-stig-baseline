control "V-89811" do
  title "The SLES for vRealize must protect against or limit the effects of
Denial of Service (DoS) attacks by ensuring the SLES for vRealize is
implementing rate-limiting measures on impacted network interfaces."
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    This requirement addresses the configuration of the operating system to
mitigate the impact of DoS attacks that have occurred or are ongoing on system
availability. For each system, known and potential DoS attacks must be
identified and solutions for each type implemented. A variety of technologies
exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g.,
limiting processes or establishing memory partitions). Employing increased
capacity and bandwidth, combined with service redundancy, may reduce the
susceptibility to some DoS attacks.
  "
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000420-GPOS-00186"
  tag "gid": "V-89811"
  tag "rid": "SV-100461r1_rule"
  tag "stig_id": "VRAU-SL-001305"
  tag "fix_id": "F-96553r1_fix"
  tag "cci": ["CCI-002385"]
  tag "nist": ["SC-5", "Rev_4"]
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
  tag "check": "Check that the system configured to use TCP syncookies when
experiencing a TCP SYN flood.

# cat /proc/sys/net/ipv4/tcp_syncookies

If the result is not \"1\", this is a finding."
  tag "fix": "Configure the system to use TCP syncookies when experiencing a
TCP SYN flood.

Check for the presence of \"net.ipv4.tcp_syncookies\" in the /etc/sysctl.conf
file:

# grep \"net.ipv4.tcp_syncookies\" /etc/sysctl.conf

If it exists, change the value to \"1\". If it does not exist, add a setting
for tcp_syncookies:

# echo \"net.ipv4.tcp_syncookies=1\" >> /etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"
end

