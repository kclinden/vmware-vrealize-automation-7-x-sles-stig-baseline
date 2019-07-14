control "V-89673" do
  title "The Lightweight User Datagram Protocol (UDP-Lite) must be disabled
unless required."
  desc  "The Lightweight User Datagram Protocol (UDP-Lite) is a proposed
transport layer protocol. This protocol is not yet widely used. Binding this
protocol to the network stack increases the attack surface of the host.
Unprivileged local processes may be able to cause the system to dynamically
load a protocol handler by opening a socket using the protocol."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89673"
  tag "rid": "SV-100323r1_rule"
  tag "stig_id": "VRAU-SL-000635"
  tag "fix_id": "F-96415r1_fix"
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
  tag "check": "Run the following command:

iptables --list | grep \"udplite\"

If no result is displayed, this is a finding."
  tag "fix": "Configure the system to prevent the dynamic loading of the
UDP-Lite protocol handler:

Add the following rule to the iptables firewall ruleset:

# iptables -A INPUT -p udplite -j DROP"
end

