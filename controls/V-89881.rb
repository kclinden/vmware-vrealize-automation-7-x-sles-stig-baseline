control "V-89881" do
  title "The SLES for vRealize must employ a deny-all, allow-by-exception
firewall policy for allowing connections to other systems."
  desc  "Failure to restrict network connectivity only to authorized systems
permits inbound connections from malicious systems. It also permits outbound
connections that may facilitate exfiltration of DoD data."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00231"
  tag "gid": "V-89881"
  tag "rid": "SV-100531r1_rule"
  tag "stig_id": "VRAU-SL-001550"
  tag "fix_id": "F-96623r1_fix"
  tag "cci": ["CCI-000366", "CCI-002080"]
  tag "nist": ["CM-6 b", "CA-3 (5)", "Rev_4"]
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
  tag "check": "Check firewall configuration with the following command:

iptables --list|grep -e OUTPUT -e INPUT -e FORWARD

If employ a deny-all, allow-by-exception firewall policy for allowing
connections to other systems, this is a finding."
  tag "fix": "Configure the SLES for vRealize to employ a deny-all,
allow-by-exception firewall policy for allowing connections to other systems."
end

