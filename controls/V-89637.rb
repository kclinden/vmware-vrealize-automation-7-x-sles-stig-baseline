control "V-89637" do
  title "The system must not use UDP for NIS/NIS+."
  desc  "Implementing NIS or NIS+ under UDP may make the system more
susceptible to a denial-of-service attack and does not provide the same quality
of service as TCP."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89637"
  tag "rid": "SV-100287r1_rule"
  tag "stig_id": "VRAU-SL-000545"
  tag "fix_id": "F-96379r1_fix"
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
  tag "check": "If the SLES for vRealize does not use NIS or NIS+, this is not
applicable.

Check if NIS or NIS+ is implemented using UDP:

# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding."
  tag "fix": "Configure the SLES for vRealize to not use UDP for NIS and NIS+.
Consult vendor documentation for the required procedure."
end

