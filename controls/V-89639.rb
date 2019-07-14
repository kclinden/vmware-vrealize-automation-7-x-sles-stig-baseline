control "V-89639" do
  title "NIS maps must be protected through hard-to-guess domain names."
  desc  "The use of hard-to-guess NIS domain names provides additional
protection from unauthorized access to the NIS directory information."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89639"
  tag "rid": "SV-100289r1_rule"
  tag "stig_id": "VRAU-SL-000550"
  tag "fix_id": "F-96381r1_fix"
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

Check the domain name for NIS maps:

# domainname

If the name returned is simple to guess, such as the organization name,
building or room name, etc., this is a finding."
  tag "fix": "Change the NIS domain name to a value difficult to guess. Consult
vendor documentation for the required procedure."
end

