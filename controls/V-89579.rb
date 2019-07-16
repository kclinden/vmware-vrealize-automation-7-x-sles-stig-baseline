control "V-89579" do
  title "Users must not be able to change passwords more than once every 24
hours."
  desc  "Enforcing a minimum password lifetime helps to prevent repeated
password changes to defeat the password reuse or history enforcement
requirement. If users are allowed to immediately and continually change their
password, then the password could be repeatedly changed in a short period of
time to defeat the organization's policy regarding password reuse."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000075-GPOS-00043"
  tag "gid": "V-89579"
  tag "rid": "SV-100229r1_rule"
  tag "stig_id": "VRAU-SL-000385"
  tag "fix_id": "F-96321r1_fix"
  tag "cci": ["CCI-000198"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "Check the minimum time period between password changes for each
user account is 1 day.

# cat /etc/shadow | cut -d ':' -f1,4 | grep -v 1 | grep -v \":$\"

If any results are returned, this is a finding."
  tag "fix": "Change the minimum time period between password changes for each
[USER] account to 1 day. The command in the check text will give you a list of
users that need to be updated to be in compliance.

# passwd -n 1 [USER]"

describe shadow do
  its('min_days.uniq') { should eq [1] }
end

end

