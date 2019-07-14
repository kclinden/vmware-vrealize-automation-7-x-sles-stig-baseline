control "V-89669" do
  title "The SMTP service must not have the EXPN feature active."
  desc  "The SMTP EXPN function allows an attacker to determine if an account
exists on a system, providing significant assistance to a brute force attack on
user accounts. EXPN may also provide additional information concerning users on
the system, such as the full names of account owners."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89669"
  tag "rid": "SV-100319r1_rule"
  tag "stig_id": "VRAU-SL-000625"
  tag "fix_id": "F-96411r1_fix"
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
  tag "check": "Use the following command to check if EXPN is disabled:

# grep -v \"^#\" /etc/sendmail.cf |grep -i PrivacyOptions

If \"noexpn\" is not returned, this is a finding."
  tag "fix": "Add \"noexpn\" to the \"PrivacyOptions\" flag in /etc/sendmail.cf"
end

