control "V-89671" do
  title "The SMTP service must not have the VRFY feature active."
  desc  "The VRFY (Verify) command allows an attacker to determine if an
account exists on a system, providing significant assistance to a brute force
attack on user accounts. VRFY may provide additional information about users on
the system, such as the full names of account owners."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000096-GPOS-00050"
  tag "gid": "V-89671"
  tag "rid": "SV-100321r1_rule"
  tag "stig_id": "VRAU-SL-000630"
  tag "fix_id": "F-96413r1_fix"
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
  tag "check": "Use the following command to check if VRFY is disabled:

# grep -v \"^#\" /etc/sendmail.cf |grep -i PrivacyOptions

If \"novrfy\" is not returned, this is a finding."
  tag "fix": "Add \"novrfy\" to the \"PrivacyOptions\" flag in /etc/sendmail.cf"
end

