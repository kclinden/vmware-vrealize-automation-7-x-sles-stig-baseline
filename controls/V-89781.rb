control "V-89781" do
  title "The SLES for vRealize must automatically lock an account until the
locked account is released by an administrator when three unsuccessful logon
attempts in 15 minutes occur."
  desc  "By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-forcing, is reduced. Limits are imposed by locking the account."
  impact 0.3
  tag "severity": nil
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "gid": "V-89781"
  tag "rid": "SV-100431r1_rule"
  tag "stig_id": "VRAU-SL-001035"
  tag "fix_id": "F-96523r1_fix"
  tag "cci": ["CCI-002238"]
  tag "nist": ["AC-7 b", "Rev_4"]
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
  tag "check": "Check the \"pam_tally2\" configuration:

# more /etc/pam.d/common-auth

Confirm the following line is configured:

auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=86400
root_unlock_time=300

# more /etc/pam.d/common-account

Confirm the following line is configured:

account required pam_tally2.so

If no such lines are found, this is a finding."
  tag "fix": "Edit \"/etc/pam.d/common-auth\" and add the following line:

auth required pam_tally2.so deny=3 onerr=fail even_deny_root unlock_time=86400
root_unlock_time=300

Edit \"/etc/pam.d/common-account\" and add the following line:

account required pam_tally2.so"
end

