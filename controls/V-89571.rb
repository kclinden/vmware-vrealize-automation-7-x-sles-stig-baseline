control "V-89571" do
  title "The SLES for vRealize must require the change of at least eight of the
total number of characters when passwords are changed."
  desc  " If the operating system allows the user to consecutively reuse
extensive portions of passwords, this increases the chances of password
compromise by increasing the window of opportunity for attempts at guessing and
brute-force attacks.

    The number of changed characters refers to the number of changes required
with respect to the total number of positions in the current password. In other
words, characters may be the same within the two passwords; however, the
positions of the like characters must be different.
  "
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000072-GPOS-00040"
  tag "gid": "V-89571"
  tag "rid": "SV-100221r1_rule"
  tag "stig_id": "VRAU-SL-000360"
  tag "fix_id": "F-96313r2_fix"
  tag "cci": ["CCI-000195"]
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
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
  tag "check": "Check that at least eight characters need to be changed between
old and new passwords during a password change by running the following command:

# grep pam_cracklib /etc/pam.d/common-password-vmware.local

The \"difok\" parameter indicates how many characters must be different. The
DoD requires at least eight characters to be different during a password
change. This would appear as \"difok=8\". If difok is not found or not set to
at least \"8\", this is a finding.

Expected Result:
password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=14 difok=8 retry=3"
  tag "fix": "If \"difok\" was not set at all in
/etc/pam.d/common-password-vmware.local then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ difok-8/'
/etc/pam.d/common-password-vmware.local

If \"difok\" was set incorrectly then run the following command to set it to
\"8\":

# sed -i '/pam_cracklib.so/ s/difok=./difok=8/' /etc/pam.d/common-password-vmware.local"

describe file('/etc/pam.d/common-password-vmware.local') do
  its('content') {should match %r{difok=8} }
end

end

