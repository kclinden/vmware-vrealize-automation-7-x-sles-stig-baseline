control "V-89869" do
  title "The SLES for vRealize must prevent the use of dictionary words for
passwords."
  desc  "If the operating system allows the user to select passwords based on
dictionary words, this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00225"
  tag "gid": "V-89869"
  tag "rid": "SV-100519r1_rule"
  tag "stig_id": "VRAU-SL-001510"
  tag "fix_id": "F-96611r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "Verify the \"passwd\" command uses the \"common-password\"
settings.

# grep common-password /etc/pam.d/passwd

If a line \"password include common-password\" is not found then the \"password
checks in common-password\" will not be applied to new passwords, and this is a
finding."
  tag "fix": "Configure the SLES for vRealize to prevent the use of dictionary
words for passwords.

Edit the file \"/etc/pam.d/passwd\". Configure \"passwd\" by adding a line such
as:

password include common-password

Save the changes made to the file."
end

