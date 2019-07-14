control "V-89867" do
  title "The SLES for vRealize must prevent the use of dictionary words for
passwords."
  desc  "If the operating system allows the user to select passwords based on
dictionary words, this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000480-GPOS-00225"
  tag "gid": "V-89867"
  tag "rid": "SV-100517r1_rule"
  tag "stig_id": "VRAU-SL-001505"
  tag "fix_id": "F-96609r1_fix"
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
  tag "check": "Verify the module \"pam_cracklib.so\" is present.

# ls /lib/security/

Confirm that \"pam_cracklib.so\" is present in the directory listing.

If \"pam_cracklib.so\" is not present, this is a finding.

Verify the file \"/etc/pam.d/common-password\" is configured.

# grep pam_cracklib /etc/pam.d/common-password*

If a line containing \"password required pam_cracklib.so\"  is not present,
this is a finding."
  tag "fix": "Configure the SLES for vRealize to prevent the use of dictionary
words for passwords. Edit the file \"/etc/pam.d/common-password\". Configure
\"common-password\" by adding a line such as:

password  required pam_cracklib.so

Save the changes made to the file \"/etc/pam.d/common-password\"."
end

