control "V-89739" do
  title "Any publically accessible connection to the SLES for vRealize must
display the Standard Mandatory DoD Notice and Consent Banner before granting
access to the system."
  desc  "Display of a standardized and approved use notification before
granting access to the publicly accessible operating system ensures privacy and
security notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for operating systems that can accommodate banners of
1300 characters:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

    Use the following verbiage for operating systems that have severe
limitations on the number of characters that can be displayed in the banner:

    \"I've read and consent to terms in IS user agreem't.\"
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000228-GPOS-00088"
  tag "gid": "V-89739"
  tag "rid": "SV-100389r1_rule"
  tag "stig_id": "VRAU-SL-000865"
  tag "fix_id": "F-96481r1_fix"
  tag "cci": ["CCI-001384", "CCI-001385", "CCI-001386", "CCI-001387",
"CCI-001388"]
  tag "nist": ["AC-8 c 1", "AC-8 c 2", "AC-8 c 2", "AC-8 c 2", "AC-8 c 3",
"Rev_4"]
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
  tag "check": "Check the issue file to verify that it contains one of the DoD
required banners:

# cat /etc/issue

\"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent
to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

Use the following verbiage for SLES for vRealize that have severe limitations
on the number of characters that can be displayed in the banner:

\"I've read & consent to terms in IS user agreem't.\"

If it does not, this is a finding."
  tag "fix": "To configure the system to display the Standard Mandatory DoD
Notice and Consent Banner, run the dodscript with the following command as root:

# /etc/dodscript.sh"
end

