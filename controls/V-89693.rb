control "V-89693" do
  title "The SLES for vRealize must prevent direct logon into the root account."
  desc  "To assure individual accountability and prevent unauthorized access,
organizational users must be individually identified and authenticated.

    A group authenticator is a generic account used by multiple individuals.
Use of a group authenticator alone does not uniquely identify individual users.
Examples of the group authenticator is the UNIX OS \"root\" user account, the
Windows \"Administrator\" account, the \"sa\" account, or a \"helpdesk\"
account.

    For example, the UNIX and Windows operating systems offer a 'switch user'
capability allowing users to authenticate with their individual credentials
and, when needed, 'switch' to the administrator role. This method provides for
unique individual authentication prior to using a group authenticator.

    Users (and any processes acting on behalf of users) need to be uniquely
identified and authenticated for all accesses other than those accesses
explicitly identified and documented by the organization, which outlines
specific user actions that can be performed on the operating system without
identification or authentication.

    Requiring individuals to be authenticated with an individual authenticator
prior to using a group authenticator allows for traceability of actions, as
well as adding an additional level of protection of the actions that can be
taken with group account knowledge.
  "
  impact 0.7
  tag "severity": nil
  tag "gtitle": "SRG-OS-000109-GPOS-00056"
  tag "gid": "V-89693"
  tag "rid": "SV-100343r1_rule"
  tag "stig_id": "VRAU-SL-000705"
  tag "fix_id": "F-96435r1_fix"
  tag "cci": ["CCI-000770"]
  tag "nist": ["IA-2 (5)", "Rev_4"]
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
  tag "check": "Verify the SLES for vRealize prevents direct logons to the
\"root\" account by running the following command:

# grep root /etc/shadow | cut -d \"\":\"\" -f 2

If the returned message contains any text, this is a finding."
  tag "fix": "Configure the SLES for vRealize to prevent direct logons to the
\"root\" account by performing the following operations:

Add this line to the /etc/group file:

admin:x:[UNIQUE_NUMBER]:[USERNAME]

USERNAME is the user to be added to the admin group.
UNIQUE_NUMBER is a number entered into the ID field of an entry that is unique
to all other IDs in the file.

Comment out the following lines in /etc/sudoers file:
Default targetpw
ALL  ALL=(ALL) ALL

Under the line in the /etc/sudoers file:

root ALL=(ALL) All

Add the following line:

%admin ALL=(ALL) ALL

Run the following command:

# passwd -d root"
end

