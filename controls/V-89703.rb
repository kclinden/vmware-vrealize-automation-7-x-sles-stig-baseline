control "V-89703" do
  title "The SLES for vRealize must uniquely identify and must authenticate
non-organizational users (or processes acting on behalf of non-organizational
users)."
  desc  "Lack of authentication and identification enables non-organizational
users to gain access to the application or possibly other information systems
and provides an opportunity for intruders to compromise resources within the
application or information system.

    Non-organizational users include all information system users other than
organizational users, which include organizational employees or individuals the
organization deems to have equivalent status of an employee (e.g., contractors
and guest researchers).

    Non-organizational users must be uniquely identified and authenticated for
all accesses other than those accesses explicitly identified and documented by
the organization when related to the use of anonymous access.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000121-GPOS-00062"
  tag "gid": "V-89703"
  tag "rid": "SV-100353r1_rule"
  tag "stig_id": "VRAU-SL-000735"
  tag "fix_id": "F-96445r1_fix"
  tag "cci": ["CCI-000804"]
  tag "nist": ["IA-8", "Rev_4"]
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
  tag "check": "Run the following command to check for duplicate account names:

# pwck -rq

If there are no duplicate names, no line will be returned.

If a line is returned, this is a finding."
  tag "fix": "Change usernames, or delete accounts, so each has a unique name."

describe command('pwck -rq') do
 its('stdout') { should eq ''}
end

end

