control "V-89469" do
  title "In addition to auditing new user and group accounts, these watches
will alert the system administrator(s) to any modifications. Any unexpected
users, groups, or modifications must be investigated for legitimacy."
  desc  "Once an attacker establishes initial access to a system, the attacker
often attempts to create a persistent method of reestablishing access. One way
to accomplish this is for the attacker to simply create a new account. Auditing
of account creation mitigates this risk.

    To address access requirements, many operating systems may be integrated
with enterprise-level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000004-GPOS-00004"
  tag "gid": "V-89469"
  tag "rid": "SV-100119r1_rule"
  tag "stig_id": "VRAU-SL-000020"
  tag "fix_id": "F-96211r1_fix"
  tag "cci": ["CCI-000018"]
  tag "nist": ["AC-2 (4)", "Rev_4"]
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
  tag "check": "Determine if /etc/passwd, /etc/shadow, /etc/group, and
/etc/gshadow are audited for appending.

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)' |
grep perm=a

If any of these are not listed with a permissions filter of at least \"a\",
this is a finding.

Expected result:
LIST_RULES: exit,always watch=/etc/passwd perm=a key=passwd
LIST_RULES: exit,always watch=/etc/shadow perm=a key=shadow
LIST_RULES: exit,always watch=/etc/group perm=a key=group
LIST_RULES: exit,always watch=/etc/gshadow perm=a key=gshadow"
  tag "fix": "Configure append auditing of the passwd, shadow, group, and
gshadow files. Run the dodscript with the following command as root:

# /etc/dodscript.sh
# echo '-w /etc/gshadow -p a -k gshadow' >> /etc/audit/audit.rules

Restart the auditd service.
# service auditd restart

OR

Configure append auditing of the passwd, shadow, group, and gshadow files by
running the following commands:

# echo '-w /etc/passwd -p a -k passwd' >> /etc/audit/audit.rules
# echo '-w /etc/shadow -p a -k shadow' >> /etc/audit/audit.rules
# echo '-w /etc/group -p a -k group' >> /etc/audit/audit.rules
# echo '-w /etc/gshadow -p a -k gshadow' >> /etc/audit/audit.rules

Restart the auditd service:
# service auditd restart"

describe file("/etc/audit/audit.rules") do
  its("content") { should match %r{-w /etc/passwd -p a -k passwd} }
  its("content") { should match %r{-w /etc/shadow -p a -k shadow} }
  its("content") { should match %r{-w /etc/group -p a -k group} }
  its("content") { should match %r{-w /etc/gshadow -p a -k gshadow} }
end

end

