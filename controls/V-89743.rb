control "V-89743" do
  title "The SLES for vRealize must audit all account modifications."
  desc  "Once an attacker establishes initial access to a system, the attacker
often attempts to create a persistent method of reestablishing access. One way
to accomplish this is for the attacker to simply modify an existing account.
Auditing of account modification is one method for mitigating this risk.

    To address access requirements, many operating systems can be integrated
with enterprise-level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000239-GPOS-00089"
  tag "gid": "V-89743"
  tag "rid": "SV-100393r1_rule"
  tag "stig_id": "VRAU-SL-000875"
  tag "fix_id": "F-96485r1_fix"
  tag "cci": ["CCI-001403"]
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
/etc/gshadow are audited for writing.

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)' |
grep perm=w

If any of these are not listed with a permissions filter of at least \"w\",
this is a finding."
  tag "fix": "Configure append auditing of the \"passwd\", \"shadow\",
\"group\", and \"gshadow\" files run \"dodscript\" with the following command
as \"root\":

# /etc/dodscript.sh

OR

Configure auditing of the \"passwd\", \"shadow\", \"group\", and \"gshadow\"
files. Add the following to the audit.rules file:
-w /etc/passwd -p w -k passwd
-w /etc/shadow -p w -k shadow
-w /etc/group -p w -k group
-w /etc/gshadow -p w -k gshadow

Restart the auditd service:

# service auditd restart"
end

