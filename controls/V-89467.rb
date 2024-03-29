control "V-89467" do
  title "The SLES for vRealize must audit all account creations."
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
  tag "gid": "V-89467"
  tag "rid": "SV-100117r1_rule"
  tag "stig_id": "VRAU-SL-000015"
  tag "fix_id": "F-96209r1_fix"
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
  tag "check": "Determine if execution of the useradd and groupadd executable
are audited.

# auditctl -l | egrep '(useradd|groupadd)'

If either useradd or groupadd are not listed with a permissions filter of at
least \"x\", this is a finding.

Expected result:
LIST_RULES: exit,always watch=/usr/sbin/useradd perm=x key=useradd
LIST_RULES: exit,always watch=/usr/sbin/groupadd perm=x key=groupadd"
  tag "fix": "Configure execute auditing of the useradd and groupadd
executables. Run the dodscript with the following command as root:

# /etc/dodscript.sh

OR

Configure execute auditing of the useradd and groupadd executables.

Add the following to /etc/audit/audit.rules:
-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

Restart the auditd service:
# service auditd restart"

  describe file("/etc/audit/audit.rules") do
    its("content") { should match %r{-w /usr/sbin/useradd -p x -k useradd} }
    its("content") { should match %r{-w /usr/sbin/groupadd -p x -k groupadd} }
  end

end

