control "V-89537" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful attempts to access privileges occur. The SLES for
vRealize must generate audit records for all discretionary access control
permission modifications using chown."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-89537"
  tag "rid": "SV-100187r1_rule"
  tag "stig_id": "VRAU-SL-000260"
  tag "fix_id": "F-96279r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "check": "To determine if the system is configured to audit calls to the
\"chown\" system call, run the following command:

# auditctl -l | grep syscall | grep chown

If the system is configured to audit this activity, it will return several
lines, such as:

LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid=0
syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat
LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid>=500 (0x1f4) auid!=-1
(0xffffffff) syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat

If no lines are returned, this is a finding."
  tag "fix": "At a minimum, the audit system should collect file permission
changes for all users and \"root\". Add the following to
\"/etc/audit/audit.rules\":

-a always,exit -F arch=b64 -S chown -F auid=0
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"
end

