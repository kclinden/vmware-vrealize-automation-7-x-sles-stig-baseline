control "V-89713" do
  title "The SLES for vRealize must terminate all sessions and network
connections related to nonlocal maintenance when nonlocal maintenance is
completed."
  desc  " If a maintenance session or connection remains open after maintenance
is completed, it may be hijacked by an attacker and used to compromise or
damage the system.

    Some maintenance and test tools are either standalone devices with their
own operating systems or are applications bundled with an operating system.

    Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000126-GPOS-00066"
  tag "gid": "V-89713"
  tag "rid": "SV-100363r1_rule"
  tag "stig_id": "VRAU-SL-000765"
  tag "fix_id": "F-96455r1_fix"
  tag "cci": ["CCI-000879"]
  tag "nist": ["MA-4 e", "Rev_4"]
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
  tag "check": "Check for the existence of the /etc/profile.d/tmout.sh file:

# ls -al /etc/profile.d/tmout.sh

Check for the presence of the \"TMOUT\" variable:

# grep TMOUT /etc/profile.d/tmout.sh

The value of \"TMOUT\" should be set to \"900\" seconds (15 minutes).

If the file does not exist, or the \"TMOUT\" variable is not set to \"900\",
this is a finding."
  tag "fix": "Ensure the file exists and is owned by \"root\". If the files
does not exist, use the following commands to create the file:

# touch /etc/profile.d/tmout.sh
# chown root:root /etc/profile.d/tmout.sh
# chmod 644 /etc/profile.d/tmout.sh

Edit the file /etc/profile.d/tmout.sh, and add the following lines:

TMOUT=900
readonly TMOUT
export TMOUT
mesg n 2>/dev/null"
end

